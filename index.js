const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');

const app = express();

// ── CORS — permite Netlify + qualquer origem em dev ──
app.use(cors({
  origin: ['https://adr-barbearia.netlify.app', 'http://localhost:3000', /\.netlify\.app$/],
  methods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization'],
  credentials: true
}));
app.options('*', cors());
app.use(express.json());

// ── Supabase ──────────────────────────────────────────
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_KEY;

if (!SUPABASE_URL || !SUPABASE_KEY) {
  console.error('ERRO FATAL: SUPABASE_URL ou SUPABASE_KEY não definidos!');
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

// ── Helpers ───────────────────────────────────────────
const hashStr = str => crypto.createHash('sha256').update(String(str)).digest('hex');
const genPin  = (n=4) => Array.from({length:n}, ()=>Math.floor(Math.random()*10)).join('');
const genToken = () => crypto.randomBytes(32).toString('hex');

// ── Sessões em memória ────────────────────────────────
// ATENÇÃO: no plano free do Render o servidor dorme e perde sessões.
// Tokens expiram em 8h e o front reenvia as credenciais se necessário.
const sessions = new Map();
setInterval(() => {
  const now = Date.now();
  for (const [k,v] of sessions) {
    if (now - v.ts > 8 * 3600 * 1000) sessions.delete(k);
  }
}, 60 * 60 * 1000);

function requireAuth(req, res, next) {
  const token = (req.headers['authorization'] || '').replace('Bearer ', '').trim();
  if (!token || !sessions.has(token)) {
    console.log('[AUTH] Token inválido ou sessão expirada');
    return res.status(401).json({ error: 'Não autenticado. Faça login novamente.' });
  }
  req.session = sessions.get(token);
  next();
}

// ── Health ────────────────────────────────────────────
app.get('/health', (_, res) => res.json({ status: 'ok', ts: Date.now() }));

// ══════════════════════════════════════════════════════
// AUTH — DONO
// ══════════════════════════════════════════════════════

app.post('/api/auth/owner', async (req, res) => {
  try {
    const { userHash, passHash } = req.body;
    if (!userHash || !passHash) return res.status(400).json({ error: 'Dados incompletos.' });

    const { data: cfg, error: cfgErr } = await supabase
      .from('config').select('dados').eq('id', 1).maybeSingle();

    if (cfgErr) {
      console.error('[AUTH/OWNER] Erro Supabase:', cfgErr.message);
      return res.status(500).json({ error: 'Erro ao acessar configurações.' });
    }

    // Primeiro acesso — salva credenciais
    if (!cfg?.dados?.ownerUserHash) {
      const { error: saveErr } = await supabase.from('config').upsert({
        id: 1,
        dados: { ...(cfg?.dados || {}), ownerUserHash: userHash, ownerPassHash: passHash }
      });
      if (saveErr) {
        console.error('[AUTH/OWNER] Erro ao salvar credenciais:', saveErr.message);
        return res.status(500).json({ error: 'Erro ao salvar credenciais.' });
      }
      const token = genToken();
      sessions.set(token, { role: 'owner', ts: Date.now() });
      console.log('[AUTH/OWNER] Primeiro acesso — credenciais salvas');
      return res.json({ token, firstAccess: true });
    }

    if (cfg.dados.ownerUserHash !== userHash || cfg.dados.ownerPassHash !== passHash) {
      console.log('[AUTH/OWNER] Credenciais incorretas');
      return res.status(401).json({ error: 'Usuário ou senha incorretos.' });
    }

    const token = genToken();
    sessions.set(token, { role: 'owner', ts: Date.now() });
    console.log('[AUTH/OWNER] Login bem-sucedido');
    res.json({ token, firstAccess: false });
  } catch(e) {
    console.error('[AUTH/OWNER] Exceção:', e.message);
    res.status(500).json({ error: 'Erro interno.' });
  }
});

app.post('/api/auth/owner/update', requireAuth, async (req, res) => {
  try {
    if (req.session.role !== 'owner') return res.status(403).json({ error: 'Sem permissão.' });
    const { userHash, passHash } = req.body;
    const { data: cfg } = await supabase.from('config').select('dados').eq('id', 1).maybeSingle();
    await supabase.from('config').upsert({
      id: 1,
      dados: { ...(cfg?.dados || {}), ownerUserHash: userHash, ownerPassHash: passHash }
    });
    res.json({ ok: true });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ══════════════════════════════════════════════════════
// AUTH — CLIENTE
// ══════════════════════════════════════════════════════

app.post('/api/auth/client', async (req, res) => {
  try {
    const { tel, pin } = req.body;
    if (!tel || !pin) return res.status(400).json({ error: 'Dados incompletos.' });

    const telClean = tel.replace(/\D/g, '');
    const pinHash  = hashStr(pin);

    console.log('[AUTH/CLIENT] Tentativa login tel:', telClean);

    const { data: clientes, error } = await supabase.from('clientes').select('*');
    if (error) {
      console.error('[AUTH/CLIENT] Erro Supabase:', error.message);
      return res.status(500).json({ error: 'Erro ao buscar clientes.' });
    }

    const cliente = (clientes || []).find(c => {
      const cTel = (c.tel_clean || c.tel || '').replace(/\D/g, '');
      const pinOk = c.pin === pin || c.pin_hash === pinHash;
      return cTel === telClean && pinOk;
    });

    if (!cliente) {
      console.log('[AUTH/CLIENT] Não encontrado — tel:', telClean);
      return res.status(401).json({ error: 'Telefone ou PIN incorretos.' });
    }

    const token = genToken();
    sessions.set(token, { role: 'client', clienteId: cliente.id, ts: Date.now() });
    console.log('[AUTH/CLIENT] Login OK — cliente:', cliente.nome);
    res.json({ token, cliente });
  } catch(e) {
    console.error('[AUTH/CLIENT] Exceção:', e.message);
    res.status(500).json({ error: 'Erro interno.' });
  }
});

// ══════════════════════════════════════════════════════
// CLIENTES
// ══════════════════════════════════════════════════════

app.get('/api/clientes', requireAuth, async (req, res) => {
  try {
    if (req.session.role !== 'owner') return res.status(403).json({ error: 'Sem permissão.' });
    const { data, error } = await supabase.from('clientes').select('*').order('created_at', { ascending: false });
    if (error) return res.status(500).json({ error: error.message });
    res.json(data || []);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/clientes', requireAuth, async (req, res) => {
  try {
    if (req.session.role !== 'owner') return res.status(403).json({ error: 'Sem permissão.' });
    const { nome, tel, plano, status, metodo, obs } = req.body;
    if (!nome || !tel) return res.status(400).json({ error: 'Nome e telefone obrigatórios.' });

    const pin      = genPin(4);
    const pinHash  = hashStr(pin);
    const telClean = tel.replace(/\D/g, '');
    const hoje     = new Date().toLocaleDateString('pt-BR');

    const { data, error } = await supabase.from('clientes').insert({
      nome, tel, tel_clean: telClean, plano: plano || null,
      status: status || 'Pendente', metodo: metodo || '',
      obs: obs || '', pag_status: 'Pendente',
      pin, pin_hash: pinHash, desde: hoje
    }).select().single();

    if (error) {
      console.error('[POST/CLIENTES] Erro:', error.message);
      return res.status(500).json({ error: error.message });
    }
    console.log('[POST/CLIENTES] Criado:', data.nome, '| PIN:', pin);
    res.json(data);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Auto-cadastro (rota pública)
app.post('/api/clientes/register', async (req, res) => {
  try {
    const { nome, tel, pin } = req.body;
    if (!nome || !tel || !pin) return res.status(400).json({ error: 'Dados incompletos.' });
    if (!/^\d{4,6}$/.test(pin)) return res.status(400).json({ error: 'PIN deve ter 4 a 6 números.' });

    const telClean = tel.replace(/\D/g, '');
    const pinHash  = hashStr(pin);

    console.log('[REGISTER] Tentativa cadastro:', nome, '| tel:', telClean);

    const { data: todos, error: listErr } = await supabase
      .from('clientes').select('id, tel, tel_clean');

    if (listErr) {
      console.error('[REGISTER] Erro ao listar clientes:', listErr.message);
      return res.status(500).json({ error: 'Erro ao verificar cadastro.' });
    }

    const existing = (todos || []).find(c =>
      (c.tel_clean || c.tel || '').replace(/\D/g, '') === telClean
    );
    if (existing) return res.status(400).json({ error: 'Telefone já cadastrado. Faça login.' });

    const hoje = new Date().toLocaleDateString('pt-BR');
    const { data, error } = await supabase.from('clientes').insert({
      nome, tel, tel_clean: telClean,
      pin, pin_hash: pinHash,
      pag_status: 'SemPlano', status: 'Pendente',
      obs: 'Auto-cadastro', desde: hoje
    }).select().single();

    if (error) {
      console.error('[REGISTER] Erro Supabase:', error.message, '| detalhes:', JSON.stringify(error));
      return res.status(500).json({ error: error.message });
    }

    console.log('[REGISTER] Cadastro OK:', data.nome);
    res.json(data);
  } catch(e) {
    console.error('[REGISTER] Exceção:', e.message);
    res.status(500).json({ error: 'Erro interno ao cadastrar.' });
  }
});

app.patch('/api/clientes/:id', requireAuth, async (req, res) => {
  try {
    if (req.session.role !== 'owner') return res.status(403).json({ error: 'Sem permissão.' });
    const { data, error } = await supabase
      .from('clientes').update(req.body).eq('id', req.params.id).select().single();
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/clientes/:id', requireAuth, async (req, res) => {
  try {
    if (req.session.role !== 'owner') return res.status(403).json({ error: 'Sem permissão.' });
    const { error } = await supabase.from('clientes').delete().eq('id', req.params.id);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/clientes/:id/reset-pin', requireAuth, async (req, res) => {
  try {
    if (req.session.role !== 'owner') return res.status(403).json({ error: 'Sem permissão.' });
    const { pin } = req.body;
    const pinHash = hashStr(pin);
    const { data, error } = await supabase
      .from('clientes').update({ pin, pin_hash: pinHash }).eq('id', req.params.id).select().single();
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/me', requireAuth, async (req, res) => {
  try {
    if (req.session.role !== 'client') return res.status(403).json({ error: 'Sem permissão.' });
    const { data, error } = await supabase
      .from('clientes').select('*').eq('id', req.session.clienteId).single();
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════
// CONFIG
// ══════════════════════════════════════════════════════

app.get('/api/config', async (_, res) => {
  try {
    const { data, error } = await supabase.from('config').select('dados').eq('id', 1).maybeSingle();
    if (error) return res.status(500).json({ error: error.message });
    res.json(data?.dados || {});
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/config', requireAuth, async (req, res) => {
  try {
    if (req.session.role !== 'owner') return res.status(403).json({ error: 'Sem permissão.' });
    const { data: cfg } = await supabase.from('config').select('dados').eq('id', 1).maybeSingle();
    const { error } = await supabase.from('config').upsert({
      id: 1, dados: { ...(cfg?.dados || {}), ...req.body }
    });
    if (error) return res.status(500).json({ error: error.message });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════
// PAGAMENTO
// ══════════════════════════════════════════════════════
app.post('/api/payment/create', requireAuth, async (req, res) => {
  res.status(501).json({ error: 'Integração Mercado Pago ainda não configurada.' });
});

// ══════════════════════════════════════════════════════
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log('========================================');
  console.log('API ADR Barber rodando na porta', PORT);
  console.log('Supabase URL:', SUPABASE_URL ? 'OK' : 'AUSENTE!');
  console.log('Supabase KEY:', SUPABASE_KEY ? 'OK' : 'AUSENTE!');
  console.log('========================================');
});
      
