const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(cors());
app.use(express.json());

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);

// ── Helpers ──────────────────────────────
function hashStr(str) {
  return crypto.createHash('sha256').update(str).digest('hex');
}

function genPin(len = 4) {
  let p = '';
  for (let i = 0; i < len; i++) p += Math.floor(Math.random() * 10);
  return p;
}

function genToken() {
  return crypto.randomBytes(32).toString('hex');
}

const sessions = new Map();

function requireAuth(req, res, next) {
  const auth = req.headers['authorization'] || '';
  const token = auth.replace('Bearer ', '').trim();
  if (!token || !sessions.has(token)) return res.status(401).json({ error: 'Não autenticado.' });
  req.session = sessions.get(token);
  next();
}

// ── Health ────────────────────────────────
app.get('/health', (_, res) => res.json({ status: 'ok' }));

// ══════════════════════════════════════════
// AUTH
// ══════════════════════════════════════════

app.post('/api/auth/owner', async (req, res) => {
  const { userHash, passHash } = req.body;
  if (!userHash || !passHash) return res.status(400).json({ error: 'Dados incompletos.' });

  const { data: cfg } = await supabase.from('config').select('dados').eq('id', 1).single();

  if (!cfg || !cfg.dados?.ownerUserHash) {
    await supabase.from('config').upsert({
      id: 1,
      dados: { ...(cfg?.dados || {}), ownerUserHash: userHash, ownerPassHash: passHash }
    });
    const token = genToken();
    sessions.set(token, { role: 'owner' });
    return res.json({ token, firstAccess: true });
  }

  if (cfg.dados.ownerUserHash !== userHash || cfg.dados.ownerPassHash !== passHash) {
    return res.status(401).json({ error: 'Usuário ou senha incorretos.' });
  }

  const token = genToken();
  sessions.set(token, { role: 'owner' });
  res.json({ token, firstAccess: false });
});

app.post('/api/auth/owner/update', requireAuth, async (req, res) => {
  if (req.session.role !== 'owner') return res.status(403).json({ error: 'Sem permissão.' });
  const { userHash, passHash } = req.body;
  const { data: cfg } = await supabase.from('config').select('dados').eq('id', 1).single();
  await supabase.from('config').upsert({
    id: 1,
    dados: { ...(cfg?.dados || {}), ownerUserHash: userHash, ownerPassHash: passHash }
  });
  res.json({ ok: true });
});

app.post('/api/auth/client', async (req, res) => {
  const { tel, pin } = req.body;
  if (!tel || !pin) return res.status(400).json({ error: 'Dados incompletos.' });

  const telClean = tel.replace(/\D/g, '');
  const pinHash = hashStr(pin);

  const { data: clientes } = await supabase.from('clientes').select('*');
  const cliente = clientes?.find(c => {
    const cTel = (c.tel_clean || c.tel || '').replace(/\D/g, '');
    // Compara pin direto OU pin_hash
    const pinOk = c.pin === pin || c.pin_hash === pinHash;
    return cTel === telClean && pinOk;
  });

  if (!cliente) return res.status(401).json({ error: 'Telefone ou PIN incorretos.' });

  const token = genToken();
  sessions.set(token, { role: 'client', clienteId: cliente.id });
  res.json({ token, cliente });
});

// ══════════════════════════════════════════
// CLIENTES
// ══════════════════════════════════════════

app.get('/api/clientes', requireAuth, async (req, res) => {
  if (req.session.role !== 'owner') return res.status(403).json({ error: 'Sem permissão.' });
  const { data, error } = await supabase.from('clientes').select('*').order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/clientes', requireAuth, async (req, res) => {
  if (req.session.role !== 'owner') return res.status(403).json({ error: 'Sem permissão.' });
  const { nome, tel, plano, status, metodo, obs } = req.body;
  if (!nome || !tel) return res.status(400).json({ error: 'Nome e telefone obrigatórios.' });

  const pin = genPin(4);
  const pinHash = hashStr(pin);
  const telClean = tel.replace(/\D/g, '');
  const hoje = new Date().toLocaleDateString('pt-BR');

  const { data, error } = await supabase.from('clientes').insert({
    nome, tel, tel_clean: telClean, plano, status: status || 'Pendente',
    metodo: metodo || '', obs: obs || '',
    pag_status: 'Pendente', pin, pin_hash: pinHash, desde: hoje
  }).select().single();

  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.patch('/api/clientes/:id', requireAuth, async (req, res) => {
  if (req.session.role !== 'owner') return res.status(403).json({ error: 'Sem permissão.' });
  const { data, error } = await supabase
    .from('clientes').update(req.body).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.delete('/api/clientes/:id', requireAuth, async (req, res) => {
  if (req.session.role !== 'owner') return res.status(403).json({ error: 'Sem permissão.' });
  const { error } = await supabase.from('clientes').delete().eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

app.patch('/api/clientes/:id/reset-pin', requireAuth, async (req, res) => {
  if (req.session.role !== 'owner') return res.status(403).json({ error: 'Sem permissão.' });
  const { pin } = req.body;
  const pinHash = hashStr(pin);
  const { data, error } = await supabase
    .from('clientes').update({ pin, pin_hash: pinHash }).eq('id', req.params.id).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.get('/api/me', requireAuth, async (req, res) => {
  if (req.session.role !== 'client') return res.status(403).json({ error: 'Sem permissão.' });
  const { data, error } = await supabase.from('clientes').select('*').eq('id', req.session.clienteId).single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/clientes/register', async (req, res) => {
  const { nome, tel, pin } = req.body;
  if (!nome || !tel || !pin) return res.status(400).json({ error: 'Dados incompletos.' });

  const telClean = tel.replace(/\D/g, '');
  const pinHash = hashStr(pin);

  const { data: todos } = await supabase.from('clientes').select('id, tel, tel_clean');
  const existing = todos?.find(c => (c.tel_clean || c.tel || '').replace(/\D/g, '') === telClean);
  if (existing) return res.status(400).json({ error: 'Telefone já cadastrado.' });

  const hoje = new Date().toLocaleDateString('pt-BR');
  const { data, error } = await supabase.from('clientes').insert({
    nome, tel, tel_clean: telClean, pin, pin_hash: pinHash,
    pag_status: 'SemPlano', status: 'Pendente', obs: 'Auto-cadastro', desde: hoje
  }).select().single();

  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// ══════════════════════════════════════════
// CONFIG
// ══════════════════════════════════════════

app.get('/api/config', async (_, res) => {
  const { data, error } = await supabase.from('config').select('dados').eq('id', 1).single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data?.dados || {});
});

app.post('/api/config', requireAuth, async (req, res) => {
  if (req.session.role !== 'owner') return res.status(403).json({ error: 'Sem permissão.' });
  const { data: cfg } = await supabase.from('config').select('dados').eq('id', 1).single();
  const { error } = await supabase.from('config').upsert({
    id: 1,
    dados: { ...(cfg?.dados || {}), ...req.body }
  });
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

// ══════════════════════════════════════════
// PAGAMENTO
// ══════════════════════════════════════════
app.post('/api/payment/create', requireAuth, async (req, res) => {
  res.status(501).json({ error: 'Integração Mercado Pago ainda não configurada.' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('API ADR Barber rodando na porta ' + PORT));
