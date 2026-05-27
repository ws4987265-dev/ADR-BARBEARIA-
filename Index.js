const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(cors());
app.use(express.json());

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);

app.get('/health', (_, res) => res.json({ status: 'ok' }));

app.get('/clientes', async (_, res) => {
  const { data, error } = await supabase.from('clientes').select('*');
  if (error) return res.status(500).json({ error });
  res.json(data);
});

app.post('/clientes', async (req, res) => {
  const { data, error } = await supabase.from('clientes').insert(req.body).select();
  if (error) return res.status(500).json({ error });
  res.json(data);
});

app.put('/clientes/:id', async (req, res) => {
  const { data, error } = await supabase.from('clientes').update(req.body).eq('id', req.params.id).select();
  if (error) return res.status(500).json({ error });
  res.json(data);
});

app.get('/config', async (_, res) => {
  const { data, error } = await supabase.from('config').select('*').eq('id', 1).single();
  if (error) return res.status(500).json({ error });
  res.json(data);
});

app.post('/config', async (req, res) => {
  const { data, error } = await supabase.from('config').upsert({ id: 1, dados: req.body }).select();
  if (error) return res.status(500).json({ error });
  res.json(data);
});

app.listen(3000, () => console.log('API rodando na porta 3000'));
