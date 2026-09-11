const express = require('express');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

// ====================== SUPABASE (SỬA LỖI) ======================
const { createClient } = require('@supabase/supabase-js');

const supabaseAdmin = createClient(
  process.env.SUPABASE_PROJECT_URL,          // ← SỬA THÀNH PROJECT_URL
  process.env.SUPABASE_SERVICE_KEY            // dùng service_role key
);

const supabase = createClient(
  process.env.SUPABASE_PROJECT_URL,          // ← SỬA THÀNH PROJECT_URL
  process.env.SUPABASE_ANON_KEY
);

// ====================== ROUTES ======================

// Auth
app.post('/auth/register', async (req, res) => {
  const { email, password, full_name, phone } = req.body;
  const { data, error } = await supabaseAdmin.auth.admin.createUser({
    email, password, user_metadata: { full_name, phone }
  });
  res.json({ data, error });
});

app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const { data, error } = await supabase.auth.signInWithPassword({ email, password });
  res.json({ data, error });
});

// Devices
app.post('/devices', async (req, res) => {
  const { device_code, provisioning_secret, owner_id } = req.body;
  const { data, error } = await supabase
    .from('devices')
    .insert({
      device_code,
      provisioning_secret_hash: require('crypto').createHash('sha256').update(provisioning_secret).digest('hex'),
      owner_id,
      status: 'online',
      device_mode: 'physical'
    })
    .select();
  res.json({ data, error });
});

app.get('/devices', async (req, res) => {
  const { data, error } = await supabase.from('devices').select('*');
  res.json({ data, error });
});

// NFC
app.post('/nfc/register', async (req, res) => {
  const { card_uid, device_id } = req.body;
  const { data, error } = await supabase
    .from('access_cards')
    .insert({
      card_uid_hash: require('crypto').createHash('sha256').update(card_uid).digest('hex'),
      status: 'active',
      registered_by: req.user?.id
    })
    .select();
  res.json({ data, error });
});

// Commands
app.post('/commands', async (req, res) => {
  const { device_id, command_type } = req.body;
  const { data, error } = await supabase
    .from('device_commands')
    .insert({
      device_id,
      command_type,
      issued_by: req.user?.id,
      status: 'pending',
      command_token_hash: require('crypto').createHash('sha256').update(Math.random().toString()).digest('hex')
    })
    .select();
  res.json({ data, error });
});

app.listen(PORT, () => {
  console.log(`🚀 Backend chạy tại http://localhost:${PORT}`);
});