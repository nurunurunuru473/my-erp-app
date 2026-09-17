import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { createClient } from '@libsql/client';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json());

// Turso Database Client
const db = createClient({
  url: process.env.TURSO_DATABASE_URL || "",
  authToken: process.env.TURSO_AUTH_TOKEN || "",
});

// Serve Static Files
app.use(express.static(path.join(__dirname, '..')));

// Test Connection
app.get('/api/test', async (req, res) => {
  try {
    const result = await db.execute("SELECT 1;");
    res.json({ message: "Turso DB Connection Successful!", data: result });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Generic Endpoint to execute SQL queries from frontend
app.post('/api/query', async (req, res) => {
  try {
    const { sql, args } = req.body;
    const result = await db.execute({ sql, args: args || [] });
    res.json({ success: true, result });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Fallback Route
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'index.html'));
});

export default app;
