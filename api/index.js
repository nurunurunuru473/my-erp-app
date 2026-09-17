import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { createClient } from '@libsql/client';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json());

const db = createClient({
  url: process.env.TURSO_DATABASE_URL || "",
  authToken: process.env.TURSO_AUTH_TOKEN || "",
});

// Static ፋይሎችን ማቅረብ
app.use(express.static(path.join(__dirname, '..')));

// GET /api/test - የቱርሶ ዳታቤዝ ግንኙነት መፈተሻ
app.get('/api/test', async (req, res) => {
  try {
    const result = await db.execute("SELECT 1;");
    res.json({ 
      status: "SUCCESS", 
      message: "Turso DB Connection is Working!", 
      data: result 
    });
  } catch (err) {
    res.status(500).json({ 
      status: "ERROR", 
      message: "Failed to connect to Turso", 
      error: err.message 
    });
  }
});

// POST /api/query - ዳታ ወደ Turso ለመላክ እና ለማንበብ
app.post('/api/query', async (req, res) => {
  try {
    const { sql, args } = req.body;
    const result = await db.execute({ sql, args: args || [] });
    res.json({ success: true, result });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ሌሎችን ጥያቄዎች ወደ index.html መምራት
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'index.html'));
});

export default app;
