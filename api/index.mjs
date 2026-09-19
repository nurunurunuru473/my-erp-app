import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url'; 
import { createClient } from '@libsql/client';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename); 

const app = express();
app.use(express.json()); 

// Static files (index.html ያለበትን root directory ለማመልከት)
const rootDir = path.resolve(__dirname, '..');
app.use(express.static(rootDir));

// Turso DB Connection
const db = createClient({
  url: process.env.TURSO_DATABASE_URL || "",
  authToken: process.env.TURSO_AUTH_TOKEN || "",
});

app.get('/api/test', async (req, res) => {
  try {
    const result = await db.execute("SELECT 1;");
    res.json({ message: "Server and Turso DB are running perfectly!", db: result });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
}); 

// JSON Data መቀበያና መላኪያ Endpoint
app.post('/api/query', async (req, res) => {
  try {
    const { sql, args } = req.body || {};
    const result = await db.execute({ sql: sql || "", args: args || [] });
    res.json({ success: true, result });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ማንኛውም ሌላ request ሲመጣ index.html መላክ
app.get('*', (req, res) => {
  res.sendFile(path.join(rootDir, 'index.html'));
}); 

export default app;
