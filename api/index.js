import { createClient } from '@libsql/client';

export default async function handler(req, res) {
  // CORS Headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  const db = createClient({
    url: process.env.TURSO_DATABASE_URL || "",
    authToken: process.env.TURSO_AUTH_TOKEN || "",
  });

  // /api/test
  if (req.url.includes('/api/test')) {
    try {
      const result = await db.execute("SELECT 1;");
      return res.status(200).json({ 
        status: "SUCCESS", 
        message: "Turso DB Connection is Working!", 
        data: result 
      });
    } catch (err) {
      return res.status(500).json({ 
        status: "ERROR", 
        message: "Failed to connect to Turso", 
        error: err.message 
      });
    }
  }

  // /api/query (ለ ፎርም መረጃ መላኪያ)
  if (req.method === 'POST') {
    try {
      const { sql, args } = req.body || {};
      const result = await db.execute({ sql, args: args || [] });
      return res.status(200).json({ success: true, result });
    } catch (err) {
      return res.status(500).json({ success: false, error: err.message });
    }
  }

  return res.status(404).json({ error: "Route not found" });
}
