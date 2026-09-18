import { createClient } from '@libsql/client';

export default async function handler(req, res) {
  try {
    const db = createClient({
      url: process.env.TURSO_DATABASE_URL || "",
      authToken: process.env.TURSO_AUTH_TOKEN || "",
    });

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
