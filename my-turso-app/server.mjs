import dotenv from 'dotenv';

dotenv.config({ path: '.env.local' });
import express from 'express';
import api from './api/index.mjs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

app.use(express.json());

const TURSO_URL = process.env.TURSO_URL;
const TURSO_TOKEN = process.env.TURSO_TOKEN;

function tursoEndpoint() {
  let url = TURSO_URL;

  if (url.startsWith('libsql://')) {
    url = 'https://' + url.slice('libsql://'.length);
  }

  return url.replace(/\/$/, '') + '/v2/pipeline';
}

async function tursoQuery(sql, args = []) {
  const response = await fetch(tursoEndpoint(), {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${TURSO_TOKEN}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      requests: [
        {
          type: 'execute',
          stmt: {
            sql,
            args
          }
        },
        {
          type: 'close'
        }
      ]
    })
  });

  const data = await response.json();

  if (!response.ok) {
    throw new Error(JSON.stringify(data));
  }

  return data;
}

// Test API
app.get('/api/test', (req, res) => {
  res.json({
    message: 'Server is running perfectly!'
  });
});

// Users API
app.get('/api/users', async (req, res) => {
  try {
    const data = await tursoQuery(
      'SELECT * FROM users'
    );

    res.json(data);
  } catch (error) {
    res.status(500).json({
      error: 'Failed to load users',
      details: error.message
    });
  }
});

// Create seasons table
app.get('/api/create-seasons-table', async (req, res) => {
  try {
    await tursoQuery(`
      CREATE TABLE IF NOT EXISTS seasons (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        active INTEGER NOT NULL DEFAULT 0
      )
    `);

    res.json({
      success: true,
      message: 'Seasons table created successfully'
    });
  } catch (error) {
    res.status(500).json({
      error: error.message
    });
  }
});

// Create 2018 E.C. season
app.get('/api/create-season-2018', async (req, res) => {
  try {
    await tursoQuery(`
      INSERT OR IGNORE INTO seasons (name, active)
      VALUES ('2018 E.C.', 1)
    `);

    res.json({
      success: true,
      season: '2018 E.C.'
    });
  } catch (error) {
    res.status(500).json({
      error: error.message
    });
  }
});

// Get seasons
app.get('/api/seasons', async (req, res) => {
  try {
    const data = await tursoQuery(
      'SELECT * FROM seasons ORDER BY id DESC'
    );

    res.json(data);
  } catch (error) {
    res.status(500).json({
      error: error.message
    });
  }
});

// Website
app.use(express.static(__dirname));
app.use(api);
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});	


app.get('/api/create-users-table', async (req, res) => {
  try {
    await tursoQuery(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL
      )
    `);

    res.json({
      success: true,
      message: 'Users table created successfully'
    });
  } catch (error) {
    res.status(500).json({
      error: error.message
    });
  }
});
