import express from 'express';

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
      'Authorization': `Bearer ${TURSO_TOKEN}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      requests: [
        {
          type: 'execute',
          stmt: {
            sql,
            args: args.map(value => ({ type: typeof value === 'number' ? 'integer' : 'text', value: String(value) }))
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

// Test
app.get('/api/test', (req, res) => {
  res.json({
    message: 'Server is running perfectly!'
  });
});

// Create user in Turso
app.post('/api/users', async (req, res) => {
  try {
    const { name, email } = req.body;

    if (!name || !email) {
      return res.status(400).json({
        error: 'Name and email are required'
      });
    }

    const data = await tursoQuery(
      'INSERT INTO users (name, email) VALUES (?, ?)',
      [name, email]
    );

    res.json({
      success: true,
      data
    });
  } catch (error) {
    console.error('Turso error:', error);

    res.status(500).json({
      error: 'Failed to create user',
      details: error.message
    });
  }
});

// Get users from Turso
app.get('/api/users', async (req, res) => {
  try {
    const data = await tursoQuery(
      'SELECT * FROM users'
    );

    res.json(data);
  } catch (error) {
    console.error('Turso error:', error);

    res.status(500).json({
      error: 'Failed to load users',
      details: error.message
    });
  }
});

export default app;

app.get('/api/seasons', async (req, res) => {
  try {
    const data = await tursoQuery(
      'SELECT * FROM seasons ORDER BY id DESC'
    );

    res.json(data);
  } catch (error) {
    console.error('Turso error:', error);

    res.status(500).json({
      error: 'Failed to load seasons',
      details: error.message
    });
  }
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
    console.error('Turso error:', error);

    res.status(500).json({
      error: error.message
    });
  }
});

app.get('/api/create-products-table', async (req, res) => {
  try {
    await tursoQuery(`
      CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        unit TEXT NOT NULL DEFAULT 'pcs',
        purchase_price REAL NOT NULL DEFAULT 0,
        selling_price REAL NOT NULL DEFAULT 0,
        stock REAL NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `);

    res.json({
      success: true,
      message: 'Products table created successfully'
    });
  } catch (error) {
    console.error('Turso error:', error);

    res.status(500).json({
      error: error.message
    });
  }
});

app.get('/api/products', async (req, res) => {
  try {
    const data = await tursoQuery(
      'SELECT * FROM products ORDER BY id DESC'
    );

    res.json(data);
  } catch (error) {
    console.error('Turso error:', error);

    res.status(500).json({
      error: 'Failed to load products',
      details: error.message
    });
  }
});
app.post('/api/products', async (req, res) => {
  try {
    const {
      name,
      unit,
      purchase_price,
      selling_price,
      stock
    } = req.body;

    if (!name) {
      return res.status(400).json({
        error: 'Product name is required'
      });
    }

    const data = await tursoQuery(
      `INSERT INTO products
       (name, unit, purchase_price, selling_price, stock)
       VALUES (?, ?, ?, ?, ?)`,
      [
        name,
        unit || 'pcs',
        Number(purchase_price) || 0,
        Number(selling_price) || 0,
        Number(stock) || 0
      ]
    );

    res.json({
      success: true,
      message: 'Product created successfully',
      data
    });

  } catch (error) {
    console.error('Turso error:', error);

    res.status(500).json({
      error: 'Failed to create product',
      details: error.message
    });
  }
});
// 💰 Finance / Cash Foundation
app.get('/api/create-finance-tables', async (req, res) => {
  try {
    await tursoQuery(`
      CREATE TABLE IF NOT EXISTS cash_transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        type TEXT NOT NULL,
        description TEXT NOT NULL,
        amount REAL NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `);

    res.json({
      success: true,
      message: 'Finance tables created successfully'
    });

  } catch (error) {
    console.error('Turso error:', error);

    res.status(500).json({
      error: error.message
    });
  }
});

// 💰 Current Cash / Capital
app.get('/api/cash-balance', async (req, res) => {
  try {
    const data = await tursoQuery(`
      SELECT COALESCE(SUM(amount), 0) AS balance
      FROM cash_transactions
    `);

    res.json(data);

  } catch (error) {
    console.error('Turso error:', error);

    res.status(500).json({
      error: 'Failed to load cash balance',
      details: error.message
    });
  }
});

// 📋 Recent Cash Transactions
app.get('/api/recent-cash-transactions', async (req, res) => {
  try {
    const data = await tursoQuery(`
      SELECT *
      FROM cash_transactions
      ORDER BY id DESC
      LIMIT 20
    `);

    res.json(data);

  } catch (error) {
    console.error('Turso error:', error);

    res.status(500).json({
      error: 'Failed to load cash transactions',
      details: error.message
    });
  }
});
