import dotenv from 'dotenv';

dotenv.config({ path: '.env.local' });
import crypto from 'node:crypto';
import express from 'express';

const app = express();

app.use(express.json());

const TURSO_URL = process.env.TURSO_URL;
const TURSO_TOKEN = process.env.TURSO_TOKEN;
const AUTH_SECRET = process.env.AUTH_SECRET;
function tursoEndpoint() {
  let url = TURSO_URL;

  if (url.startsWith('libsql://')) {
    url = 'https://' + url.slice('libsql://'.length);
  }

  return url.replace(/\/$/, '') + '/v2/pipeline';
}
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');

  const hash = crypto.scryptSync(
    password,
    salt,
    64
  ).toString('hex');

  return `${salt}:${hash}`;
}
function verifyPassword(password, stored) {
  const [salt, key] = String(stored || '').split(':');

  if (!salt || !key || key.length !== 128) {
    return false;
  }

  const derived = crypto.scryptSync(
    password,
    salt,
    64
  ).toString('hex');

  return crypto.timingSafeEqual(
    Buffer.from(derived, 'hex'),
    Buffer.from(key, 'hex')
  );
}
function createAuthToken(user) {
  const payload = {
    id: user.id,
    role: user.role,
    exp: Math.floor(Date.now() / 1000) + (60 * 60 * 24 * 7)
  };

  const encoded = Buffer
    .from(JSON.stringify(payload))
    .toString('base64url');

  const signature = crypto
    .createHmac('sha256', AUTH_SECRET)
    .update(encoded)
    .digest('base64url');

  return `${encoded}.${signature}`;
}
function parseCookies(req) {
  const header = req.headers.cookie || '';

  return Object.fromEntries(
    header
      .split(';')
      .map(part => part.trim())
      .filter(Boolean)
      .map(part => {
        const index = part.indexOf('=');

        if (index === -1) {
          return [part, ''];
        }

        return [
          part.slice(0, index),
          decodeURIComponent(part.slice(index + 1))
        ];
      })
  );
}
function verifyAuthToken(token) {
  if (!token) {
    return null;
  }

  const parts = token.split('.');

  if (parts.length !== 2) {
    return null;
  }

  const [encoded, signature] = parts;

  const expectedSignature = crypto
    .createHmac('sha256', AUTH_SECRET)
    .update(encoded)
    .digest('base64url');

  if (signature !== expectedSignature) {
    return null;
  }

  try {
    const payload = JSON.parse(
      Buffer.from(encoded, 'base64url').toString('utf8')
    );

    if (!payload.id || !payload.exp) {
      return null;
    }

    if (payload.exp < Math.floor(Date.now() / 1000)) {
      return null;
    }

    return payload;
  } catch {
    return null;
  }
}
function requireAuth(req, res, next) {
  const cookies = parseCookies(req);
  const token = cookies.auth_token;

  const user = verifyAuthToken(token);

  if (!user) {
    return res.status(401).json({
      error: 'Authentication required'
    });
  }

  req.user = user;
  next();
}
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        error: 'Username and password are required'
      });
    }

    const data = await tursoQuery(
      `SELECT id, name, email, username, password_hash, role, active, language
       FROM users
       WHERE username = ?
       LIMIT 1`,
      [username.trim()]
    );

    const rows =
      data.results?.[0]?.response?.result?.rows || [];

    if (!rows.length) {
      return res.status(401).json({
        error: 'Invalid username or password'
      });
    }

    const row = rows[0];

    const user = {
      id: Number(row[0].value),
      name: row[1].value,
      email: row[2].value,
      username: row[3].value,
      password_hash: row[4].value,
      role: row[5].value,
      active: Number(row[6].value),
      language: row[7].value
    };

    if (!user.active) {
      return res.status(403).json({
        error: 'This account is disabled'
      });
    }

    if (!verifyPassword(password, user.password_hash)) {
      return res.status(401).json({
        error: 'Invalid username or password'
      });
    }

    const token = createAuthToken(user);

    res.setHeader(
      'Set-Cookie',
      `auth_token=${encodeURIComponent(token)}; HttpOnly; ${process.env.VERCEL === "1" || process.env.NODE_ENV === "production" ? "Secure; " : ""}SameSite=Lax; Path=/; Max-Age=604800`
    );

    res.json({
      success: true,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        username: user.username,
        role: user.role,
        language: user.language
      }
    });

  } catch (error) {
    console.error('Login error:', error);

    res.status(500).json({
      error: 'Login failed',
      details: error.message
    });
  }
});
app.get('/api/me', requireAuth, async (req, res) => {
  try {
    const data = await tursoQuery(
      `SELECT id, name, email, username, role, active, language
       FROM users
       WHERE id = ?
       LIMIT 1`,
      [req.user.id]
    );

    const rows =
      data.results?.[0]?.response?.result?.rows || [];

    if (!rows.length) {
      return res.status(404).json({
        error: 'User not found'
      });
    }

    const row = rows[0];

    res.json({
      authenticated: true,
      user: {
        id: Number(row[0].value),
        name: row[1].value,
        email: row[2].value,
        username: row[3].value,
        role: row[4].value,
        active: Number(row[5].value),
        language: row[6].value
      }
    });

  } catch (error) {
    console.error('Me error:', error);

    res.status(500).json({
      error: 'Failed to load current user',
      details: error.message
    });
  }
});
app.post('/api/logout', (req, res) => {
  res.setHeader(
    'Set-Cookie',
    'auth_token=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0'
  );

  res.json({
    success: true,
    message: 'Logged out successfully'
  });
});
app.post('/api/bootstrap-admin', async (req, res) => {
  try {
    const { name, username, password, email } = req.body;

    if (!name || !username || !password) {
      return res.status(400).json({
        error: 'Name, username and password are required'
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        error: 'Password must be at least 8 characters'
      });
    }

    const existing = await tursoQuery(
      `SELECT id FROM users
       WHERE role = 'admin'
       LIMIT 1`
    );

    const existingRows =
      existing.results?.[0]?.response?.result?.rows || [];

    if (existingRows.length) {
      return res.status(403).json({
        error: 'Admin account already exists'
      });
    }

    const passwordHash = hashPassword(password);

    const data = await tursoQuery(
      `INSERT INTO users
       (name, email, username, password_hash, role, active, language)
       VALUES (?, ?, ?, ?, 'admin', 1, 'am')`,
      [
        name.trim(),
        email?.trim() || '',
        username.trim(),
        passwordHash
      ]
    );

    res.json({
      success: true,
      message: 'Admin account created successfully',
      data
    });

  } catch (error) {
    console.error('Bootstrap admin error:', error);

    res.status(500).json({
      error: 'Failed to create admin',
      details: error.message
    });
  }
});
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

app.get('/api/migrate-users-auth', async (req, res) => {
  try {
    await tursoQuery(`
      ALTER TABLE users ADD COLUMN username TEXT
    `);

    await tursoQuery(`
      ALTER TABLE users ADD COLUMN password_hash TEXT
    `);

    await tursoQuery(`
      ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'
    `);

    await tursoQuery(`
      ALTER TABLE users ADD COLUMN active INTEGER NOT NULL DEFAULT 1
    `);

    await tursoQuery(`
      ALTER TABLE users ADD COLUMN language TEXT NOT NULL DEFAULT 'am'
    `);

    res.json({
      success: true,
      message: 'Users authentication fields added successfully'
    });

  } catch (error) {
    console.error('Migration error:', error);

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

app.get('/api/expenses-total', async (req, res) => {
  try {
    const data = await tursoQuery(`
      SELECT COALESCE(SUM(ABS(amount)), 0) AS total
      FROM cash_transactions
      WHERE type = 'expense'
    `);

    res.json(data);

  } catch (error) {
    console.error('Turso error:', error);

    res.status(500).json({
      error: 'Failed to load expenses total',
      details: error.message
    });
  }
});

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
// 💰 Income
app.post('/api/income', async (req, res) => {
  try {
    const { description, amount } = req.body;

    if (!description || !amount || Number(amount) <= 0) {
      return res.status(400).json({
        error: 'Description and valid amount are required'
      });
    }

    const data = await tursoQuery(
      `INSERT INTO cash_transactions
       (type, description, amount)
       VALUES (?, ?, ?)`,
      [
        'income',
        description,
        Number(amount)
      ]
    );

    res.json({
      success: true,
      message: 'Income registered successfully',
      data
    });

  } catch (error) {
    console.error('Turso error:', error);

    res.status(500).json({
      error: 'Failed to register income',
      details: error.message
    });
  }
});

// 💸 Expense
app.post('/api/expenses', async (req, res) => {
  try {
    const { description, amount } = req.body;

    if (!description || !amount || Number(amount) <= 0) {
      return res.status(400).json({
        error: 'Description and valid amount are required'
      });
    }

    const data = await tursoQuery(
      `INSERT INTO cash_transactions
       (type, description, amount)
       VALUES (?, ?, ?)`,
      [
        'expense',
        description,
        -Number(amount)
      ]
    );

    res.json({
      success: true,
      message: 'Expense registered successfully',
      data
    });

  } catch (error) {
    console.error('Turso error:', error);

    res.status(500).json({
      error: 'Failed to register expense',
      details: error.message
    });
  }
});
// 🛒 Purchases Table
app.get('/api/create-purchases-table', async (req, res) => {
  try {
    await tursoQuery(`
      CREATE TABLE IF NOT EXISTS purchases (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        product_id INTEGER NOT NULL,
        quantity REAL NOT NULL,
        unit_price REAL NOT NULL,
        supplier TEXT,
        total REAL NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `);

    res.json({
      success: true,
      message: 'Purchases table created successfully'
    });

  } catch (error) {
    console.error('Turso error:', error);

    res.status(500).json({
      error: error.message
    });
  }
});
// 🛒 Register Purchase
app.post('/api/purchases', async (req, res) => {
  try {
    const {
      product_id,
      quantity,
      unit_price,
      supplier
    } = req.body;

    const productId = Number(product_id);
    const qty = Number(quantity);
    const price = Number(unit_price);

    if (!Number.isInteger(productId) || productId <= 0) {
      return res.status(400).json({
        error: 'Valid product_id is required'
      });
    }

    if (!Number.isFinite(qty) || qty <= 0) {
      return res.status(400).json({
        error: 'Valid quantity is required'
      });
    }

    if (!Number.isFinite(price) || price < 0) {
      return res.status(400).json({
        error: 'Valid unit_price is required'
      });
    }

    const productData = await tursoQuery(
      'SELECT id, name FROM products WHERE id = ?',
      [productId]
    );

    const productRows =
      productData.results?.[0]?.response?.result?.rows || [];

    if (!productRows.length) {
      return res.status(404).json({
        error: 'Product not found'
      });
    }

    const productName = productRows[0][1].value;
    const total = qty * price;

    const purchase = await tursoQuery(
      `INSERT INTO purchases
       (product_id, quantity, unit_price, supplier, total)
       VALUES (?, ?, ?, ?, ?)`,
      [
        productId,
        qty,
        price,
        supplier || '',
        total
      ]
    );

    await tursoQuery(
      'UPDATE products SET stock = stock + ? WHERE id = ?',
      [qty, productId]
    );

    await tursoQuery(
      `INSERT INTO cash_transactions
       (type, description, amount)
       VALUES (?, ?, ?)`,
      [
        'purchase',
        `Purchase - ${productName}${supplier ? ` - ${supplier}` : ''}`,
        -total
      ]
    );

    res.json({
      success: true,
      message: 'Purchase registered successfully',
      total,
      purchase
    });

  } catch (error) {
    console.error('Turso error:', error);

    res.status(500).json({
      error: 'Failed to register purchase',
      details: error.message
    });
  }
});
// 🛍️ Sales Table
app.get('/api/create-sales-table', async (req, res) => {
  try {
    await tursoQuery(`
      CREATE TABLE IF NOT EXISTS sales (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        product_id INTEGER NOT NULL,
        quantity REAL NOT NULL,
        unit_price REAL NOT NULL,
        customer TEXT,
        total REAL NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `);

    res.json({
      success: true,
      message: 'Sales table created successfully'
    });

  } catch (error) {
    console.error('Turso error:', error);

    res.status(500).json({
      error: error.message
    });
  }
});
// 🛍️ Register Sale
app.post('/api/sales', async (req, res) => {
  try {
    const {
      product_id,
      quantity,
      unit_price,
      customer
    } = req.body;

    const productId = Number(product_id);
    const qty = Number(quantity);
    const price = Number(unit_price);

    if (!Number.isInteger(productId) || productId <= 0) {
      return res.status(400).json({
        error: 'Valid product_id is required'
      });
    }

    if (!Number.isFinite(qty) || qty <= 0) {
      return res.status(400).json({
        error: 'Valid quantity is required'
      });
    }

    if (!Number.isFinite(price) || price < 0) {
      return res.status(400).json({
        error: 'Valid unit_price is required'
      });
    }

    const productData = await tursoQuery(
      'SELECT id, name, stock FROM products WHERE id = ?',
      [productId]
    );

    const productRows =
      productData.results?.[0]?.response?.result?.rows || [];

    if (!productRows.length) {
      return res.status(404).json({
        error: 'Product not found'
      });
    }

    const productName = productRows[0][1].value;
    const currentStock = Number(productRows[0][2].value);

    if (qty > currentStock) {
      return res.status(400).json({
        error: `Insufficient stock. Available stock: ${currentStock}`
      });
    }

    const total = qty * price;

    const sale = await tursoQuery(
      `INSERT INTO sales
       (product_id, quantity, unit_price, customer, total)
       VALUES (?, ?, ?, ?, ?)`,
      [
        productId,
        qty,
        price,
        customer || '',
        total
      ]
    );

    await tursoQuery(
      'UPDATE products SET stock = stock - ? WHERE id = ?',
      [qty, productId]
    );

    await tursoQuery(
      `INSERT INTO cash_transactions
       (type, description, amount)
       VALUES (?, ?, ?)`,
      [
        'sale',
        `Sale - ${productName}${customer ? ` - ${customer}` : ''}`,
        total
      ]
    );

    res.json({
      success: true,
      message: 'Sale registered successfully',
      total,
      sale
    });

  } catch (error) {
    console.error('Turso error:', error);

    res.status(500).json({
      error: 'Failed to register sale',
      details: error.message
    });
  }
})
// 📋 Recent Purchases
app.get('/api/recent-purchases', async (req, res) => {
  try {
    const data = await tursoQuery(`
      SELECT
        purchases.id,
        products.name AS product_name,
        purchases.quantity,
        purchases.unit_price,
        purchases.supplier,
        purchases.total,
        purchases.created_at
      FROM purchases
      JOIN products
        ON purchases.product_id = products.id
      ORDER BY purchases.id DESC
      LIMIT 20
    `);

    res.json(data);

  } catch (error) {
    console.error('Turso error:', error);

    res.status(500).json({
      error: 'Failed to load recent purchases',
      details: error.message
    });
  }
});
// 📋 Recent Sales

app.get('/api/sales-total', async (req, res) => {
  try {
    const data = await tursoQuery(`
      SELECT COALESCE(SUM(total), 0) AS total
      FROM sales
    `);

    res.json(data);

  } catch (error) {
    console.error('Turso error:', error);

    res.status(500).json({
      error: 'Failed to load sales total',
      details: error.message
    });
  }
});

app.get('/api/recent-sales', async (req, res) => {
  try {
    const data = await tursoQuery(`
      SELECT
        sales.id,
        products.name AS product_name,
        sales.quantity,
        sales.unit_price,
        sales.customer,
        sales.total,
        sales.created_at
      FROM sales
      JOIN products
        ON sales.product_id = products.id
      ORDER BY sales.id DESC
      LIMIT 20
    `);

    res.json(data);

  } catch (error) {
    console.error('Turso error:', error);

    res.status(500).json({
      error: 'Failed to load recent sales',
      details: error.message
    });
  }
});
// 🏭 Production Table
app.get('/api/create-production-table', async (req, res) => {
  try {
    await tursoQuery(`
      CREATE TABLE IF NOT EXISTS production (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        product_id INTEGER NOT NULL,
        quantity REAL NOT NULL,
        note TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `);

    res.json({
      success: true,
      message: 'Production table created successfully'
    });

  } catch (error) {
    console.error('Turso error:', error);

    res.status(500).json({
      error: error.message
    });
  }
});
// 🏭 Register Production
app.post('/api/production', async (req, res) => {
  try {
    const {
      product_id,
      quantity,
      note
    } = req.body;

    const productId = Number(product_id);
    const qty = Number(quantity);

    if (!Number.isInteger(productId) || productId <= 0) {
      return res.status(400).json({
        error: 'Valid product_id is required'
      });
    }

    if (!Number.isFinite(qty) || qty <= 0) {
      return res.status(400).json({
        error: 'Valid quantity is required'
      });
    }

    const productData = await tursoQuery(
      'SELECT id, name FROM products WHERE id = ?',
      [productId]
    );

    const productRows =
      productData.results?.[0]?.response?.result?.rows || [];

    if (!productRows.length) {
      return res.status(404).json({
        error: 'Product not found'
      });
    }

    const productName = productRows[0][1].value;

    const production = await tursoQuery(
      `INSERT INTO production
       (product_id, quantity, note)
       VALUES (?, ?, ?)`,
      [
        productId,
        qty,
        note || ''
      ]
    );

    await tursoQuery(
      'UPDATE products SET stock = stock + ? WHERE id = ?',
      [qty, productId]
    );

    res.json({
      success: true,
      message: 'Production registered successfully',
      product: productName,
      quantity: qty,
      production
    });

  } catch (error) {
    console.error('Turso error:', error);

    res.status(500).json({
      error: 'Failed to register production',
      details: error.message
    });
  }
});
app.get('/api/recent-production', async (req, res) => {
  try {
    const data = await tursoQuery(`
      SELECT
        production.id,
        products.name AS product_name,
        production.quantity,
        production.note,
        production.created_at
      FROM production
      JOIN products
        ON production.product_id = products.id
      ORDER BY production.id DESC
      LIMIT 20
    `);

    res.json(data);

  } catch (error) {
    console.error('Turso error:', error);

    res.status(500).json({
      error: 'Failed to load recent production',
      details: error.message
    });
  }
});
