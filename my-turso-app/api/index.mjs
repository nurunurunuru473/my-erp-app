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
      error: "Authentication required"
    });
  }

  req.user = user;
  next();
}

function requireAdmin(req, res, next) {
  if (req.user?.role !== "admin") {
    return res.status(403).json({
      error: "Admin access required"
    });
  }

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
app.post('/api/register', async (req, res) => {
  try {
    const {
      name,
      email,
      username,
      password,
      language = 'am'
    } = req.body;

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
      'SELECT id FROM users WHERE username = ? LIMIT 1',
      [username.trim()]
    );

    const existingRows =
      existing.results?.[0]?.response?.result?.rows || [];

    if (existingRows.length) {
      return res.status(409).json({
        error: 'Username already exists'
      });
    }

    const passwordHash = hashPassword(password);

    await tursoQuery(
      `INSERT INTO users
       (name, email, username, password_hash, role, active, language)
       VALUES (?, ?, ?, ?, 'user', 1, ?)`,
      [
        name.trim(),
        email?.trim() || '',
        username.trim(),
        passwordHash,
        language === 'en' ? 'en' : 'am'
      ]
    );

    res.json({
      success: true,
      message: 'Account created successfully'
    });

  } catch (error) {
    console.error('Register error:', error);

    res.status(500).json({
      error: 'Failed to create account',
      details: error.message
    });
  }
});

app.post('/api/users', requireAuth, requireAdmin, async (req, res) => {
  try {
    const {
      name,
      email,
      username,
      password,
      role = 'user',
      active = 1,
      language = 'am'
    } = req.body;

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

    if (!['admin', 'user'].includes(role)) {
      return res.status(400).json({
        error: 'Invalid role'
      });
    }

    const existing = await tursoQuery(
      'SELECT id FROM users WHERE username = ? LIMIT 1',
      [username.trim()]
    );

    const existingRows =
      existing.results?.[0]?.response?.result?.rows || [];

    if (existingRows.length) {
      return res.status(409).json({
        error: 'Username already exists'
      });
    }

    const passwordHash = hashPassword(password);

    const data = await tursoQuery(
      `INSERT INTO users
       (name, email, username, password_hash, role, active, language)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        name.trim(),
        email?.trim() || '',
        username.trim(),
        passwordHash,
        role,
        Number(active) ? 1 : 0,
        language === 'en' ? 'en' : 'am'
      ]
    );

    res.json({
      success: true,
      message: 'User created successfully',
      data
    });

  } catch (error) {
    console.error('Create user error:', error);

    res.status(500).json({
      error: 'Failed to create user',
      details: error.message
    });
  }
});

// Get users from Turso
app.get('/api/users', requireAuth, requireAdmin, async (req, res) => {
  try {
    const data = await tursoQuery(
      'SELECT id, name, email, username, role, active, language FROM users'
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
// Admin: Enable / Disable user
app.patch('/api/users/:id/status', requireAuth, requireAdmin, async (req, res) => {
  try {
    const userId = Number(req.params.id);
    const active = Number(req.body.active);

    if (!Number.isInteger(userId) || userId <= 0) {
      return res.status(400).json({
        error: 'Invalid user ID'
      });
    }

    if (active !== 0 && active !== 1) {
      return res.status(400).json({
        error: 'Active must be 0 or 1'
      });
    }

    if (userId === req.user.id) {
      return res.status(400).json({
        error: 'You cannot disable your own account'
      });
    }

    const existing = await tursoQuery(
      'SELECT id FROM users WHERE id = ? LIMIT 1',
      [userId]
    );

    const rows =
      existing.results?.[0]?.response?.result?.rows || [];

    if (!rows.length) {
      return res.status(404).json({
        error: 'User not found'
      });
    }

    await tursoQuery(
      'UPDATE users SET active = ? WHERE id = ?',
      [active, userId]
    );

    res.json({
      success: true,
      message: active === 1
        ? 'User enabled successfully'
        : 'User disabled successfully'
    });

  } catch (error) {
    console.error('User status error:', error);

    res.status(500).json({
      error: 'Failed to update user status',
      details: error.message
    });
  }
});

// Admin: Delete user
app.delete('/api/users/:id', requireAuth, requireAdmin, async (req, res) => {
  try {
    const userId = Number(req.params.id);

    if (!Number.isInteger(userId) || userId <= 0) {
      return res.status(400).json({
        error: 'Invalid user ID'
      });
    }

    if (userId === req.user.id) {
      return res.status(400).json({
        error: 'You cannot delete your own account'
      });
    }

    const existing = await tursoQuery(
      'SELECT id FROM users WHERE id = ? LIMIT 1',
      [userId]
    );

    const rows =
      existing.results?.[0]?.response?.result?.rows || [];

    if (!rows.length) {
      return res.status(404).json({
        error: 'User not found'
      });
    }

    await tursoQuery(
      'DELETE FROM users WHERE id = ?',
      [userId]
    );

    res.json({
      success: true,
      message: 'User deleted successfully'
    });

  } catch (error) {
    console.error('User delete error:', error);

    res.status(500).json({
      error: 'Failed to delete user',
      details: error.message
    });
  }
});


// 🔧 Sales cost-price migration
app.get('/api/upgrade-sales-table', async (req, res) => {
  try {
    await tursoQuery(`
      ALTER TABLE sales
      ADD COLUMN cost_price REAL NOT NULL DEFAULT 0
    `);
  } catch (error) {
    if (!String(error.message).includes('duplicate column name')) {
      return res.status(500).json({
        error: 'Failed to add sales cost_price',
        details: error.message
      });
    }
  }

  try {
    await tursoQuery(`
      UPDATE sales
      SET cost_price = (
        SELECT purchase_price
        FROM products
        WHERE products.id = sales.product_id
      )
      WHERE cost_price = 0
    `);

    res.json({
      success: true,
      message: 'Sales cost_price migration completed successfully'
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to update sales cost_price',
      details: error.message
    });
  }
});


// 💼 Capital Transactions

// 💼 Register Capital
app.post('/api/capital', async (req, res) => {
  try {
    const { description, amount } = req.body;
    const value = Number(amount);

    if (!description || !Number.isFinite(value) || value <= 0) {
      return res.status(400).json({
        error: 'Description and valid amount are required'
      });
    }

    const capital = await tursoQuery(
      `INSERT INTO capital_transactions
       (type, description, amount)
       VALUES (?, ?, ?)`,
      ['capital', description, value]
    );

    await tursoQuery(
      `INSERT INTO cash_transactions
       (type, description, amount)
       VALUES (?, ?, ?)`,
      ['capital', `Capital - ${description}`, value]
    );

    res.json({
      success: true,
      message: 'Capital registered successfully',
      capital
    });
  } catch (error) {
    console.error('Capital error:', error);

    res.status(500).json({
      error: 'Failed to register capital',
      details: error.message
    });
  }
});

// 💼 Owner Withdrawal
app.post('/api/withdrawal', async (req, res) => {
  try {
    const { description, amount } = req.body;
    const value = Number(amount);

    if (!description || !Number.isFinite(value) || value <= 0) {
      return res.status(400).json({
        error: 'Description and valid amount are required'
      });
    }

    const withdrawal = await tursoQuery(
      `INSERT INTO capital_transactions
       (type, description, amount)
       VALUES (?, ?, ?)`,
      ['withdrawal', description, -value]
    );

    await tursoQuery(
      `INSERT INTO cash_transactions
       (type, description, amount)
       VALUES (?, ?, ?)`,
      ['withdrawal', `Withdrawal - ${description}`, -value]
    );

    res.json({
      success: true,
      message: 'Withdrawal registered successfully',
      withdrawal
    });
  } catch (error) {
    console.error('Withdrawal error:', error);

    res.status(500).json({
      error: 'Failed to register withdrawal',
      details: error.message
    });
  }
});

// 💼 Capital Transactions
app.get('/api/capital-transactions', async (req, res) => {
  try {
    const data = await tursoQuery(`
      SELECT *
      FROM capital_transactions
      ORDER BY id DESC
      LIMIT 50
    `);

    res.json(data);
  } catch (error) {
    console.error('Capital transactions error:', error);

    res.status(500).json({
      error: 'Failed to load capital transactions',
      details: error.message
    });
  }
});


// 📊 Capital & Profit Summary
app.get('/api/capital-profit', async (req, res) => {
  try {
    const salesData = await tursoQuery(`
      SELECT
        COALESCE(SUM(total), 0) AS revenue,
        COALESCE(SUM(quantity * cost_price), 0) AS cogs
      FROM sales
    `);

    const expenseData = await tursoQuery(`
      SELECT COALESCE(SUM(ABS(amount)), 0) AS expenses
      FROM cash_transactions
      WHERE type = 'expense'
    `);

    const capitalData = await tursoQuery(`
      SELECT
        COALESCE(SUM(CASE WHEN type = 'capital' THEN amount ELSE 0 END), 0) AS capital_in,
        COALESCE(SUM(CASE WHEN type = 'withdrawal' THEN ABS(amount) ELSE 0 END), 0) AS withdrawals
      FROM capital_transactions
    `);

    const cashData = await tursoQuery(`
      SELECT COALESCE(SUM(amount), 0) AS cash
      FROM cash_transactions
    `);

    const stockData = await tursoQuery(`
      SELECT COALESCE(SUM(stock * purchase_price), 0) AS stock_value
      FROM products
    `);

    const salesRows =
      salesData.results?.[0]?.response?.result?.rows || [];

    const expenseRows =
      expenseData.results?.[0]?.response?.result?.rows || [];

    const capitalRows =
      capitalData.results?.[0]?.response?.result?.rows || [];

    const cashRows =
      cashData.results?.[0]?.response?.result?.rows || [];

    const stockRows =
      stockData.results?.[0]?.response?.result?.rows || [];

    const revenue = Number(salesRows[0]?.[0]?.value || 0);
    const cogs = Number(salesRows[0]?.[1]?.value || 0);
    const expenses = Number(expenseRows[0]?.[0]?.value || 0);
    const capitalIn = Number(capitalRows[0]?.[0]?.value || 0);
    const withdrawals = Number(capitalRows[0]?.[1]?.value || 0);
    const cash = Number(cashRows[0]?.[0]?.value || 0);
    const stockValue = Number(stockRows[0]?.[0]?.value || 0);

    const grossProfit = revenue - cogs;
    const netProfit = grossProfit - expenses;
    const ownerEquity = capitalIn + netProfit - withdrawals;

    res.json({
      success: true,
      summary: {
        revenue,
        cogs,
        gross_profit: grossProfit,
        expenses,
        net_profit: netProfit,
        capital_in: capitalIn,
        withdrawals,
        cash,
        stock_value: stockValue,
        owner_equity: ownerEquity
      }
    });

  } catch (error) {
    console.error('Capital & Profit error:', error);

    res.status(500).json({
      error: 'Failed to calculate capital and profit',
      details: error.message
    });
  }
});

app.get('/api/create-capital-table', async (req, res) => {
  try {
    await tursoQuery(`
      CREATE TABLE IF NOT EXISTS capital_transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        type TEXT NOT NULL,
        description TEXT NOT NULL,
        amount REAL NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `);

    res.json({
      success: true,
      message: 'Capital table created successfully'
    });
  } catch (error) {
    console.error('Capital table error:', error);

    res.status(500).json({
      error: 'Failed to create capital table',
      details: error.message
    });
  }
});
// 💳 Create Customer Payments Table
app.get('/api/create-customer-payments-table', async (req, res) => {
  try {
    await tursoQuery(`
      CREATE TABLE IF NOT EXISTS customer_payments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        customer TEXT NOT NULL,
        sale_id INTEGER,
        description TEXT NOT NULL,
        amount REAL NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `);

    res.json({
      success: true,
      message: 'Customer payments table created successfully'
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to create customer payments table',
      details: error.message
    });
  }
});

// 💳 Register Customer Credit Payment
app.post('/api/customer-payments', async (req, res) => {
  try {
    const {
      customer,
      sale_id = null,
      description = 'Customer Credit Payment',
      amount
    } = req.body;

    const paymentAmount = Number(amount);

    if (!customer || !customer.trim()) {
      return res.status(400).json({
        error: 'Customer name is required'
      });
    }

    if (!Number.isFinite(paymentAmount) || paymentAmount <= 0) {
      return res.status(400).json({
        error: 'Payment amount must be greater than 0'
      });
    }

    await tursoQuery(
      `INSERT INTO customer_payments
       (customer, sale_id, description, amount)
       VALUES (?, ?, ?, ?)`,
      [
        customer.trim(),
        sale_id,
        description,
        paymentAmount
      ]
    );

    await tursoQuery(
      `INSERT INTO cash_transactions
       (type, description, amount)
       VALUES ('customer_payment', ?, ?)`,
      [
        `Customer Payment - ${customer.trim()}`,
        paymentAmount
      ]
    );

    res.json({
      success: true,
      message: 'Customer payment recorded successfully',
      customer: customer.trim(),
      amount: paymentAmount
    });

  } catch (error) {
    console.error('Customer payment error:', error);

    res.status(500).json({
      error: 'Failed to record customer payment',
      details: error.message
    });
  }
});
// 📒 Customer Credit Balances
app.get('/api/customer-credits', async (req, res) => {
  try {
    const data = await tursoQuery(`
      SELECT
        r.customer,
        COALESCE(SUM(r.amount), 0) AS credit_total,
        COALESCE((
          SELECT SUM(p.amount)
          FROM customer_payments p
          WHERE p.customer = r.customer
        ), 0) AS paid_total
      FROM customer_receivables r
      GROUP BY r.customer
      ORDER BY r.customer
    `);

    const rows =
      data.results?.[0]?.response?.result?.rows || [];

    const credits = rows.map(row => {
      const customer = row[0]?.value || '';
      const creditTotal = Number(row[1]?.value || 0);
      const paidTotal = Number(row[2]?.value || 0);

      return {
        customer,
        credit_total: creditTotal,
        paid_total: paidTotal,
        outstanding: Math.max(creditTotal - paidTotal, 0)
      };
    }).filter(item => item.outstanding > 0);

    res.json({
      success: true,
      credits
    });

  } catch (error) {
    console.error('Customer credits error:', error);

    res.status(500).json({
      error: 'Failed to load customer credits',
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

    if (!['cash', 'credit'].includes(payment_type)) {
      return res.status(400).json({
        error: 'Invalid payment_type'
      });
    }

    if (payment_type === 'credit' && !customer) {
      return res.status(400).json({
        error: 'Customer name is required for credit sale'
      });
    }

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
        payment_type TEXT NOT NULL DEFAULT 'cash',
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
// 🔄 Add payment_type to existing sales table
app.get('/api/upgrade-sales-payment-type', async (req, res) => {
  try {
    try {
      await tursoQuery(`
        ALTER TABLE sales
        ADD COLUMN payment_type TEXT NOT NULL DEFAULT 'cash'
      `);
    } catch (error) {
      if (!String(error.message).toLowerCase().includes('duplicate column')) {
        throw error;
      }
    }

    res.json({
      success: true,
      message: 'Sales payment_type migration completed successfully'
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to migrate sales payment_type',
      details: error.message
    });
  }
});

// 💳 Customer Receivables Table
app.get('/api/create-receivables-table', async (req, res) => {
  try {
    await tursoQuery(`
      CREATE TABLE IF NOT EXISTS customer_receivables (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sale_id INTEGER,
        customer TEXT NOT NULL,
        description TEXT NOT NULL,
        amount REAL NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `);

// 💳 Create Supplier Debts Table
app.get('/api/create-supplier-debts-table', async (req, res) => {
  try {
    await tursoQuery(`
      CREATE TABLE IF NOT EXISTS supplier_debts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        purchase_id INTEGER,
        supplier TEXT NOT NULL,
        description TEXT NOT NULL,
        amount REAL NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `);

    res.json({
      success: true,
      message: 'Supplier debts table created successfully'
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to create supplier debts table',
      details: error.message
    });
  }
});
    res.json({
      success: true,
      message: 'Customer receivables table created successfully'
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to create receivables table',
      details: error.message
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
      customer,
      payment_type = 'cash'
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
      'SELECT id, name, stock, purchase_price FROM products WHERE id = ?',
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
    const costPrice = Number(productRows[0][3].value) || 0;

    if (qty > currentStock) {
      return res.status(400).json({
        error: `Insufficient stock. Available stock: ${currentStock}`
      });
    }

    const total = qty * price;

    const sale = await tursoQuery(
      `INSERT INTO sales
       (product_id, quantity, unit_price, cost_price, customer, total, payment_type)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        productId,
        qty,
        price,
        costPrice,
        customer || '',
        total,
        payment_type
      ]
    );

    await tursoQuery(
      'UPDATE products SET stock = stock - ? WHERE id = ?',
      [qty, productId]
    );

    if (payment_type === 'cash') {
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
    } else {
      await tursoQuery(
        `INSERT INTO customer_receivables
         (sale_id, customer, description, amount)
         VALUES (?, ?, ?, ?)`,
        [
          sale.results?.[0]?.response?.result?.last_insert_rowid || null,
          customer,
          `Credit Sale - ${productName}`,
          total
        ]
      );
    }

    res.json({
      success: true,
      message: 'Sale registered successfully',
      total,
      payment_type,
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


app.get('/api/dashboard-sales-summary', async (req, res) => {
  try {
    const salesData = await tursoQuery(`
      SELECT
        COALESCE(SUM(
          CASE
            WHEN date(created_at, '+3 hours') = date('now', '+3 hours')
            THEN total
            ELSE 0
          END
        ), 0) AS sales_today,

        COUNT(
          CASE
            WHEN date(created_at, '+3 hours') = date('now', '+3 hours')
            THEN 1
          END
        ) AS sales_count_today,

        COALESCE(SUM(
          CASE
            WHEN date(created_at, '+3 hours') = date('now', '+3 hours')
             AND payment_type = 'cash'
            THEN total
            ELSE 0
          END
        ), 0) AS sales_collected_today

      FROM sales
    `);

    const creditData = await tursoQuery(`
  SELECT
    COALESCE((SELECT SUM(amount) FROM customer_receivables), 0)
    -
    COALESCE((SELECT SUM(amount) FROM customer_payments), 0)
    AS credit_total
`);
const paymentData = await tursoQuery(`
  SELECT
    COALESCE(SUM(amount), 0) AS customer_payments_today
  FROM customer_payments
  WHERE date(created_at, '+3 hours') = date('now', '+3 hours')
`);
    const salesRows =
      salesData.results?.[0]?.response?.result?.rows || [];

    const creditRows =
      creditData.results?.[0]?.response?.result?.rows || [];

const paymentRows =
  paymentData.results?.[0]?.response?.result?.rows || [];

const paymentRow = paymentRows[0] || [];
    const salesRow = salesRows[0] || [];
    const creditRow = creditRows[0] || [];

    res.json({
      success: true,
      summary: {
        sales_today: Number(salesRow[0]?.value || 0),
        sales_count_today: Number(salesRow[1]?.value || 0),
        sales_collected_today:
  Number(salesRow[2]?.value || 0) +
  Number(paymentRow[0]?.value || 0),
        credit_today: Number(creditRow[0]?.value || 0)
      }
    });

  } catch (error) {
    console.error('Dashboard sales summary error:', error);

    res.status(500).json({
      error: 'Failed to load dashboard sales summary',
      details: error.message
    });
  }
});

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
        sales.cost_price,
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
