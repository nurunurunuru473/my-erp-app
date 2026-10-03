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
  console.log(
    '[AUTH DEBUG] cookie header present:',
    Boolean(req.headers.cookie)
  );

  const cookies = parseCookies(req);
  const token = cookies.auth_token;

  const user = verifyAuthToken(token);

  console.log(
    '[AUTH DEBUG] token present:',
    Boolean(token),
    'verified:',
    Boolean(user)
  );

  if (!user) {
    return res.status(401).json({
      error: "Authentication required"
    });
  }

  req.user = user;
  next();
}


async function requirePermissionCheck(req, permission) {
  if (req.user?.role === 'admin') {
    return true;
  }

  const department = String(
    req.user?.department || 'general'
  ).trim().toLowerCase();

  const departmentPermissions = {
    stock: ['delete_stock'],
    sales: ['delete_sales'],
    repairs: ['delete_repairs'],
    finance: [],
    general: []
  };

  const allowedForDepartment =
    departmentPermissions[department] || [];

  if (!allowedForDepartment.includes(permission)) {
    return false;
  }

  const data = await tursoQuery(
    `SELECT id
     FROM user_permissions
     WHERE user_id = ? AND permission = ?
     LIMIT 1`,
    [req.user.id, permission]
  );

  const rows =
    data.results?.[0]?.response?.result?.rows || [];

  return rows.length > 0;
}

function requirePermission(permission) {
  return async (req, res, next) => {
    try {
      if (req.user?.role === 'admin') {
        return next();
      }

      const allowed = await requirePermissionCheck(req, permission);

      if (!allowed) {
        return res.status(403).json({
          error: 'Permission denied',
          permission
        });
      }

      next();
    } catch (error) {
      console.error('Permission check error:', error);

      res.status(500).json({
        error: 'Failed to check permission',
        details: error.message
      });
    }
  };
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
        language: user.language,
        department: user.department || 'general',
        permissions: []
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
  const secureCookie =
    process.env.VERCEL === "1" ||
    process.env.NODE_ENV === "production"
      ? "Secure; "
      : "";

  res.setHeader(
    'Set-Cookie',
    `auth_token=; HttpOnly; ${secureCookie}SameSite=Lax; Path=/; Max-Age=0`
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
      language = 'am',
      department = 'general'
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

    const allowedDepartments = [
      'general',
      'stock',
      'sales',
      'repairs',
      'finance'
    ];

    if (!allowedDepartments.includes(department)) {
      return res.status(400).json({
        error: 'Invalid department'
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
       (name, email, username, password_hash, role, active, language, department)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        name.trim(),
        email?.trim() || '',
        username.trim(),
        passwordHash,
        role,
        Number(active) ? 1 : 0,
        language === 'en' ? 'en' : 'am',
        department
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
      'SELECT id, name, email, username, role, active, language, department FROM users'
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



// Admin: Update user profile
app.patch('/api/users/:id/profile', requireAuth, requireAdmin, async (req, res) => {
  try {
    const userId = Number(req.params.id);
    const { name, username, email } = req.body;

    if (!Number.isInteger(userId) || userId <= 0) {
      return res.status(400).json({
        error: 'Invalid user ID'
      });
    }

    if (!name || !username) {
      return res.status(400).json({
        error: 'Name and username are required'
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

    const duplicate = await tursoQuery(
      'SELECT id FROM users WHERE username = ? AND id != ? LIMIT 1',
      [username.trim(), userId]
    );

    const duplicateRows =
      duplicate.results?.[0]?.response?.result?.rows || [];

    if (duplicateRows.length) {
      return res.status(409).json({
        error: 'Username already exists'
      });
    }

    await tursoQuery(
      `UPDATE users
       SET name = ?, username = ?, email = ?
       WHERE id = ?`,
      [
        name.trim(),
        username.trim(),
        email?.trim() || '',
        userId
      ]
    );

    res.json({
      success: true,
      message: 'User profile updated successfully'
    });

  } catch (error) {
    console.error('User profile update error:', error);

    res.status(500).json({
      error: 'Failed to update user profile',
      details: error.message
    });
  }
});


// Admin: Change user password
app.patch('/api/users/:id/password', requireAuth, requireAdmin, async (req, res) => {
  try {
    const userId = Number(req.params.id);
    const { password } = req.body;

    if (!Number.isInteger(userId) || userId <= 0) {
      return res.status(400).json({
        error: 'Invalid user ID'
      });
    }

    if (!password) {
      return res.status(400).json({
        error: 'Password is required'
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        error: 'Password must be at least 8 characters'
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

    const passwordHash = hashPassword(password);

    await tursoQuery(
      'UPDATE users SET password_hash = ? WHERE id = ?',
      [passwordHash, userId]
    );

    res.json({
      success: true,
      message: 'Password changed successfully'
    });

  } catch (error) {
    console.error('User password update error:', error);

    res.status(500).json({
      error: 'Failed to change password',
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



// 💳 Customer Payments List
app.get('/api/customer-payments', async (req, res) => {
  try {
    const data = await tursoQuery(`
      SELECT
        p.id,
        p.customer,
        p.sale_id,
        p.description,
        p.amount,
        p.created_at,
        CASE
          WHEN EXISTS (
            SELECT 1
            FROM cash_transactions ct
            WHERE ct.type = 'customer_payment_correction'
              AND ct.description LIKE
                  'Correction for Customer Payment #' || p.id || ' -%'
          )
          THEN 1
          ELSE 0
        END AS corrected
      FROM customer_payments p
      ORDER BY p.id DESC
    `);

    const rows =
      data?.results?.[0]?.response?.result?.rows || [];

    const cols =
      data?.results?.[0]?.response?.result?.cols || [];

    const payments = rows.map(row => {
      const payment = {};

      cols.forEach((col, index) => {
        const cell = row[index];

        if (cell?.type === 'integer' || cell?.type === 'float') {
          payment[col.name] = Number(cell.value);
        } else if (cell?.type === 'null') {
          payment[col.name] = null;
        } else {
          payment[col.name] = cell?.value ?? null;
        }
      });

      return payment;
    });

    res.json(payments);

  } catch (error) {
    console.error('Customer payments list error:', error);

    res.status(500).json({
      error: 'Failed to load customer payments',
      details: error.message
    });
  }
});

// 💳 Customer Payment Correction
app.post('/api/customer-payments/:id/correct', async (req, res) => {
  try {
    const paymentId = Number(req.params.id);
    const { reason } = req.body;

    if (!Number.isInteger(paymentId) || paymentId <= 0) {
      return res.status(400).json({
        error: 'Valid customer payment ID is required'
      });
    }

    if (!reason || !String(reason).trim()) {
      return res.status(400).json({
        error: 'Correction reason is required'
      });
    }

    const paymentData = await tursoQuery(
      `SELECT id, customer, sale_id, description, amount, created_at
       FROM customer_payments
       WHERE id = ?`,
      [paymentId]
    );

    const rows =
      paymentData?.results?.[0]?.response?.result?.rows || [];

    const cols =
      paymentData?.results?.[0]?.response?.result?.cols || [];

    if (rows.length === 0) {
      return res.status(404).json({
        error: 'Customer payment not found'
      });
    }

    const payment = {};

    cols.forEach((col, index) => {
      const cell = rows[0][index];

      if (cell?.type === 'integer' || cell?.type === 'float') {
        payment[col.name] = Number(cell.value);
      } else if (cell?.type === 'null') {
        payment[col.name] = null;
      } else {
        payment[col.name] = cell?.value ?? null;
      }
    });

    const amount = Number(payment.amount);

    if (!(amount > 0)) {
      return res.status(400).json({
        error: 'Selected customer payment is invalid'
      });
    }

    const duplicateData = await tursoQuery(
      `SELECT id
       FROM cash_transactions
       WHERE type = 'customer_payment_correction'
         AND description LIKE ?
       LIMIT 1`,
      [`Correction for Customer Payment #${paymentId} -%`]
    );

    const duplicateRows =
      duplicateData?.results?.[0]?.response?.result?.rows || [];

    if (duplicateRows.length > 0) {
      return res.status(400).json({
        error: 'This customer payment has already been corrected'
      });
    }

    await tursoQuery(
      `INSERT INTO cash_transactions
       (type, description, amount)
       VALUES (?, ?, ?)`,
      [
        'customer_payment_correction',
        `Correction for Customer Payment #${paymentId} - ${String(reason).trim()}`,
        -Math.abs(amount)
      ]
    );

    res.json({
      success: true,
      message: 'Customer payment corrected successfully',
      original_payment_id: paymentId,
      correction_amount: amount
    });

  } catch (error) {
    console.error('Customer payment correction error:', error);

    res.status(500).json({
      error: 'Failed to correct customer payment',
      details: error.message
    });
  }
});

// 💵 Supplier Payment Correction
app.post('/api/supplier-payments/:id/correct', async (req, res) => {
  try {
    const paymentId = Number(req.params.id);
    const { reason } = req.body;

    if (!Number.isInteger(paymentId) || paymentId <= 0) {
      return res.status(400).json({
        error: 'Valid supplier payment ID is required'
      });
    }

    if (!reason || !String(reason).trim()) {
      return res.status(400).json({
        error: 'Correction reason is required'
      });
    }

    const paymentData = await tursoQuery(
      `SELECT id, supplier, purchase_id, description, amount, created_at
       FROM supplier_payments
       WHERE id = ?`,
      [paymentId]
    );

    const rows =
      paymentData?.results?.[0]?.response?.result?.rows || [];

    const cols =
      paymentData?.results?.[0]?.response?.result?.cols || [];

    if (rows.length === 0) {
      return res.status(404).json({
        error: 'Supplier payment not found'
      });
    }

    const payment = {};

    cols.forEach((col, index) => {
      const cell = rows[0][index];

      if (cell?.type === 'integer' || cell?.type === 'float') {
        payment[col.name] = Number(cell.value);
      } else if (cell?.type === 'null') {
        payment[col.name] = null;
      } else {
        payment[col.name] = cell?.value ?? null;
      }
    });

    const amount = Number(payment.amount);

    if (!(amount > 0)) {
      return res.status(400).json({
        error: 'Selected supplier payment is invalid'
      });
    }

    const duplicateData = await tursoQuery(
      `SELECT id
       FROM cash_transactions
       WHERE type = 'supplier_payment_correction'
         AND description LIKE ?
       LIMIT 1`,
      [`Correction for Supplier Payment #${paymentId} -%`]
    );

    const duplicateRows =
      duplicateData?.results?.[0]?.response?.result?.rows || [];

    if (duplicateRows.length > 0) {
      return res.status(400).json({
        error: 'This supplier payment has already been corrected'
      });
    }

    await tursoQuery(
      `INSERT INTO cash_transactions
       (type, description, amount)
       VALUES (?, ?, ?)`,
      [
        'supplier_payment_correction',
        `Correction for Supplier Payment #${paymentId} - ${String(reason).trim()}`,
        Math.abs(amount)
      ]
    );

    res.json({
      success: true,
      message: 'Supplier payment corrected successfully',
      original_payment_id: paymentId,
      correction_amount: amount
    });

  } catch (error) {
    console.error('Supplier payment correction error:', error);

    res.status(500).json({
      error: 'Failed to correct supplier payment',
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


// 👥 Customers
app.get('/api/create-repairs-table', async (req, res) => {
  try {
    await tursoQuery(`
      CREATE TABLE IF NOT EXISTS repairs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        customer_id INTEGER,
        device TEXT NOT NULL,
        problem TEXT NOT NULL,
        description TEXT,
        status TEXT NOT NULL DEFAULT 'active',
        estimated_cost REAL NOT NULL DEFAULT 0,
        paid_amount REAL NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        completed_at TEXT
      )
    `);

    res.json({
      success: true,
      message: 'Repairs table created successfully'
    });
  } catch (error) {
    console.error('Repairs table error:', error);

    res.status(500).json({
      error: 'Failed to create repairs table',
      details: error.message
    });
  }
});

app.patch('/api/repairs/:id/complete', async (req, res) => {
  try {
    const repairId = Number(req.params.id);

    if (!Number.isInteger(repairId) || repairId <= 0) {
      return res.status(400).json({
        error: 'Valid repair id is required'
      });
    }

    const existingData = await tursoQuery(
      `SELECT id, status
       FROM repairs
       WHERE id = ?`,
      [repairId]
    );

    const rows =
      existingData.results?.[0]?.response?.result?.rows || [];

    if (!rows.length) {
      return res.status(404).json({
        error: 'Repair not found'
      });
    }

    const currentStatus = rows[0]?.[1]?.value || '';

    if (currentStatus === 'completed') {
      return res.json({
        success: true,
        message: 'Repair is already completed'
      });
    }

    await tursoQuery(
      `UPDATE repairs
       SET status = 'completed',
           completed_at = CURRENT_TIMESTAMP
       WHERE id = ?`,
      [repairId]
    );

    res.json({
      success: true,
      message: 'Repair completed successfully',
      repair_id: repairId
    });

  } catch (error) {
    console.error('Complete repair error:', error);

    res.status(500).json({
      error: 'Failed to complete repair',
      details: error.message
    });
  }
});


app.delete('/api/repairs/:id', requireAuth, requirePermission('delete_repairs'), async (req, res) => {
  try {
    const repairId = Number(req.params.id);

    if (!Number.isInteger(repairId) || repairId <= 0) {
      return res.status(400).json({
        error: 'Valid repair id is required'
      });
    }

    const existingData = await tursoQuery(
      `SELECT id
       FROM repairs
       WHERE id = ?`,
      [repairId]
    );

    const rows =
      existingData.results?.[0]?.response?.result?.rows || [];

    if (!rows.length) {
      return res.status(404).json({
        error: 'Repair not found'
      });
    }

    await tursoQuery(
      `DELETE FROM repairs
       WHERE id = ?`,
      [repairId]
    );

    res.json({
      success: true,
      message: 'Repair deleted successfully',
      repair_id: repairId
    });

  } catch (error) {
    console.error('Delete repair error:', error);

    res.status(500).json({
      error: 'Failed to delete repair',
      details: error.message
    });
  }
});

app.get('/api/customer-repairs/:customerId', async (req, res) => {
  try {
    const customerId = Number(req.params.customerId);

    if (!Number.isInteger(customerId) || customerId <= 0) {
      return res.status(400).json({
        error: 'Valid customer id is required'
      });
    }

    const data = await tursoQuery(
      `SELECT
         id,
         customer_id,
         device,
         problem,
         description,
         status,
         estimated_cost,
         paid_amount,
         created_at,
         completed_at
       FROM repairs
       WHERE customer_id = ?
       ORDER BY id DESC`,
      [customerId]
    );

    res.json(data);
  } catch (error) {
    console.error('Customer repairs error:', error);

    res.status(500).json({
      error: 'Failed to load customer repairs',
      details: error.message
    });
  }
});

app.get('/api/repairs', async (req, res) => {
  try {
    const data = await tursoQuery(`
      SELECT
        repairs.id,
        repairs.customer_id,
        customers.name AS customer_name,
        repairs.device,
        repairs.problem,
        repairs.description,
        repairs.status,
        repairs.estimated_cost,
        repairs.paid_amount,
        repairs.created_at,
        repairs.completed_at
      FROM repairs
      LEFT JOIN customers
        ON customers.id = repairs.customer_id
      ORDER BY repairs.id DESC
    `);

    res.json(data);
  } catch (error) {
    console.error('Repairs error:', error);

    res.status(500).json({
      error: 'Failed to load repairs',
      details: error.message
    });
  }
});

app.post('/api/repairs', async (req, res) => {
  try {
    const {
      customer_id,
      device,
      problem,
      description = '',
      status = 'active',
      estimated_cost = 0,
      paid_amount = 0
    } = req.body;

    const customerId = Number(customer_id);
    const deviceName = String(device || '').trim();
    const problemText = String(problem || '').trim();
    const repairStatus = String(status || 'active').trim();

    if (!Number.isInteger(customerId) || customerId <= 0) {
      return res.status(400).json({
        error: 'Valid customer_id is required'
      });
    }

    if (!deviceName) {
      return res.status(400).json({
        error: 'Device is required'
      });
    }

    if (!problemText) {
      return res.status(400).json({
        error: 'Problem is required'
      });
    }

    const customerData = await tursoQuery(
      `SELECT id, name
       FROM customers
       WHERE id = ?`,
      [customerId]
    );

    const customerRows =
      customerData.results?.[0]?.response?.result?.rows || [];

    if (!customerRows.length) {
      return res.status(404).json({
        error: 'Customer not found'
      });
    }

    const estimatedCost = Number(estimated_cost) || 0;
    const paidAmount = Number(paid_amount) || 0;

    if (estimatedCost < 0 || paidAmount < 0) {
      return res.status(400).json({
        error: 'Amounts cannot be negative'
      });
    }

    if (paidAmount > estimatedCost) {
      return res.status(400).json({
        error: 'Paid amount cannot exceed estimated cost'
      });
    }

    const data = await tursoQuery(
      `INSERT INTO repairs
       (
         customer_id,
         device,
         problem,
         description,
         status,
         estimated_cost,
         paid_amount
       )
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        customerId,
        deviceName,
        problemText,
        String(description || '').trim(),
        repairStatus,
        estimatedCost,
        paidAmount
      ]
    );

    res.json({
      success: true,
      message: 'Repair created successfully',
      repair_id:
        data.results?.[0]?.response?.result?.last_insert_rowid || null
    });
  } catch (error) {
    console.error('Create repair error:', error);

    res.status(500).json({
      error: 'Failed to create repair',
      details: error.message
    });
  }
});

app.get('/api/create-customers-table', async (req, res) => {
  try {
    await tursoQuery(`
      CREATE TABLE IF NOT EXISTS customers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        phone TEXT,
        address TEXT,
        notes TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `);

    res.json({
      success: true,
      message: 'Customers table created successfully'
    });
  } catch (error) {
    console.error('Customers table error:', error);

    res.status(500).json({
      error: 'Failed to create customers table',
      details: error.message
    });
  }
});

app.get('/api/customers', async (req, res) => {
  try {
    const data = await tursoQuery(`
      SELECT id, name, phone, address, notes, created_at
      FROM customers
      ORDER BY id DESC
    `);

    res.json(data);
  } catch (error) {
    console.error('Customers error:', error);

    res.status(500).json({
      error: 'Failed to load customers',
      details: error.message
    });
  }
});

app.post('/api/customers', async (req, res) => {
  try {
    const {
      name,
      phone = '',
      address = '',
      notes = ''
    } = req.body;

    const customerName = String(name || '').trim();

    if (!customerName) {
      return res.status(400).json({
        error: 'Customer name is required'
      });
    }

    const data = await tursoQuery(
      `INSERT INTO customers
       (name, phone, address, notes)
       VALUES (?, ?, ?, ?)`,
      [
        customerName,
        String(phone || '').trim(),
        String(address || '').trim(),
        String(notes || '').trim()
      ]
    );

    res.json({
      success: true,
      message: 'Customer created successfully',
      customer: {
        id: data.results?.[0]?.response?.result?.last_insert_rowid || null,
        name: customerName,
        phone: String(phone || '').trim(),
        address: String(address || '').trim(),
        notes: String(notes || '').trim()
      }
    });
  } catch (error) {
    console.error('Create customer error:', error);

    res.status(500).json({
      error: 'Failed to create customer',
      details: error.message
    });
  }
});

app.get('/api/customer-sales/:customer', async (req, res) => {
  try {
    const customerName = decodeURIComponent(req.params.customer || '').trim();

    if (!customerName) {
      return res.status(400).json({
        error: 'Customer name is required'
      });
    }

    const data = await tursoQuery(
      `SELECT
         sales.id,
         sales.product_id,
         products.name AS product_name,
         sales.quantity,
         sales.unit_price,
         sales.total,
         sales.payment_type,
         sales.created_at
       FROM sales
       LEFT JOIN products ON products.id = sales.product_id
       WHERE sales.customer = ?
       ORDER BY sales.id DESC`,
      [customerName]
    );

    res.json(data);

  } catch (error) {
    console.error('Customer sales error:', error);

    res.status(500).json({
      error: 'Failed to load customer sales',
      details: error.message
    });
  }
});

app.get('/api/customers/:id', async (req, res) => {
  try {
    const customerId = Number(req.params.id);

    if (!Number.isInteger(customerId) || customerId <= 0) {
      return res.status(400).json({
        error: 'Valid customer id is required'
      });
    }

    const data = await tursoQuery(
      `SELECT id, name, phone, address, notes, created_at
       FROM customers
       WHERE id = ?`,
      [customerId]
    );

    const rows =
      data.results?.[0]?.response?.result?.rows || [];

    if (!rows.length) {
      return res.status(404).json({
        error: 'Customer not found'
      });
    }

    const row = rows[0];

    res.json({
      success: true,
      customer: {
        id: row[0]?.value,
        name: row[1]?.value || '',
        phone: row[2]?.value || '',
        address: row[3]?.value || '',
        notes: row[4]?.value || '',
        created_at: row[5]?.value || ''
      }
    });
  } catch (error) {
    console.error('Customer details error:', error);

    res.status(500).json({
      error: 'Failed to load customer',
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
app.get('/api/migrate-users-department', async (req, res) => {
  try {
    await tursoQuery(`
      ALTER TABLE users
      ADD COLUMN department TEXT NOT NULL DEFAULT 'general'
    `);

    res.json({
      success: true,
      message: 'User department field added successfully'
    });
  } catch (error) {
    console.error('Department migration error:', error);

    res.status(500).json({
      error: error.message
    });
  }
});

app.get('/api/create-user-permissions-table', async (req, res) => {
  try {
    await tursoQuery(`
      CREATE TABLE IF NOT EXISTS user_permissions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        permission TEXT NOT NULL,
        UNIQUE(user_id, permission)
      )
    `);

    res.json({
      success: true,
      message: 'User permissions table created successfully'
    });
  } catch (error) {
    console.error('User permissions table error:', error);

    res.status(500).json({
      error: error.message
    });
  }
});


app.get('/api/users/:id/permissions', requireAuth, requireAdmin, async (req, res) => {
  try {
    const userId = Number(req.params.id);

    if (!Number.isInteger(userId) || userId <= 0) {
      return res.status(400).json({
        error: 'Invalid user ID'
      });
    }

    const data = await tursoQuery(
      `SELECT permission
       FROM user_permissions
       WHERE user_id = ?
       ORDER BY permission`,
      [userId]
    );

    const rows =
      data.results?.[0]?.response?.result?.rows || [];

    const permissions = rows
      .map(row => row[0]?.value)
      .filter(Boolean);

    res.json({
      success: true,
      user_id: userId,
      permissions
    });

  } catch (error) {
    console.error('Get user permissions error:', error);

    res.status(500).json({
      error: 'Failed to load user permissions',
      details: error.message
    });
  }
});

app.put('/api/users/:id/permissions', requireAuth, requireAdmin, async (req, res) => {
  try {
    const userId = Number(req.params.id);
    const permissions = Array.isArray(req.body.permissions)
      ? req.body.permissions
      : [];

    if (!Number.isInteger(userId) || userId <= 0) {
      return res.status(400).json({
        error: 'Invalid user ID'
      });
    }

    const allowedPermissions = [
      'delete_stock',
      'delete_sales',
      'delete_repairs'
    ];

    const invalidPermissions = permissions.filter(
      permission => !allowedPermissions.includes(permission)
    );

    if (invalidPermissions.length) {
      return res.status(400).json({
        error: 'Invalid permission',
        permissions: invalidPermissions
      });
    }

    const uniquePermissions = [...new Set(permissions)];

    const userData = await tursoQuery(
      'SELECT id, role FROM users WHERE id = ? LIMIT 1',
      [userId]
    );

    const userRows =
      userData.results?.[0]?.response?.result?.rows || [];

    if (!userRows.length) {
      return res.status(404).json({
        error: 'User not found'
      });
    }

    await tursoQuery(
      'DELETE FROM user_permissions WHERE user_id = ?',
      [userId]
    );

    for (const permission of uniquePermissions) {
      await tursoQuery(
        `INSERT INTO user_permissions
         (user_id, permission)
         VALUES (?, ?)`,
        [userId, permission]
      );
    }

    res.json({
      success: true,
      message: 'User permissions updated successfully',
      user_id: userId,
      permissions: uniquePermissions
    });

  } catch (error) {
    console.error('Update user permissions error:', error);

    res.status(500).json({
      error: 'Failed to update user permissions',
      details: error.message
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

app.delete('/api/products/:id', requireAuth, requirePermission('delete_stock'), async (req, res) => {
  try {
    const productId = Number(req.params.id);

    if (!Number.isInteger(productId) || productId <= 0) {
      return res.status(400).json({
        error: 'Valid product id is required'
      });
    }

    const productData = await tursoQuery(
      'SELECT id, name FROM products WHERE id = ? LIMIT 1',
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

    const salesData = await tursoQuery(
      'SELECT id FROM sales WHERE product_id = ? LIMIT 1',
      [productId]
    );

    const salesRows =
      salesData.results?.[0]?.response?.result?.rows || [];

    if (salesRows.length) {
      return res.status(409).json({
        error: 'Cannot delete product because sales history exists'
      });
    }

    const purchasesData = await tursoQuery(
      'SELECT id FROM purchases WHERE product_id = ? LIMIT 1',
      [productId]
    );

    const purchaseRows =
      purchasesData.results?.[0]?.response?.result?.rows || [];

    if (purchaseRows.length) {
      return res.status(409).json({
        error: 'Cannot delete product because purchase history exists'
      });
    }

    const movementsData = await tursoQuery(
      'SELECT id FROM stock_movements WHERE product_id = ? LIMIT 1',
      [productId]
    );

    const movementRows =
      movementsData.results?.[0]?.response?.result?.rows || [];

    if (movementRows.length) {
      return res.status(409).json({
        error: 'Cannot delete product because stock movement history exists'
      });
    }

    await tursoQuery(
      'DELETE FROM products WHERE id = ?',
      [productId]
    );

    res.json({
      success: true,
      message: 'Product deleted successfully',
      product: productName
    });

  } catch (error) {
    console.error('Delete product error:', error);

    res.status(500).json({
      error: 'Failed to delete product',
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

    const newProductId =
      data.results?.[0]?.response?.result?.last_insert_rowid || null;

    const openingQty = Number(stock) || 0;

    if (newProductId && openingQty > 0) {
      await tursoQuery(
        `INSERT INTO stock_movements
         (product_id, type, quantity, stock_before, stock_after, reference_id, note)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [
          newProductId,
          'opening',
          openingQty,
          0,
          openingQty,
          null,
          'Opening Stock'
        ]
      );
    }
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


// 🔧 Expense Correction
app.post('/api/expenses/:id/correct', async (req, res) => {
  try {
    const expenseId = Number(req.params.id);
    const { reason } = req.body;

    if (!Number.isInteger(expenseId) || expenseId <= 0) {
      return res.status(400).json({
        error: 'Valid expense ID is required'
      });
    }

    if (!reason || !String(reason).trim()) {
      return res.status(400).json({
        error: 'Correction reason is required'
      });
    }

    const result = await tursoQuery(
      `SELECT id, type, description, amount, created_at
       FROM cash_transactions
       WHERE id = ? AND type = 'expense'`,
      [expenseId]
    );

    const rows =
      result?.results?.[0]?.response?.result?.rows || [];

    const cols =
      result?.results?.[0]?.response?.result?.cols || [];

    if (rows.length === 0) {
      return res.status(404).json({
        error: 'Expense not found'
      });
    }

    const expense = {};

    cols.forEach((col, index) => {
      const cell = rows[0][index];

      if (cell?.type === 'integer') {
        expense[col.name] = Number(cell.value);
      } else if (cell?.type === 'float') {
        expense[col.name] = Number(cell.value);
      } else if (cell?.type === 'null') {
        expense[col.name] = null;
      } else {
        expense[col.name] = cell?.value ?? null;
      }
    });
    const amount = Number(expense.amount);

    if (!(amount < 0)) {
      return res.status(400).json({
        error: 'Selected transaction is not a valid expense'
      });
    }

    const correctionAmount = Math.abs(amount);

    const data = await tursoQuery(
      `INSERT INTO cash_transactions
       (type, description, amount)
       VALUES (?, ?, ?)`,
      [
        'expense_correction',
        `Correction for Expense #${expenseId} - ${String(reason).trim()}`,
        correctionAmount
      ]
    );

    res.json({
      success: true,
      message: 'Expense corrected successfully',
      original_expense_id: expenseId,
      correction_amount: correctionAmount,
      data
    });

  } catch (error) {
    console.error('Turso error:', error);

    res.status(500).json({
      error: 'Failed to correct expense',
      details: error.message
    });
  }
});

// 💰 Income Correction
app.post('/api/income/:id/correct', async (req, res) => {
  try {
    const incomeId = Number(req.params.id);
    const { reason } = req.body;

    if (!Number.isInteger(incomeId) || incomeId <= 0) {
      return res.status(400).json({
        error: 'Valid income ID is required'
      });
    }

    if (!reason || !String(reason).trim()) {
      return res.status(400).json({
        error: 'Correction reason is required'
      });
    }

    const result = await tursoQuery(
      `SELECT id, type, description, amount, created_at
       FROM cash_transactions
       WHERE id = ? AND type = 'income'`,
      [incomeId]
    );

    const rows =
      result?.results?.[0]?.response?.result?.rows || [];

    const cols =
      result?.results?.[0]?.response?.result?.cols || [];

    if (rows.length === 0) {
      return res.status(404).json({
        error: 'Income not found'
      });
    }

    const income = {};

    cols.forEach((col, index) => {
      const cell = rows[0][index];

      if (cell?.type === 'integer') {
        income[col.name] = Number(cell.value);
      } else if (cell?.type === 'float') {
        income[col.name] = Number(cell.value);
      } else if (cell?.type === 'null') {
        income[col.name] = null;
      } else {
        income[col.name] = cell?.value ?? null;
      }
    });

    const amount = Number(income.amount);

    if (!(amount > 0)) {
      return res.status(400).json({
        error: 'Selected transaction is not a valid income'
      });
    }

    const correctionAmount = -Math.abs(amount);

    const data = await tursoQuery(
      `INSERT INTO cash_transactions
       (type, description, amount)
       VALUES (?, ?, ?)`,
      [
        'income_correction',
        `Correction for Income #${incomeId} - ${String(reason).trim()}`,
        correctionAmount
      ]
    );

    res.json({
      success: true,
      message: 'Income corrected successfully',
      original_income_id: incomeId,
      correction_amount: Math.abs(amount),
      data
    });

  } catch (error) {
    console.error('Turso error:', error);

    res.status(500).json({
      error: 'Failed to correct income',
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
// 🔄 Add payment_type to existing purchases table
app.get('/api/upgrade-purchases-payment-type', async (req, res) => {
  try {
    try {
      await tursoQuery(`
        ALTER TABLE purchases
        ADD COLUMN payment_type TEXT NOT NULL DEFAULT 'cash'
      `);
    } catch (error) {
      if (!String(error.message).toLowerCase().includes('duplicate column')) {
        throw error;
      }
    }

    res.json({
      success: true,
      message: 'Purchases payment_type migration completed successfully'
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to migrate purchases payment_type',
      details: error.message
    });
  }
});


// 📋 Purchase History
app.get('/api/purchases', async (req, res) => {
  try {
    const data = await tursoQuery(`
      SELECT
        purchases.id,
        purchases.product_id,
        products.name AS product_name,
        products.unit,
        purchases.quantity,
        purchases.unit_price,
        purchases.supplier,
        purchases.total,
        purchases.payment_type,
        purchases.created_at,
CASE
  WHEN EXISTS (
    SELECT 1
    FROM stock_movements sm
    WHERE sm.type = 'purchase_correction'
      AND sm.reference_id = purchases.id
  )
  THEN 1
  ELSE 0
END AS corrected
      FROM purchases
      JOIN products
        ON purchases.product_id = products.id
      ORDER BY purchases.id DESC
    `);

    const rows =
      data.results?.[0]?.response?.result?.rows || [];

    const purchases = rows.map(row => ({
      id: Number(row[0].value),
      product_id: Number(row[1].value),
      product_name: row[2].value,
      unit: row[3].value,
      quantity: Number(row[4].value),
      unit_price: Number(row[5].value),
      supplier: row[6].value || '',
      total: Number(row[7].value),
      payment_type: row[8].value,
      
     created_at: row[9].value,
     corrected: Number(row[10]?.value || 0) === 1
    }));

    res.json({
      success: true,
      count: purchases.length,
      purchases
    });

  } catch (error) {
    console.error('Turso error:', error);

    res.status(500).json({
      error: 'Failed to load purchase history',
      details: error.message
    });
  }
});


// 📦 Purchase Batch Tracking
app.get('/api/create-purchase-batches-table', async (req, res) => {
  try {
    await tursoQuery(`
      CREATE TABLE IF NOT EXISTS purchase_batches (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        purchase_id INTEGER NOT NULL,
        product_id INTEGER NOT NULL,
        quantity REAL NOT NULL,
        remaining_quantity REAL NOT NULL,
        unit_cost REAL NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `);

    res.json({
      success: true,
      message: 'Purchase batches table created successfully'
    });

  } catch (error) {
    console.error('Purchase batches table error:', error);

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
      supplier,
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

    if (!['cash', 'credit'].includes(payment_type)) {
      return res.status(400).json({
        error: 'Invalid payment_type'
      });
    }

    if (payment_type === 'credit' && (!supplier || !supplier.trim())) {
      return res.status(400).json({
        error: 'Supplier name is required for credit purchase'
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
    const supplierName = (supplier || '').trim();
    const total = qty * price;

    const purchase = await tursoQuery(
      `INSERT INTO purchases
       (product_id, quantity, unit_price, supplier, total, payment_type)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [
        productId,
        qty,
        price,
        supplierName,
        total,
        payment_type
      ]
    );

    const purchaseId =
      purchase.results?.[0]?.response?.result?.last_insert_rowid || null;

    if (purchaseId) {
      await tursoQuery(
        `INSERT INTO purchase_batches
         (purchase_id, product_id, quantity, remaining_quantity, unit_cost)
         VALUES (?, ?, ?, ?, ?)`,
        [
          purchaseId,
          productId,
          qty,
          qty,
          price
        ]
      );
    }

const stockData = await tursoQuery(
  'SELECT stock FROM products WHERE id = ?',
  [productId]
);

const stockBefore =
  Number(stockData.results?.[0]?.response?.result?.rows?.[0]?.[0]?.value) || 0;

const stockAfter = stockBefore + qty;
    await tursoQuery(
      'UPDATE products SET stock = stock + ? WHERE id = ?',
      [qty, productId]
    );


await tursoQuery(
  `INSERT INTO stock_movements
   (product_id, type, quantity, stock_before, stock_after, reference_id, note)
   VALUES (?, ?, ?, ?, ?, ?, ?)`,
  [
    productId,
    'purchase',
    qty,
    stockBefore,
    stockAfter,
    purchaseId,
    `Purchase - ${productName}`
  ]
);
    if (payment_type === 'cash') {
      await tursoQuery(
        `INSERT INTO cash_transactions
         (type, description, amount)
         VALUES (?, ?, ?)`,
        [
          'purchase',
          `Purchase - ${productName}${supplierName ? ` - ${supplierName}` : ''}`,
          -total
        ]
      );
    } else {
      await tursoQuery(
        `INSERT INTO supplier_debts
         (purchase_id, supplier, description, amount)
         VALUES (?, ?, ?, ?)`,
        [
          purchaseId,
          supplierName,
          `Credit Purchase - ${productName}`,
          total
        ]
      );
    }

    res.json({
      success: true,
      message: 'Purchase registered successfully',
      total,
      payment_type,
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


// 💵 Create Supplier Payments Table
app.get('/api/create-supplier-payments-table', async (req, res) => {
  try {
    await tursoQuery(`
      CREATE TABLE IF NOT EXISTS supplier_payments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        supplier TEXT NOT NULL,
        purchase_id INTEGER,
        description TEXT NOT NULL,
        amount REAL NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `);

    res.json({
      success: true,
      message: 'Supplier payments table created successfully'
    });
  } catch (error) {
    console.error('Turso error:', error);

    res.status(500).json({
      error: 'Failed to create supplier payments table',
      details: error.message
    });
  }
});

// 💳 Supplier Debts List
app.get('/api/supplier-debts', async (req, res) => {
  try {
    const data = await tursoQuery(`
      SELECT
        id,
        purchase_id,
        supplier,
        description,
        amount,
        created_at
      FROM supplier_debts
      ORDER BY id DESC
    `);

    const rows =
      data.results?.[0]?.response?.result?.rows || [];

    const debts = rows.map(row => ({
      id: Number(row[0].value),
      purchase_id: row[1].value === null ? null : Number(row[1].value),
      supplier: row[2].value,
      description: row[3].value,
      amount: Number(row[4].value),
      created_at: row[5].value,
      corrected: Number(row[6]?.value || 0) === 1
    }));

    const total = debts.reduce((sum, debt) => sum + debt.amount, 0);

    res.json({
      success: true,
      total,
      count: debts.length,
      debts
    });

  } catch (error) {
    console.error('Turso error:', error);

    res.status(500).json({
      error: 'Failed to load supplier debts',
      details: error.message
    });
  }
});

// 💳 Create Supplier Debts Table

// 🗑️ Delete Purchase
app.delete(
  '/api/purchases/:id',
  requireAuth,
  requirePermission('delete_stock'),
  async (req, res) => {
    try {
      const purchaseId = Number(req.params.id);

      if (!Number.isInteger(purchaseId) || purchaseId <= 0) {
        return res.status(400).json({
          error: 'Invalid purchase ID'
        });
      }

      // 1. Find the purchase.
      const purchaseData = await tursoQuery(
        `SELECT
          id,
          product_id,
          quantity,
          unit_price,
          supplier,
          total,
          payment_type
         FROM purchases
         WHERE id = ?
         LIMIT 1`,
        [purchaseId]
      );

      const purchaseRows =
        purchaseData.results?.[0]?.response?.result?.rows || [];

      if (!purchaseRows.length) {
        return res.status(404).json({
          error: 'Purchase not found'
        });
      }

      const purchase = purchaseRows[0];

      const productId = Number(purchase[1]?.value);
      const quantity = Number(purchase[2]?.value || 0);
      const total = Number(purchase[5]?.value || 0);
      const supplier = purchase[4]?.value || '';
      const paymentType = purchase[6]?.value || 'cash';

      if (
        !Number.isInteger(productId) ||
        productId <= 0 ||
        !Number.isFinite(quantity) ||
        quantity <= 0
      ) {
        return res.status(400).json({
          error: 'Invalid purchase data'
        });
      }

      // 2. Check FIFO allocation usage.
      const allocationData = await tursoQuery(
        `SELECT
          COALESCE(SUM(quantity), 0)
         FROM sale_purchase_allocations
         WHERE purchase_id = ?`,
        [purchaseId]
      );

      const allocationRows =
        allocationData.results?.[0]?.response?.result?.rows || [];

      const allocatedQuantity =
        Number(allocationRows[0]?.[0]?.value || 0);

      if (allocatedQuantity > 0) {
        return res.status(409).json({
          error: 'Cannot delete purchase because some of this purchase has already been sold',
          purchase_id: purchaseId,
          purchased_quantity: quantity,
          sold_quantity: allocatedQuantity,
          remaining_quantity: Math.max(quantity - allocatedQuantity, 0)
        });
      }

      // 3. Find the purchase batch.
      const batchData = await tursoQuery(
        `SELECT
          id,
          quantity,
          remaining_quantity,
          unit_cost
         FROM purchase_batches
         WHERE purchase_id = ?
           AND product_id = ?
         ORDER BY id ASC`,
        [purchaseId, productId]
      );

      const batchRows =
        batchData.results?.[0]?.response?.result?.rows || [];

      let batchQuantity = 0;
      let batchRemaining = 0;

      if (batchRows.length) {
        batchQuantity = Number(batchRows[0][1]?.value || 0);
        batchRemaining = Number(batchRows[0][2]?.value || 0);

        // If there is no sale allocation, the full batch should remain.
        if (Math.abs(batchRemaining - batchQuantity) > 0.000001) {
          return res.status(409).json({
            error: 'Cannot delete purchase because its batch has already been partially consumed',
            purchase_id: purchaseId,
            batch_quantity: batchQuantity,
            batch_remaining: batchRemaining
          });
        }
      }

      // 4. Check current product stock.
      const productData = await tursoQuery(
        `SELECT
          id,
          name,
          stock
         FROM products
         WHERE id = ?
         LIMIT 1`,
        [productId]
      );

      const productRows =
        productData.results?.[0]?.response?.result?.rows || [];

      if (!productRows.length) {
        return res.status(404).json({
          error: 'Product for this purchase was not found'
        });
      }

      const productName = productRows[0][1]?.value || '';
      const currentStock = Number(productRows[0][2]?.value || 0);

      if (quantity > currentStock) {
        return res.status(409).json({
          error: 'Cannot delete purchase because current stock is lower than the purchased quantity',
          purchase_id: purchaseId,
          purchased_quantity: quantity,
          current_stock: currentStock
        });
      }

      // 5. Reduce product stock.
      const newStock = currentStock - quantity;

      await tursoQuery(
        `UPDATE products
         SET stock = ?
         WHERE id = ?`,
        [newStock, productId]
      );

      // 6. Record stock reversal.
      await tursoQuery(
        `INSERT INTO stock_movements
         (product_id, type, quantity, stock_before, stock_after, reference_id, note)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [
          productId,
          'purchase_reversal',
          -quantity,
          currentStock,
          newStock,
          purchaseId,
          `Purchase #${purchaseId} deleted - ${productName}`
        ]
      );

      // 7. Reverse cash purchase.
      if (paymentType === 'cash') {
        await tursoQuery(
          `INSERT INTO cash_transactions
           (type, description, amount)
           VALUES (?, ?, ?)`,
          [
            'purchase_reversal',
            `Deleted Purchase #${purchaseId} - ${productName}${supplier ? ` - ${supplier}` : ''}`,
            total
          ]
        );
      }

      // 8. Reverse credit supplier debt.
      if (paymentType === 'credit') {
        await tursoQuery(
          `DELETE FROM supplier_debts
           WHERE purchase_id = ?`,
          [purchaseId]
        );
      }

      // 9. Delete purchase batch.
      await tursoQuery(
        `DELETE FROM purchase_batches
         WHERE purchase_id = ?`,
        [purchaseId]
      );

      // 10. Delete purchase.
      await tursoQuery(
        `DELETE FROM purchases
         WHERE id = ?`,
        [purchaseId]
      );

      res.json({
        success: true,
        message: 'Purchase deleted and reversed successfully',
        purchase_id: purchaseId,
        restored_cash: paymentType === 'cash' ? total : 0,
        reversed_supplier_debt: paymentType === 'credit',
        restored_stock: -quantity,
        new_stock: newStock
      });

    } catch (error) {
      console.error('Delete purchase error:', error);

      res.status(500).json({
        error: 'Failed to delete purchase',
        details: error.message
      });
    }
  }
);

// ✏️ Purchase Correction
app.post('/api/purchases/:id/correct', requireAuth, async (req, res) => {
  try {
    const purchaseId = Number(req.params.id);
    const { reason } = req.body;

    if (!Number.isInteger(purchaseId) || purchaseId <= 0) {
      return res.status(400).json({
        error: 'Invalid purchase ID'
      });
    }

    if (!reason || !String(reason).trim()) {
      return res.status(400).json({
        error: 'Correction reason is required'
      });
    }

    // 1. Find original purchase
    const purchaseData = await tursoQuery(
      `SELECT
        id,
        product_id,
        quantity,
        unit_price,
        supplier,
        total,
        payment_type
       FROM purchases
       WHERE id = ?
       LIMIT 1`,
      [purchaseId]
    );

    const purchaseRows =
      purchaseData.results?.[0]?.response?.result?.rows || [];

    if (!purchaseRows.length) {
      return res.status(404).json({
        error: 'Purchase not found'
      });
    }

    const purchase = purchaseRows[0];

    const productId = Number(purchase[1]?.value);
    const quantity = Number(purchase[2]?.value || 0);
    const supplier = purchase[4]?.value || '';
    const total = Number(purchase[5]?.value || 0);
    const paymentType = purchase[6]?.value || 'cash';

    if (
      !Number.isInteger(productId) ||
      productId <= 0 ||
      !Number.isFinite(quantity) ||
      quantity <= 0 ||
      !Number.isFinite(total) ||
      total < 0
    ) {
      return res.status(400).json({
        error: 'Invalid purchase data'
      });
    }

    // 2. Prevent duplicate correction
    const existingCorrection = await tursoQuery(
      `SELECT id
       FROM stock_movements
       WHERE type = 'purchase_correction'
         AND reference_id = ?
       LIMIT 1`,
      [purchaseId]
    );

    const correctionRows =
      existingCorrection.results?.[0]?.response?.result?.rows || [];

    if (correctionRows.length) {
      return res.status(409).json({
        error: 'This purchase has already been corrected'
      });
    }

    // 3. Check whether this purchase was already used in a sale
    const allocationData = await tursoQuery(
      `SELECT
        COALESCE(SUM(quantity), 0)
       FROM sale_purchase_allocations
       WHERE purchase_id = ?`,
      [purchaseId]
    );

    const allocationRows =
      allocationData.results?.[0]?.response?.result?.rows || [];

    const allocatedQuantity =
      Number(allocationRows[0]?.[0]?.value || 0);

    if (allocatedQuantity > 0) {
      return res.status(409).json({
        error: 'Cannot correct purchase because some of it has already been sold',
        purchase_id: purchaseId,
        purchased_quantity: quantity,
        sold_quantity: allocatedQuantity,
        remaining_quantity: Math.max(
          quantity - allocatedQuantity,
          0
        )
      });
    }

    // 4. Check purchase batch
    const batchData = await tursoQuery(
      `SELECT
        id,
        quantity,
        remaining_quantity
       FROM purchase_batches
       WHERE purchase_id = ?
         AND product_id = ?
       ORDER BY id ASC`,
      [purchaseId, productId]
    );

    const batchRows =
      batchData.results?.[0]?.response?.result?.rows || [];

    if (batchRows.length) {
      const batchQuantity =
        Number(batchRows[0][1]?.value || 0);

      const batchRemaining =
        Number(batchRows[0][2]?.value || 0);

      if (
        Math.abs(batchRemaining - batchQuantity) >
        0.000001
      ) {
        return res.status(409).json({
          error: 'Cannot correct purchase because its FIFO batch has already been partially consumed',
          purchase_id: purchaseId,
          batch_quantity: batchQuantity,
          batch_remaining: batchRemaining
        });
      }
    }

    // 5. Check current product stock
    const productData = await tursoQuery(
      `SELECT
        id,
        name,
        stock
       FROM products
       WHERE id = ?
       LIMIT 1`,
      [productId]
    );

    const productRows =
      productData.results?.[0]?.response?.result?.rows || [];

    if (!productRows.length) {
      return res.status(404).json({
        error: 'Product for this purchase was not found'
      });
    }

    const productName =
      productRows[0][1]?.value || '';

    const currentStock =
      Number(productRows[0][2]?.value || 0);

    if (quantity > currentStock) {
      return res.status(409).json({
        error: 'Cannot correct purchase because current stock is lower than the purchased quantity',
        purchase_id: purchaseId,
        purchased_quantity: quantity,
        current_stock: currentStock
      });
    }

    // 6. Reduce stock
    const newStock = currentStock - quantity;

    await tursoQuery(
      `UPDATE products
       SET stock = ?
       WHERE id = ?`,
      [newStock, productId]
    );

    // 7. Mark FIFO batch as fully reversed
    await tursoQuery(
      `UPDATE purchase_batches
       SET remaining_quantity = 0
       WHERE purchase_id = ?
         AND product_id = ?`,
      [purchaseId, productId]
    );

    // 8. Record stock correction
    await tursoQuery(
      `INSERT INTO stock_movements
       (product_id, type, quantity, stock_before, stock_after, reference_id, note)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        productId,
        'purchase_correction',
        -quantity,
        currentStock,
        newStock,
        purchaseId,
        `Purchase #${purchaseId} corrected - ${String(reason).trim()}`
      ]
    );

    // 9. Reverse cash or supplier debt
    if (paymentType === 'cash') {
      await tursoQuery(
        `INSERT INTO cash_transactions
         (type, description, amount)
         VALUES (?, ?, ?)`,
        [
          'purchase_correction',
          `Correction for Purchase #${purchaseId} - ${productName}${supplier ? ` - ${supplier}` : ''}`,
          total
        ]
      );
    }

    if (paymentType === 'credit') {
      await tursoQuery(
        `INSERT INTO supplier_debts
         (purchase_id, supplier, description, amount)
         VALUES (?, ?, ?, ?)`,
        [
          purchaseId,
          supplier || 'Unknown Supplier',
          `Purchase Correction #${purchaseId} - ${String(reason).trim()}`,
          -total
        ]
      );
    }

    res.json({
      success: true,
      message: 'Purchase corrected successfully',
      purchase_id: purchaseId,
      restored_stock: quantity,
      correction_amount: total,
      payment_type: paymentType
    });

  } catch (error) {
    console.error('Purchase correction error:', error);

    res.status(500).json({
      error: 'Failed to correct purchase',
      details: error.message
    });
  }
});
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

// 💵 Supplier Payments
app.get('/api/supplier-payments', async (req, res) => {
  try {
    const supplier = String(req.query.supplier || '').trim();

    const data = await tursoQuery(`
      SELECT
        p.id,
        p.supplier,
        p.purchase_id,
        p.description,
        p.amount,
        p.created_at,
        CASE
          WHEN EXISTS (
            SELECT 1
            FROM cash_transactions ct
            WHERE ct.type = 'supplier_payment_correction'
              AND ct.description LIKE
                  'Correction for Supplier Payment #' || p.id || ' -%'
          )
          THEN 1
          ELSE 0
        END AS corrected
      FROM supplier_payments p
      ${supplier ? 'WHERE p.supplier = ?' : ''}
      ORDER BY p.id DESC
    `, supplier ? [supplier] : []);

    const rows = data.results?.[0]?.response?.result?.rows || [];

    const payments = rows.map(row => ({
      id: Number(row[0].value),
      supplier: row[1].value,
      purchase_id: row[2].value === null ? null : Number(row[2].value),
      description: row[3].value,
      amount: Number(row[4].value),
      created_at: row[5].value,
      corrected: Number(row[6]?.value || 0) === 1
    }));

    const total = payments.reduce((sum, payment) => sum + payment.amount, 0);

    res.json({
      success: true,
      total,
      count: payments.length,
      payments
    });
  } catch (error) {
    console.error('Turso error:', error);

    res.status(500).json({
      error: 'Failed to load supplier payments',
      details: error.message
    });
  }
});

// 💵 Register Supplier Payment
app.post('/api/supplier-payments', async (req, res) => {
  try {
    const {
      supplier,
      purchase_id = null,
      description = 'Supplier Debt Payment',
      amount
    } = req.body;

    const paymentAmount = Number(amount);

    if (!supplier || !supplier.trim()) {
      return res.status(400).json({
        error: 'Supplier name is required'
      });
    }

    if (!Number.isFinite(paymentAmount) || paymentAmount <= 0) {
      return res.status(400).json({
        error: 'Payment amount must be greater than 0'
      });
    }

    const debtData = await tursoQuery(
      `SELECT COALESCE(SUM(amount), 0)
       FROM supplier_debts
       WHERE supplier = ?`,
      [supplier.trim()]
    );

    const debtRows =
      debtData.results?.[0]?.response?.result?.rows || [];

    const totalDebt = Number(debtRows[0]?.[0]?.value || 0);

    const paymentData = await tursoQuery(
      `SELECT COALESCE(SUM(amount), 0)
       FROM supplier_payments
       WHERE supplier = ?`,
      [supplier.trim()]
    );

    const paymentRows =
      paymentData.results?.[0]?.response?.result?.rows || [];

    const totalPaid = Number(paymentRows[0]?.[0]?.value || 0);
    const outstanding = Math.max(totalDebt - totalPaid, 0);

    if (paymentAmount > outstanding) {
      return res.status(400).json({
        error: `Payment exceeds outstanding supplier debt. Outstanding: ${outstanding}`
      });
    }

    await tursoQuery(
      `INSERT INTO supplier_payments
       (supplier, purchase_id, description, amount)
       VALUES (?, ?, ?, ?)`,
      [
        supplier.trim(),
        purchase_id,
        description,
        paymentAmount
      ]
    );

    await tursoQuery(
      `INSERT INTO cash_transactions
       (type, description, amount)
       VALUES ('supplier_payment', ?, ?)`,
      [
        `Supplier Payment - ${supplier.trim()}`,
        -paymentAmount
      ]
    );

    res.json({
      success: true,
      message: 'Supplier payment recorded successfully',
      supplier: supplier.trim(),
      amount: paymentAmount,
      outstanding_after_payment: outstanding - paymentAmount
    });

  } catch (error) {
    console.error('Turso error:', error);

    res.status(500).json({
      error: 'Failed to record supplier payment',
      details: error.message
    });
  }
});


// 🧾 Create Sale-Purchase Allocation Table
app.get('/api/create-sale-purchase-allocations-table', async (req, res) => {
  try {
    await tursoQuery(`
      CREATE TABLE IF NOT EXISTS sale_purchase_allocations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sale_id INTEGER NOT NULL,
        purchase_id INTEGER NOT NULL,
        quantity REAL NOT NULL,
        unit_cost REAL NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `);

    res.json({
      success: true,
      message: 'Sale purchase allocations table created successfully'
    });

  } catch (error) {
    console.error('Sale purchase allocations table error:', error);

    res.status(500).json({
      error: error.message
    });
  }
});

// 🔎 Debug Product Stock & Purchase Batches
app.get('/api/debug-product-batches/:id', async (req, res) => {
  try {
    const productId = Number(req.params.id);

    const productData = await tursoQuery(
      `SELECT id, name, stock, purchase_price, selling_price
       FROM products
       WHERE id = ?
       LIMIT 1`,
      [productId]
    );

    const productRows =
      productData.results?.[0]?.response?.result?.rows || [];

    const batchData = await tursoQuery(
      `SELECT
         id,
         purchase_id,
         product_id,
         quantity,
         remaining_quantity,
         unit_cost
       FROM purchase_batches
       WHERE product_id = ?
       ORDER BY purchase_id ASC, id ASC`,
      [productId]
    );

    const batchRows =
      batchData.results?.[0]?.response?.result?.rows || [];

    res.json({
      product: productRows,
      purchase_batches: batchRows
    });

  } catch (error) {
    console.error('Debug product batches error:', error);

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

    if (!['cash', 'credit'].includes(payment_type)) {
      return res.status(400).json({
        error: 'Invalid payment_type'
      });
    }

    if (payment_type === 'credit' && (!customer || !customer.trim())) {
      return res.status(400).json({
        error: 'Customer name is required for credit sale'
      });
    }

    const productData = await tursoQuery(
      `SELECT id, name, stock, purchase_price
       FROM products
       WHERE id = ?
       LIMIT 1`,
      [productId]
    );

    const productRows =
      productData.results?.[0]?.response?.result?.rows || [];

    if (!productRows.length) {
      return res.status(404).json({
        error: 'Product not found'
      });
    }

    const productName = productRows[0][1]?.value || '';
    const currentStock = Number(productRows[0][2]?.value || 0);
    const openingCost = Number(productRows[0][3]?.value || 0);

    if (qty > currentStock) {
      return res.status(400).json({
        error: `Insufficient stock. Available stock: ${currentStock}`
      });
    }

    // 1. Find purchase batches using FIFO.
    const batchData = await tursoQuery(
      `SELECT
         id,
         purchase_id,
         remaining_quantity,
         unit_cost
       FROM purchase_batches
       WHERE product_id = ?
         AND remaining_quantity > 0
       ORDER BY purchase_id ASC, id ASC`,
      [productId]
    );

    const batchRows =
      batchData.results?.[0]?.response?.result?.rows || [];

    let remainingToAllocate = qty;
    let totalCost = 0;
    const allocations = [];

    for (const row of batchRows) {
      if (remainingToAllocate <= 0) {
        break;
      }

      const batchId = Number(row[0]?.value);
      const purchaseId = Number(row[1]?.value);
      const batchRemaining = Number(row[2]?.value || 0);
      const unitCost = Number(row[3]?.value || 0);

      if (
        !Number.isFinite(batchRemaining) ||
        batchRemaining <= 0 ||
        !Number.isFinite(unitCost)
      ) {
        continue;
      }

      const allocatedQty = Math.min(
        remainingToAllocate,
        batchRemaining
      );

      allocations.push({
        batchId,
        purchaseId,
        quantity: allocatedQty,
        unitCost
      });

      totalCost += allocatedQty * unitCost;
      remainingToAllocate -= allocatedQty;
    }

    // 2. If FIFO batches do not cover the full sale,
    // use Opening Stock at products.purchase_price as fallback cost.
    let openingStockQuantity = 0;

    if (remainingToAllocate > 0) {
      openingStockQuantity = remainingToAllocate;
      totalCost += openingStockQuantity * openingCost;
      remainingToAllocate = 0;
    }

    const total = qty * price;

    // Actual average cost of this sale.
    const actualCostPrice = totalCost / qty;

    // Turso decimal parameters must be sent as strings.
    const actualCostPriceValue = String(actualCostPrice);

    // 3. Create the sale using the actual calculated cost.
    const sale = await tursoQuery(
      `INSERT INTO sales
       (product_id, quantity, unit_price, cost_price, customer, total, payment_type)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        productId,
        qty,
        price,
        actualCostPriceValue,
        customer?.trim() || '',
        total,
        payment_type
      ]
    );

    const saleId =
      sale.results?.[0]?.response?.result?.last_insert_rowid || null;

    if (!saleId) {
      throw new Error('Failed to create sale ID');
    }

    // 4. Save FIFO allocations and reduce batch balances.
    for (const allocation of allocations) {
      await tursoQuery(
        `INSERT INTO sale_purchase_allocations
         (sale_id, purchase_id, quantity, unit_cost)
         VALUES (?, ?, ?, ?)`,
        [
          saleId,
          allocation.purchaseId,
          allocation.quantity,
          allocation.unitCost
        ]
      );

      await tursoQuery(
        `UPDATE purchase_batches
         SET remaining_quantity = remaining_quantity - ?
         WHERE id = ?`,
        [
          allocation.quantity,
          allocation.batchId
        ]
      );
    }

    // 5. Reduce product stock.
    const newStock = currentStock - qty;

    await tursoQuery(
      `UPDATE products
       SET stock = ?
       WHERE id = ?`,
      [newStock, productId]
    );

    // 6. Record stock movement.
    await tursoQuery(
      `INSERT INTO stock_movements
       (product_id, type, quantity, stock_before, stock_after, reference_id, note)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        productId,
        'sale',
        -qty,
        currentStock,
        newStock,
        saleId,
        `Sale - ${productName}${customer ? ` - ${customer}` : ''}`
      ]
    );

    // 7. Record payment/accounting entry.
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
          saleId,
          customer.trim(),
          `Credit Sale - ${productName}`,
          total
        ]
      );
    }

    res.json({
      success: true,
      message: 'Sale registered successfully',
      sale_id: saleId,
      total,
      cost_of_goods_sold: totalCost,
      actual_cost_per_unit: actualCostPrice,
      payment_type,
      fifo_allocations: allocations,
      opening_stock_quantity: openingStockQuantity,
      sale
    });

  } catch (error) {
    console.error('FIFO sale error:', error);

    res.status(500).json({
      error: 'Failed to register sale',
      details: error.message
    });
  }
});

// 📋 Recent Purchases

// 🗑️ Delete Sale
app.delete(
  '/api/sales/:id',
  requireAuth,
  requirePermission('delete_sales'),
  async (req, res) => {
    try {
      const saleId = Number(req.params.id);

      if (!Number.isInteger(saleId) || saleId <= 0) {
        return res.status(400).json({
          error: 'Invalid sale ID'
        });
      }

      const saleData = await tursoQuery(
        `SELECT
          id,
          product_id,
          quantity,
          total,
          customer,
          payment_type
         FROM sales
         WHERE id = ?
         LIMIT 1`,
        [saleId]
      );

      const saleRows =
        saleData.results?.[0]?.response?.result?.rows || [];

      if (!saleRows.length) {
        return res.status(404).json({
          error: 'Sale not found'
        });
      }

      const sale = saleRows[0];

      const productId = Number(sale[1]?.value);
      const quantity = Number(sale[2]?.value || 0);
      const total = Number(sale[3]?.value || 0);
      const customer = sale[4]?.value || '';
      const paymentType = sale[5]?.value || 'cash';

      // 1. Find FIFO allocations for this sale.
      const allocationData = await tursoQuery(
        `SELECT
          purchase_id,
          quantity
         FROM sale_purchase_allocations
         WHERE sale_id = ?
         ORDER BY id ASC`,
        [saleId]
      );

      const allocationRows =
        allocationData.results?.[0]?.response?.result?.rows || [];

      // 2. Restore each purchase batch quantity.
      for (const row of allocationRows) {
        const purchaseId = Number(row[0]?.value);
        const allocatedQuantity = Number(row[1]?.value || 0);

        if (
          !Number.isFinite(purchaseId) ||
          purchaseId <= 0 ||
          !Number.isFinite(allocatedQuantity) ||
          allocatedQuantity <= 0
        ) {
          continue;
        }

        await tursoQuery(
          `UPDATE purchase_batches
           SET remaining_quantity = remaining_quantity + ?
           WHERE purchase_id = ?
             AND product_id = ?`,
          [
            allocatedQuantity,
            purchaseId,
            productId
          ]
        );
      }

      // 3. Return product stock.
      const productData = await tursoQuery(
        `SELECT stock
         FROM products
         WHERE id = ?
         LIMIT 1`,
        [productId]
      );

      const productRows =
        productData.results?.[0]?.response?.result?.rows || [];

      if (!productRows.length) {
        return res.status(404).json({
          error: 'Product for this sale was not found'
        });
      }

      const currentStock = Number(productRows[0][0]?.value || 0);
      const newStock = currentStock + quantity;

      await tursoQuery(
        `UPDATE products
         SET stock = ?
         WHERE id = ?`,
        [newStock, productId]
      );

      // 4. Record stock reversal.
      await tursoQuery(
        `INSERT INTO stock_movements
         (product_id, type, quantity, stock_before, stock_after, reference_id, note)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [
          productId,
          'sale_reversal',
          quantity,
          currentStock,
          newStock,
          saleId,
          `Sale #${saleId} deleted`
        ]
      );

      // 5. Reverse cash sale.
      if (paymentType === 'cash') {
        await tursoQuery(
          `INSERT INTO cash_transactions
           (type, description, amount)
           VALUES (?, ?, ?)`,
          [
            'sale_reversal',
            `Deleted Sale #${saleId}`,
            -total
          ]
        );
      }

      // 6. Remove credit receivable.
      if (paymentType === 'credit') {
        await tursoQuery(
          `DELETE FROM customer_receivables
           WHERE sale_id = ?`,
          [saleId]
        );
      }

      // 7. Delete FIFO allocation records.
      await tursoQuery(
        `DELETE FROM sale_purchase_allocations
         WHERE sale_id = ?`,
        [saleId]
      );

      // 8. Delete sale.
      await tursoQuery(
        `DELETE FROM sales
         WHERE id = ?`,
        [saleId]
      );

      res.json({
        success: true,
        message: 'Sale deleted and FIFO allocation reversed successfully',
        sale_id: saleId,
        restored_stock: quantity,
        restored_allocations: allocationRows.length
      });

    } catch (error) {
      console.error('Delete sale error:', error);

      res.status(500).json({
        error: 'Failed to delete sale',
        details: error.message
      });
    }
  }
);

// 🔄 Sales Correction
app.post(
  '/api/sales/:id/correct',
  requireAuth,
  async (req, res) => {
    try {
      const saleId = Number(req.params.id);
      const { reason } = req.body;

      if (!Number.isInteger(saleId) || saleId <= 0) {
        return res.status(400).json({
          error: 'Valid sale ID is required'
        });
      }

      if (!reason || !String(reason).trim()) {
        return res.status(400).json({
          error: 'Correction reason is required'
        });
      }

      // 1. Find the original sale.
      const saleData = await tursoQuery(
        `SELECT
          id,
          product_id,
          quantity,
          total,
          customer,
          payment_type
         FROM sales
         WHERE id = ?
         LIMIT 1`,
        [saleId]
      );

      const saleRows =
        saleData.results?.[0]?.response?.result?.rows || [];

      if (!saleRows.length) {
        return res.status(404).json({
          error: 'Sale not found'
        });
      }

      const sale = saleRows[0];

      const productId = Number(sale[1]?.value);
      const quantity = Number(sale[2]?.value || 0);
      const total = Number(sale[3]?.value || 0);
      const customer = sale[4]?.value || '';
      const paymentType = sale[5]?.value || 'cash';

      if (
        !Number.isFinite(productId) ||
        productId <= 0 ||
        !Number.isFinite(quantity) ||
        quantity <= 0 ||
        !Number.isFinite(total) ||
        total < 0
      ) {
        return res.status(400).json({
          error: 'Invalid sale data'
        });
      }

      // 2. Prevent duplicate correction.
      const existingCorrection = await tursoQuery(
        `SELECT id
         FROM stock_movements
         WHERE type = 'sale_correction'
           AND reference_id = ?
         LIMIT 1`,
        [saleId]
      );

      const correctionRows =
        existingCorrection.results?.[0]?.response?.result?.rows || [];

      if (correctionRows.length) {
        return res.status(409).json({
          error: 'This sale has already been corrected'
        });
      }

      // 3. Find FIFO allocations.
      const allocationData = await tursoQuery(
        `SELECT
          purchase_id,
          quantity
         FROM sale_purchase_allocations
         WHERE sale_id = ?
         ORDER BY id ASC`,
        [saleId]
      );

      const allocationRows =
        allocationData.results?.[0]?.response?.result?.rows || [];

      // 4. Restore purchase batch quantities.
      for (const row of allocationRows) {
        const purchaseId = Number(row[0]?.value);
        const allocatedQuantity = Number(row[1]?.value || 0);

        if (
          !Number.isFinite(purchaseId) ||
          purchaseId <= 0 ||
          !Number.isFinite(allocatedQuantity) ||
          allocatedQuantity <= 0
        ) {
          continue;
        }

        await tursoQuery(
          `UPDATE purchase_batches
           SET remaining_quantity = remaining_quantity + ?
           WHERE purchase_id = ?
             AND product_id = ?`,
          [
            allocatedQuantity,
            purchaseId,
            productId
          ]
        );
      }

      // 5. Restore product stock.
      const productData = await tursoQuery(
        `SELECT stock
         FROM products
         WHERE id = ?
         LIMIT 1`,
        [productId]
      );

      const productRows =
        productData.results?.[0]?.response?.result?.rows || [];

      if (!productRows.length) {
        return res.status(404).json({
          error: 'Product for this sale was not found'
        });
      }

      const currentStock = Number(productRows[0][0]?.value || 0);
      const newStock = currentStock + quantity;

      await tursoQuery(
        `UPDATE products
         SET stock = ?
         WHERE id = ?`,
        [newStock, productId]
      );

      // 6. Record stock correction.
      await tursoQuery(
        `INSERT INTO stock_movements
         (product_id, type, quantity, stock_before, stock_after, reference_id, note)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [
          productId,
          'sale_correction',
          quantity,
          currentStock,
          newStock,
          saleId,
          `Sale #${saleId} corrected - ${String(reason).trim()}`
        ]
      );

      // 7. Reverse cash or credit effect.
      if (paymentType === 'cash') {
        await tursoQuery(
          `INSERT INTO cash_transactions
           (type, description, amount)
           VALUES (?, ?, ?)`,
          [
            'sale_correction',
            `Correction for Sale #${saleId} - ${String(reason).trim()}`,
            -total
          ]
        );
      } else {
        await tursoQuery(
          `INSERT INTO customer_receivables
           (sale_id, customer, description, amount)
           VALUES (?, ?, ?, ?)`,
          [
            saleId,
            customer || 'Unknown Customer',
            `Sale Correction #${saleId} - ${String(reason).trim()}`,
            -total
          ]
        );
      }

      res.json({
        success: true,
        message: 'Sale corrected successfully',
        sale_id: saleId,
        restored_stock: quantity,
        correction_amount: total,
        restored_allocations: allocationRows.length
      });

    } catch (error) {
      console.error('Sales correction error:', error);

      res.status(500).json({
        error: 'Failed to correct sale',
        details: error.message
      });
    }
  }
);

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

// 📊 Sales Summary
app.get('/api/sales-summary', async (req, res) => {
  try {
    const period = String(req.query.period || 'today').toLowerCase();

    const allowedPeriods = ['today', 'yesterday', 'week', 'month', 'all'];

    if (!allowedPeriods.includes(period)) {
      return res.status(400).json({
        error: 'Invalid period. Use today, yesterday, week, month, or all'
      });
    }

    let dateCondition = '';

    if (period === 'today') {
      dateCondition = `
        date(s.created_at, '+3 hours') = date('now', '+3 hours')
      `;
    } else if (period === 'yesterday') {
      dateCondition = `
        date(s.created_at, '+3 hours') =
        date('now', '+3 hours', '-1 day')
      `;
    } else if (period === 'week') {
      dateCondition = `
        date(s.created_at, '+3 hours') >=
        date('now', '+3 hours', 'weekday 1', '-7 days')
        AND
        date(s.created_at, '+3 hours') <
        date('now', '+3 hours', 'weekday 1')
      `;
    } else if (period === 'month') {
      dateCondition = `
        strftime('%Y-%m', s.created_at, '+3 hours') =
        strftime('%Y-%m', 'now', '+3 hours')
      `;
    } else {
      dateCondition = '1 = 1';
    }

    const summaryData = await tursoQuery(`
      SELECT
        COALESCE(SUM(s.total), 0) AS revenue,
        COUNT(s.id) AS sales_count,

        COALESCE(SUM(
          CASE
            WHEN s.payment_type = 'credit'
            THEN s.total
            ELSE 0
          END
        ), 0) AS credit,

        COALESCE(SUM(
          CASE
            WHEN s.payment_type = 'cash'
            THEN s.total
            ELSE 0
          END
        ), 0) AS sales_collected

      FROM sales s
      WHERE ${dateCondition}
    `);

    const paymentData = await tursoQuery(`
      SELECT COALESCE(SUM(amount), 0) AS customer_payments
      FROM customer_payments
      WHERE ${
        period === 'all'
          ? '1 = 1'
          : period === 'today'
            ? `date(created_at, '+3 hours') = date('now', '+3 hours')`
            : period === 'yesterday'
              ? `date(created_at, '+3 hours') = date('now', '+3 hours', '-1 day')`
              : period === 'month'
                ? `strftime('%Y-%m', created_at, '+3 hours') =
                   strftime('%Y-%m', 'now', '+3 hours')`
                : `date(created_at, '+3 hours') >=
                   date('now', '+3 hours', 'weekday 1', '-7 days')
                   AND
                   date(created_at, '+3 hours') <
                   date('now', '+3 hours', 'weekday 1')`
      }
    `);

    const expenseData = await tursoQuery(`
      SELECT COALESCE(SUM(ABS(amount)), 0) AS expenses
      FROM cash_transactions
      WHERE type = 'expense'
        AND ${
          period === 'all'
            ? '1 = 1'
            : period === 'today'
              ? `date(created_at, '+3 hours') = date('now', '+3 hours')`
              : period === 'yesterday'
                ? `date(created_at, '+3 hours') = date('now', '+3 hours', '-1 day')`
                : period === 'month'
                  ? `strftime('%Y-%m', created_at, '+3 hours') =
                     strftime('%Y-%m', 'now', '+3 hours')`
                  : `date(created_at, '+3 hours') >=
                     date('now', '+3 hours', 'weekday 1', '-7 days')
                     AND
                     date(created_at, '+3 hours') <
                     date('now', '+3 hours', 'weekday 1')`
        }
    `);

    const salesListData = await tursoQuery(`
      SELECT
        s.id,
        s.product_id,
        p.name AS product_name,
        s.quantity,
        s.unit_price,
        s.cost_price,
        s.customer,
        s.total,
        s.payment_type,
        s.created_at,
        CASE
          WHEN EXISTS (
            SELECT 1
            FROM stock_movements sm
            WHERE sm.type = 'sale_correction'
              AND sm.reference_id = s.id
          )
          THEN 1
          ELSE 0
        END AS corrected
      FROM sales s
      JOIN products p
        ON s.product_id = p.id
      WHERE ${dateCondition}
      ORDER BY s.id DESC
    `);

    const summaryRows =
      summaryData.results?.[0]?.response?.result?.rows || [];

    const paymentRows =
      paymentData.results?.[0]?.response?.result?.rows || [];

    const expenseRows =
      expenseData.results?.[0]?.response?.result?.rows || [];

    const salesRows =
      salesListData.results?.[0]?.response?.result?.rows || [];

    const summaryRow = summaryRows[0] || [];
    const paymentRow = paymentRows[0] || [];
    const expenseRow = expenseRows[0] || [];

    const revenue = Number(summaryRow[0]?.value || 0);
    const salesCount = Number(summaryRow[1]?.value || 0);
    const credit = Number(summaryRow[2]?.value || 0);
    const salesCollected = Number(summaryRow[3]?.value || 0);
    const customerPayments = Number(paymentRow[0]?.value || 0);
    const expenses = Number(expenseRow[0]?.value || 0);

    res.json({
      success: true,
      period,
      summary: {
        revenue,
        sales_count: salesCount,
        credit,
        sales_collected: salesCollected + customerPayments,
        credit_return: 0,
        expenses
      },
      sales: salesRows
    });

  } catch (error) {
    console.error('Sales summary error:', error);

    res.status(500).json({
      error: 'Failed to load sales summary',
      details: error.message
    });
  }
});

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
    const stockBefore = Number(productRows[0][2].value) || 0;
    const stockAfter = stockBefore + qty;

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

    const productionId =
      production.results?.[0]?.response?.result?.last_insert_rowid || null;

    await tursoQuery(
      `INSERT INTO stock_movements
       (product_id, type, quantity, stock_before, stock_after, reference_id, note)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        productId,
        'production',
        qty,
        stockBefore,
        stockAfter,
        productionId,
        `Production - ${productName}`
      ]
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

app.get('/api/create-stock-movements-table', async (req, res) => {
  try {
    await tursoQuery(`
      CREATE TABLE IF NOT EXISTS stock_movements (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        product_id INTEGER NOT NULL,
        type TEXT NOT NULL,
        quantity REAL NOT NULL,
        stock_before REAL NOT NULL DEFAULT 0,
        stock_after REAL NOT NULL DEFAULT 0,
        reference_id INTEGER,
        note TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `);

    res.json({
      success: true,
      message: 'Stock movements table created successfully'
    });
  } catch (error) {
    console.error('Turso error:', error);

    res.status(500).json({
      error: error.message
    });
  }
});
app.get('/api/stock-movements', async (req, res) => {
  try {
    const data = await tursoQuery(`
      SELECT
        stock_movements.id,
        stock_movements.product_id,
        products.name AS product_name,
        products.unit,
        stock_movements.type,
        stock_movements.quantity,
        stock_movements.stock_before,
        stock_movements.stock_after,
        stock_movements.reference_id,
        stock_movements.note,
        stock_movements.created_at
      FROM stock_movements
      JOIN products
        ON stock_movements.product_id = products.id
      ORDER BY stock_movements.id DESC
    `);

    res.json(data);
  } catch (error) {
    console.error('Turso error:', error);

    res.status(500).json({
      error: 'Failed to load stock movements',
      details: error.message
    });
  }
});


/* =========================================================
   STOCK ADJUSTMENT
   ========================================================= */

app.post('/api/stock-adjustments', requireAuth, async (req, res) => {
  try {
    const productId = Number(req.body.product_id);
    const adjustment = Number(req.body.adjustment);
    const reason = String(req.body.reason || '').trim();

    if (!Number.isInteger(productId) || productId <= 0) {
      return res.status(400).json({
        error: 'Valid product_id is required'
      });
    }

    if (!Number.isFinite(adjustment) || adjustment === 0) {
      return res.status(400).json({
        error: 'Adjustment must be a non-zero number'
      });
    }

    if (!reason) {
      return res.status(400).json({
        error: 'Adjustment reason is required'
      });
    }

    const productData = await tursoQuery(
      `SELECT id, name, stock
       FROM products
       WHERE id = ?`,
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
    const stockBefore =
      Number(productRows[0][2].value) || 0;

    const stockAfter = stockBefore + adjustment;

    if (stockAfter < 0) {
      return res.status(400).json({
        error: `Adjustment would make stock negative. Current stock: ${stockBefore}`
      });
    }

    await tursoQuery(
      `UPDATE products
       SET stock = ?
       WHERE id = ?`,
      [stockAfter, productId]
    );

    const movement = await tursoQuery(
      `INSERT INTO stock_movements
       (product_id, type, quantity, stock_before, stock_after, reference_id, note)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        productId,
        'stock_adjustment',
        adjustment,
        stockBefore,
        stockAfter,
        null,
        reason
      ]
    );

    res.json({
      success: true,
      message: 'Stock adjusted successfully',
      product_id: productId,
      product_name: productName,
      adjustment,
      stock_before: stockBefore,
      stock_after: stockAfter,
      movement_id:
        movement.results?.[0]?.response?.result?.last_insert_rowid || null
    });

  } catch (error) {
    console.error('Stock adjustment error:', error);

    res.status(500).json({
      error: 'Failed to adjust stock',
      details: error.message
    });
  }
});

/* =========================================================
   CORRECTION STATUS
   ========================================================= */

app.get('/api/correction-status', requireAuth, async (req, res) => {
  try {
    const corrections = [];

    // 1. Sales corrections
    const salesData = await tursoQuery(`
      SELECT
        sm.id,
        sm.reference_id,
        sm.quantity,
        sm.note,
        sm.created_at,
        s.customer,
        s.total
      FROM stock_movements sm
      LEFT JOIN sales s
        ON s.id = sm.reference_id
      WHERE sm.type = 'sale_correction'
      ORDER BY sm.id DESC
    `);

    const salesRows =
      salesData.results?.[0]?.response?.result?.rows || [];

    for (const row of salesRows) {
      corrections.push({
        id: Number(row[0]?.value),
        type: 'sale',
        correction_type: 'Sales Correction',
        original_id:
          row[1]?.value == null ? null : Number(row[1].value),
        quantity: Number(row[2]?.value || 0),
        amount: Number(row[6]?.value || 0),
        description: row[3]?.value || '',
        created_at: row[4]?.value || null,
        party: row[5]?.value || ''
      });
    }

    // 2. Purchase corrections
    const purchaseData = await tursoQuery(`
      SELECT
        sm.id,
        sm.reference_id,
        sm.quantity,
        sm.note,
        sm.created_at,
        p.supplier,
        p.total
      FROM stock_movements sm
      LEFT JOIN purchases p
        ON p.id = sm.reference_id
      WHERE sm.type = 'purchase_correction'
      ORDER BY sm.id DESC
    `);

    const purchaseRows =
      purchaseData.results?.[0]?.response?.result?.rows || [];

    for (const row of purchaseRows) {
      corrections.push({
        id: Number(row[0]?.value),
        type: 'purchase',
        correction_type: 'Purchase Correction',
        original_id:
          row[1]?.value == null ? null : Number(row[1].value),
        quantity: Math.abs(Number(row[2]?.value || 0)),
        amount: Number(row[6]?.value || 0),
        description: row[3]?.value || '',
        created_at: row[4]?.value || null,
        party: row[5]?.value || ''
      });
    }

    // 3. Expense corrections
    const expenseData = await tursoQuery(`
      SELECT
        id,
        description,
        amount,
        created_at
      FROM cash_transactions
      WHERE type = 'expense_correction'
      ORDER BY id DESC
    `);

    const expenseRows =
      expenseData.results?.[0]?.response?.result?.rows || [];

    for (const row of expenseRows) {
      const description = row[1]?.value || '';
      const match =
        description.match(/Correction for Expense #(\d+)\s*-\s*(.*)$/);

      corrections.push({
        id: Number(row[0]?.value),
        type: 'expense',
        correction_type: 'Expense Correction',
        original_id: match ? Number(match[1]) : null,
        quantity: null,
        amount: Math.abs(Number(row[2]?.value || 0)),
        description: match ? match[2] : description,
        created_at: row[3]?.value || null,
        party: ''
      });
    }

    // 4. Income corrections
    const incomeData = await tursoQuery(`
      SELECT
        id,
        description,
        amount,
        created_at
      FROM cash_transactions
      WHERE type = 'income_correction'
      ORDER BY id DESC
    `);

    const incomeRows =
      incomeData.results?.[0]?.response?.result?.rows || [];

    for (const row of incomeRows) {
      const description = row[1]?.value || '';
      const match =
        description.match(/Correction for Income #(\d+)\s*-\s*(.*)$/);

      corrections.push({
        id: Number(row[0]?.value),
        type: 'income',
        correction_type: 'Cash / Income Correction',
        original_id: match ? Number(match[1]) : null,
        quantity: null,
        amount: Math.abs(Number(row[2]?.value || 0)),
        description: match ? match[2] : description,
        created_at: row[3]?.value || null,
        party: ''
      });
    }

    // 5. Customer payment corrections
    const customerPaymentData = await tursoQuery(`
      SELECT
        id,
        description,
        amount,
        created_at
      FROM cash_transactions
      WHERE type = 'customer_payment_correction'
      ORDER BY id DESC
    `);

    const customerPaymentRows =
      customerPaymentData.results?.[0]?.response?.result?.rows || [];

    for (const row of customerPaymentRows) {
      const description = row[1]?.value || '';
      const match =
        description.match(
          /Correction for Customer Payment #(\d+)\s*-\s*(.*)$/
        );

      corrections.push({
        id: Number(row[0]?.value),
        type: 'customer_payment',
        correction_type: 'Customer Payment Correction',
        original_id: match ? Number(match[1]) : null,
        quantity: null,
        amount: Math.abs(Number(row[2]?.value || 0)),
        description: match ? match[2] : description,
        created_at: row[3]?.value || null,
        party: ''
      });
    }

    // 6. Supplier payment corrections
    const supplierPaymentData = await tursoQuery(`
      SELECT
        id,
        description,
        amount,
        created_at
      FROM cash_transactions
      WHERE type = 'supplier_payment_correction'
      ORDER BY id DESC
    `);

    const supplierPaymentRows =
      supplierPaymentData.results?.[0]?.response?.result?.rows || [];

    for (const row of supplierPaymentRows) {
      const description = row[1]?.value || '';
      const match =
        description.match(
          /Correction for Supplier Payment #(\d+)\s*-\s*(.*)$/
        );

      corrections.push({
        id: Number(row[0]?.value),
        type: 'supplier_payment',
        correction_type: 'Supplier Payment Correction',
        original_id: match ? Number(match[1]) : null,
        quantity: null,
        amount: Math.abs(Number(row[2]?.value || 0)),
        description: match ? match[2] : description,
        created_at: row[3]?.value || null,
        party: ''
      });
    }

    // 7. Stock adjustments
    const stockData = await tursoQuery(`
      SELECT
        sm.id,
        sm.product_id,
        sm.quantity,
        sm.stock_before,
        sm.stock_after,
        sm.note,
        sm.created_at,
        p.name,
        p.unit
      FROM stock_movements sm
      LEFT JOIN products p
        ON p.id = sm.product_id
      WHERE sm.type = 'stock_adjustment'
      ORDER BY sm.id DESC
    `);

    const stockRows =
      stockData.results?.[0]?.response?.result?.rows || [];

    for (const row of stockRows) {
      corrections.push({
        id: Number(row[0]?.value),
        type: 'stock',
        correction_type: 'Stock Adjustment',
        original_id: null,
        quantity: Number(row[2]?.value || 0),
        amount: null,
        description: row[5]?.value || '',
        created_at: row[6]?.value || null,
        party: row[7]?.value || '',
        stock_before: Number(row[3]?.value || 0),
        stock_after: Number(row[4]?.value || 0),
        unit: row[8]?.value || ''
      });
    }

    corrections.sort((a, b) => {
      const aTime = a.created_at || '';
      const bTime = b.created_at || '';

      if (aTime < bTime) return 1;
      if (aTime > bTime) return -1;

      return Number(b.id || 0) - Number(a.id || 0);
    });

    res.json({
      success: true,
      count: corrections.length,
      corrections
    });

  } catch (error) {
    console.error('Correction status error:', error);

    res.status(500).json({
      error: 'Failed to load correction status',
      details: error.message
    });
  }
});

/* =========================================================
   SUPPLIERS MASTER
   ========================================================= */

app.get('/api/create-suppliers-table', async (req, res) => {
  try {
    await tursoQuery(`
      CREATE TABLE IF NOT EXISTS suppliers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        phone TEXT,
        address TEXT,
        note TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `);

    res.json({
      success: true,
      message: 'Suppliers table created successfully'
    });
  } catch (error) {
    console.error('Turso error:', error);
    res.status(500).json({
      error: 'Failed to create suppliers table',
      details: error.message
    });
  }
});


/* =========================================================
   SUPPLIERS API
   ========================================================= */

app.get('/api/suppliers', async (req, res) => {
  try {
    const data = await tursoQuery(`
      SELECT id, name, phone, address, note, created_at
      FROM suppliers
      ORDER BY id DESC
    `);

    const rows =
      data.results?.[0]?.response?.result?.rows || [];

    const suppliers = rows.map(row => ({
      id: Number(row[0].value),
      name: row[1].value,
      phone: row[2].value,
      address: row[3].value,
      note: row[4].value,
      created_at: row[5].value
    }));

    res.json({
      success: true,
      count: suppliers.length,
      suppliers
    });
  } catch (error) {
    console.error('Turso error:', error);
    res.status(500).json({
      error: 'Failed to load suppliers',
      details: error.message
    });
  }
});

app.post('/api/suppliers', async (req, res) => {
  try {
    const {
      name,
      phone = '',
      address = '',
      note = ''
    } = req.body;

    const supplierName = String(name || '').trim();

    if (!supplierName) {
      return res.status(400).json({
        error: 'Supplier name is required'
      });
    }

    try {
      const data = await tursoQuery(
        `INSERT INTO suppliers
         (name, phone, address, note)
         VALUES (?, ?, ?, ?)`,
        [
          supplierName,
          String(phone || '').trim(),
          String(address || '').trim(),
          String(note || '').trim()
        ]
      );

      const supplierId =
        data.results?.[0]?.response?.result?.last_insert_rowid || null;

      res.json({
        success: true,
        message: 'Supplier created successfully',
        supplier_id: supplierId
      });
    } catch (error) {
      if (String(error.message).toLowerCase().includes('unique')) {
        return res.status(409).json({
          error: 'Supplier already exists'
        });
      }

      throw error;
    }
  } catch (error) {
    console.error('Turso error:', error);
    res.status(500).json({
      error: 'Failed to create supplier',
      details: error.message
    });
  }
});

app.delete('/api/suppliers/:id', async (req, res) => {
  try {
    const supplierId = Number(req.params.id);

    if (!Number.isInteger(supplierId) || supplierId <= 0) {
      return res.status(400).json({
        error: 'Valid supplier id is required'
      });
    }

    const existing = await tursoQuery(
      'SELECT id, name FROM suppliers WHERE id = ?',
      [supplierId]
    );

    const rows =
      existing.results?.[0]?.response?.result?.rows || [];

    if (!rows.length) {
      return res.status(404).json({
        error: 'Supplier not found'
      });
    }

    await tursoQuery(
      'DELETE FROM suppliers WHERE id = ?',
      [supplierId]
    );

    res.json({
      success: true,
      message: 'Supplier deleted successfully',
      supplier_id: supplierId
    });
  } catch (error) {
    console.error('Turso error:', error);
    res.status(500).json({
      error: 'Failed to delete supplier',
      details: error.message
    });
  }
});

