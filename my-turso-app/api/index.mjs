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
