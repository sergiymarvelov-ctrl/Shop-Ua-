const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const { Pool } = require('pg');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// ================================
// DATABASE
// ================================

const pool = process.env.DATABASE_URL
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: { rejectUnauthorized: false }
    })
  : null;

let db = {
  users: [],
  products: [
    {
      id: 1,
      name: 'Лавандове мило',
      price: 120,
      desc: 'Натуральне мило ручної роботи з ніжним ароматом лаванди.',
      image: ''
    },
    {
      id: 2,
      name: 'Медове мило',
      price: 135,
      desc: 'М’яке натуральне мило з теплим медовим ароматом.',
      image: ''
    }
  ],
  orders: []
};

// ================================
// FILE UPLOAD
// ================================

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 3 * 1024 * 1024
  },
  fileFilter: (req, file, cb) => {
    if (!file.mimetype.startsWith('image/')) {
      return cb(new Error('Можна завантажувати тільки зображення'));
    }

    cb(null, true);
  }
});

// ================================
// EXPRESS
// ================================

app.use(express.urlencoded({
  extended: true,
  limit: '5mb'
}));

app.use(express.json({
  limit: '5mb'
}));

// ================================
// SESSION
// ================================

app.set('trust proxy', 1);

app.use(
  session({
    secret:
      process.env.SESSION_SECRET ||
      'soap-shop-temporary-secret-change-me',

    resave: false,
    saveUninitialized: false,

    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production',
      maxAge: 7 * 24 * 60 * 60 * 1000
    }
  })
);

// ================================
// STATIC WEBSITE
// ================================

// HTML/CSS/logo лежать у корені репозиторію
app.use(express.static(__dirname));

// Головна сторінка
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Вхід
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'login.html'));
});

// Адмін-панель
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

// ================================
// DATABASE LOAD/SAVE
// ================================

async function save() {
  if (!pool) return;

  await pool.query(
    `
    INSERT INTO app_state (id, data)
    VALUES (1, $1::jsonb)
    ON CONFLICT (id)
    DO UPDATE SET data = EXCLUDED.data
    `,
    [JSON.stringify(db)]
  );
}

async function load() {
  if (pool) {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS app_state (
        id INTEGER PRIMARY KEY,
        data JSONB NOT NULL
      )
    `);

    const result = await pool.query(
      'SELECT data FROM app_state WHERE id = 1'
    );

    if (result.rows.length > 0) {
      db = result.rows[0].data;
    }
  }

  // Головний адміністратор
  const owner = db.users.find(
    user =>
      user.username.toLowerCase() ===
      'yung_marvelov'
  );

  if (!owner) {
    const passwordHash = await bcrypt.hash(
      process.env.ADMIN_PASSWORD || 'ChangeMe123!',
      10
    );

    db.users.push({
      id: Date.now(),
      username: 'Yung_Marvelov',
      password: passwordHash,
      role: 'owner'
    });

    await save();
  }
}

// ================================
// HELPERS
// ================================

function currentUser(req) {
  return db.users.find(
    user => String(user.id) === String(req.session.uid)
  );
}

function adminOnly(req, res, next) {
  const user = currentUser(req);

  if (
    !user ||
    !['admin', 'owner'].includes(user.role)
  ) {
    return res.status(403).json({
      error: 'Немає доступу'
    });
  }

  req.user = user;
  next();
}

function imageData(file) {
  if (!file) return '';

  return `data:${file.mimetype};base64,${file.buffer.toString(
    'base64'
  )}`;
}

// ================================
// HEALTH
// ================================

app.get('/health', (req, res) => {
  res.json({
    ok: true,
    database: Boolean(pool)
  });
});

// ================================
// USER
// ================================

app.get('/api/me', (req, res) => {
  const user = currentUser(req);

  if (!user) {
    return res.json(null);
  }

  res.json({
    username: user.username,
    role: user.role
  });
});

// ================================
// REGISTER
// ================================

app.post('/api/register', async (req, res) => {
  try {
    let { username, password } = req.body;

    username = String(username || '').trim();
    password = String(password || '');

    if (username.length < 3) {
      return res.status(400).json({
        error: 'Логін має містити мінімум 3 символи'
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        error: 'Пароль має містити мінімум 6 символів'
      });
    }

    const exists = db.users.some(
      user =>
        user.username.toLowerCase() ===
        username.toLowerCase()
    );

    if (exists) {
      return res.status(400).json({
        error: 'Такий користувач уже існує'
      });
    }

    const user = {
      id: Date.now(),
      username,
      password: await bcrypt.hash(password, 10),
      role: 'user'
    };

    db.users.push(user);

    await save();

    req.session.uid = user.id;

    res.json({
      ok: true
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: 'Помилка сервера'
    });
  }
});

// ================================
// LOGIN
// ================================

app.post('/api/login', async (req, res) => {
  try {
    const username = String(
      req.body.username || ''
    ).trim();

    const password = String(
      req.body.password || ''
    );

    const user = db.users.find(
      item =>
        item.username.toLowerCase() ===
        username.toLowerCase()
    );

    if (!user) {
      return res.status(401).json({
        error: 'Невірний логін або пароль'
      });
    }

    const validPassword = await bcrypt.compare(
      password,
      user.password
    );

    if (!validPassword) {
      return res.status(401).json({
        error: 'Невірний логін або пароль'
      });
    }

    req.session.uid = user.id;

    res.json({
      ok: true,
      role: user.role
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: 'Помилка входу'
    });
  }
});

// ================================
// LOGOUT
// ================================

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({
      ok: true
    });
  });
});

// ================================
// PRODUCTS
// ================================

app.get('/api/products', (req, res) => {
  res.json(db.products);
});

// Додати товар
app.post(
  '/api/products',
  adminOnly,
  upload.single('image'),
  async (req, res) => {
    try {
      const name = String(
        req.body.name || ''
      ).trim();

      const price = Number(req.body.price);

      if (!name) {
        return res.status(400).send(
          'Вкажіть назву товару'
        );
      }

      if (
        !Number.isFinite(price) ||
        price < 0
      ) {
        return res.status(400).send(
          'Некоректна ціна'
        );
      }

      db.products.push({
        id: Date.now(),
        name,
        price,
        desc: String(req.body.desc || ''),
        image: imageData(req.file)
      });

      await save();

      res.redirect('/admin.html');
    } catch (error) {
      console.error(error);

      res.status(500).send(
        'Помилка додавання товару'
      );
    }
  }
);

// Редагувати товар
app.post(
  '/api/products/:id',
  adminOnly,
  upload.single('image'),
  async (req, res) => {
    try {
      const product = db.products.find(
        item =>
          String(item.id) ===
          String(req.params.id)
      );

      if (!product) {
        return res.status(404).send(
          'Товар не знайдено'
        );
      }

      if (req.body.name !== undefined) {
        product.name = String(
          req.body.name
        ).trim();
      }

      if (
        req.body.price !== undefined &&
        req.body.price !== ''
      ) {
        const price = Number(
          req.body.price
        );

        if (
          !Number.isFinite(price) ||
          price < 0
        ) {
          return res.status(400).send(
            'Некоректна ціна'
          );
        }

        product.price = price;
      }

      if (req.body.desc !== undefined) {
        product.desc = String(
          req.body.desc
        );
      }

      if (req.file) {
        product.image = imageData(
          req.file
        );
      }

      await save();

      res.redirect('/admin.html');
    } catch (error) {
      console.error(error);

      res.status(500).send(
        'Помилка редагування'
      );
    }
  }
);

// Видалити товар
app.delete(
  '/api/products/:id',
  adminOnly,
  async (req, res) => {
    try {
      db.products = db.products.filter(
        item =>
          String(item.id) !==
          String(req.params.id)
      );

      await save();

      res.json({
        ok: true
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: 'Помилка видалення'
      });
    }
  }
);

// ================================
// USERS / ADMINS
// ================================

app.get(
  '/api/users',
  adminOnly,
  (req, res) => {
    const users = db.users.map(
      ({ password, ...user }) => user
    );

    res.json(users);
  }
);

// Додати адміністратора
app.post(
  '/api/admins',
  adminOnly,
  async (req, res) => {
    try {
      if (req.user.role !== 'owner') {
        return res.status(403).json({
          error:
            'Тільки головний адміністратор може додавати адмінів'
        });
      }

      let { username, password } =
        req.body;

      username = String(
        username || ''
      ).trim();

      password = String(
        password || ''
      );

      if (username.length < 3) {
        return res.status(400).json({
          error:
            'Логін має містити мінімум 3 символи'
        });
      }

      if (password.length < 6) {
        return res.status(400).json({
          error:
            'Пароль має містити мінімум 6 символів'
        });
      }

      const exists = db.users.some(
        user =>
          user.username.toLowerCase() ===
          username.toLowerCase()
      );

      if (exists) {
        return res.status(400).json({
          error:
            'Такий користувач уже існує'
        });
      }

      db.users.push({
        id: Date.now(),
        username,
        password: await bcrypt.hash(
          password,
          10
        ),
        role: 'admin'
      });

      await save();

      res.json({
        ok: true
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error:
          'Не вдалося створити адміністратора'
      });
    }
  }
);

// ================================
// ORDERS
// ================================

app.post('/api/orders', async (req, res) => {
  try {
    const {
      items,
      name,
      phone
    } = req.body;

    if (
      !Array.isArray(items) ||
      items.length === 0
    ) {
      return res.status(400).json({
        error: 'Кошик порожній'
      });
    }

    if (
      !String(name || '').trim() ||
      !String(phone || '').trim()
    ) {
      return res.status(400).json({
        error:
          'Вкажіть ім’я та номер телефону'
      });
    }

    const order = {
      id: Date.now(),
      items,
      name: String(name).trim(),
      phone: String(phone).trim(),
      status: 'Нове',
      created: new Date().toISOString()
    };

    db.orders.push(order);

    await save();

    res.json({
      ok: true,
      orderId: order.id
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error:
        'Не вдалося оформити замовлення'
    });
  }
});

app.get(
  '/api/orders',
  adminOnly,
  (req, res) => {
    res.json(db.orders);
  }
);

// ================================
// 404 API
// ================================

app.use('/api', (req, res) => {
  res.status(404).json({
    error: 'API endpoint не знайдено'
  });
});

// ================================
// ERROR HANDLER
// ================================

app.use((error, req, res, next) => {
  console.error(error);

  if (error instanceof multer.MulterError) {
    return res.status(400).json({
      error:
        'Помилка завантаження зображення. Максимум 3 MB.'
    });
  }

  res.status(500).json({
    error:
      error.message || 'Помилка сервера'
  });
});

// ================================
// START SERVER
// ================================

load()
  .then(() => {
    app.listen(
      PORT,
      '0.0.0.0',
      () => {
        console.log(
          `SOAP SHOP running on port ${PORT}`
        );
      }
    );
  })
  .catch(error => {
    console.error(
      'SERVER START ERROR:',
      error
    );

    process.exit(1);
  });
