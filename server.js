import 'dotenv/config';
import express from 'express';
import session from 'express-session';
import helmet from 'helmet';
import morgan from 'morgan';
import path from 'path';
import { fileURLToPath } from 'url';
import Database from 'better-sqlite3';
import bcrypt from 'bcryptjs';
import sanitizeHtml from 'sanitize-html';
import fs from 'fs';
import ejs from 'ejs';
import { v4 as uuidv4 } from 'uuid';

const __filename = fileURLToPath(import.meta.url);
const _dirname = path.dirname(_filename);
const app = express();

// Seguridad y middlewares
app.use(helmet({ contentSecurityPolicy: false }));
app.use(morgan('dev'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Configuración de la sesión
app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-secret-elitestream',
  resave: false,
  saveUninitialized: false,
}));

// ====== DB ======
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir);
const db = new Database(path.join(dataDir, 'elite.db'));

// Creación de tablas (añadí campos importantes)
db.exec(`
  CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    password_hash TEXT,
    role TEXT DEFAULT 'client',
    points INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS products(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    price_cents INTEGER,
    period TEXT,
    category TEXT,
    logo_url TEXT,
    active INTEGER DEFAULT 1,
    details_template TEXT
  );
  CREATE TABLE IF NOT EXISTS orders(
    id TEXT PRIMARY KEY,
    user_id INTEGER,
    product_id INTEGER,
    price_cents INTEGER,
    status TEXT,
    credentials TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(product_id) REFERENCES products(id)
  );
`);

// ====== Util ======
const pesosToCents = n => Math.round(Number(n) * 100);
const safe = t => sanitizeHtml(t || '', { allowedTags: [], allowedAttributes: {} });
const logo = domain => https://logo.clearbit.com/${domain};

// ====== Semillas iniciales ======
const seedProducts = () => {
  const count = db.prepare('SELECT COUNT(*) as c FROM products').get().c;
  if (count > 0) return;

  const items = [
    ['Disney con canales ESPN STAR', 85, '1M', 'Streaming', logo('disneyplus.com')],
    ['HBO Max', 65, '1M', 'Streaming', logo('max.com')],
    ['HBO Max 4 dispositivos', 135, '1M', 'Streaming', logo('max.com')],
    ['Prime', 65, '1M', 'Streaming', logo('amazon.com')],
    ['Prime cuenta completa', 135, '1M', 'Streaming', logo('amazon.com')],
    ['Netflix', 90, '1M', 'Streaming', logo('netflix.com')],
    ['Viki Rakuten', 55, '1M', 'Streaming', logo('viki.com')],
    ['Vix 1M', 60, '1M', 'Streaming', logo('vix.com')],
    ['Vix 3M', 90, '3M', 'Streaming', logo('vix.com')],
    ['Vix 6M', 119, '6M', 'Streaming', logo('vix.com')],
    ['Vix anual', 180, 'Anual', 'Streaming', logo('vix.com')],
    ['Crunchyroll 1M', 50, '1M', 'Streaming', logo('crunchyroll.com')],
    ['Crunchyroll anual', 169, 'Anual', 'Streaming', logo('crunchyroll.com')],
    ['Deezer', 70, '1M', 'Música', logo('deezer.com')],
    ['Dramabox', 90, '1M', 'Streaming', logo('dramabox.com')],
    ['IPTV 1M', 90, '1M', 'TV', logo('iptv.org')],
    ['Flujo TV', 70, '1M', 'TV', logo('flujotv.com')],
    ['Pornhub', 69, '1M', 'Adulto', logo('pornhub.com')],
    ['Pornhub completa', 135, '1M', 'Adulto', logo('pornhub.com')],
    ['Apple Music', 100, '1M', 'Música', logo('apple.com')],
    ['Plex', 55, '1M', 'Otros', logo('plex.tv')],
    ['Tidal', 59, '1M', 'Música', logo('tidal.com')],
    ['Paramount 1M', 50, '1M', 'Streaming', logo('paramountplus.com')],
    ['Paramount 1M completa', 100, '1M', 'Streaming', logo('paramountplus.com')],
    ['Spotify 1M', 70, '1M', 'Música', logo('spotify.com')],
    ['Spotify 3M', 155, '3M', 'Música', logo('spotify.com')],
    ['YouTube 1M', 75, '1M', 'Video', logo('youtube.com')],
    ['YouTube 2M', 125, '2M', 'Video', logo('youtube.com')],
    ['YouTube 3M', 160, '3M', 'Video', logo('youtube.com')],
    ['YouTube familiar', 110, '1M', 'Video', logo('youtube.com')],
    ['Canva 1M', 55, '1M', 'Productividad', logo('canva.com')],
    ['Canva 3M', 89, '3M', 'Productividad', logo('canva.com')],
    ['Canva 6M', 125, '6M', 'Productividad', logo('canva.com')],
    ['Canva anual', 150, 'Anual', 'Productividad', logo('canva.com')],
    ['Office 365 anual', 300, 'Anual', 'Productividad', logo('office.com')],
    ['Duolingo Plus', 65, '1M', 'Educación', logo('duolingo.com')],
    ['Deezer Premium', 60, '1M', 'Música', logo('deezer.com')],
    ['Universal +', 55, '1M', 'Streaming', logo('universalplus.com')],
    ['Open English 6 meses', 1200, '6M', 'Educación', logo('openenglish.com')],
    ['CapCut Pro 1M', 150, '1M', 'Productividad', logo('capcut.com')],
    ['ChatGPT Pro 1M', 150, '1M', 'IA', logo('openai.com')],
  ];

  const ins = db.prepare(`
    INSERT INTO products(name,price_cents,period,category,logo_url,active,details_template)
    VALUES(?,?,?,?,?,1,?)
  `);

  for (const it of items) {
    const [name, price, period, category, logo_url] = it;
    const plantilla = Cuenta: ${name} | Periodo: ${period} | Usuario: {{email}} | Contraseña: (se enviará por correo o en esta pantalla);
    ins.run(name, pesosToCents(price), period, category, logo_url, plantilla);
  }
};
seedProducts();

// ====== Middleware de sesión ======
app.use((req, res, next) => {
  res.locals.session = req.session;
  next();
});

// ====== Rutas ======

// Ruta principal (Landing page con opciones de Administración y Cliente)
app.get('/', (req, res) => {
  res.render('landing', { title: 'EliteStream — Inicio' });
});

// ====== Registro ======
app.get('/registro', (req, res) => res.render('register', { title: 'Registrarme' }));

app.post('/registro', async (req, res) => {
    const { email, password } = req.body;
  
    if (!email || !password || !email.trim()) {
      return res.status(400).send('<script>alert("Por favor llena todos los campos correctamente");window.location="/registro"</script>');
    }
  
    try {
      // Hash de la contraseña de forma asíncrona
      const hash = await bcrypt.hash(password, 10);
  
      // Intenta insertar el nuevo usuario en la base de datos
      db.prepare('INSERT INTO users(email,password_hash,role,points) VALUES(?,?,\\\"client\\\",0)').run(safe(email), hash);
  
      // Redirige al usuario a la página de inicio de sesión
      res.redirect('/inicio');
    } catch (e) {
      // Si hay un error (por ejemplo, correo ya existe), muestra un mensaje de error
      console.error("Error al registrar usuario:", e);
      return res.status(400).send('<script>alert("Ese correo ya existe o es inválido");window.location="/registro"</script>');
    }
  });
  

// ====== Login ======
app.get('/inicio', (req, res) => res.render('login', { title: 'Iniciar sesión' }));

app.post('/inicio', async (req, res) => {
  const { email, password } = req.body;
  const u = db.prepare('SELECT * FROM users WHERE email=?').get(safe(email));

  if (!u) return res.status(401).send('<script>alert("Credenciales inválidas");window.location="/inicio"</script>');

  // Comparación de contraseñas de forma asíncrona
  const ok = await bcrypt.compare(password, u.password_hash);

  if (!ok) return res.status(401).send('<script>alert("Credenciales inválidas");window.location="/inicio"</script>');

  req.session.client = { id: u.id, email: u.email };
  res.redirect('/catalogo');
});

// ====== Catálogo ======
app.get('/catalogo', (req, res) => {
    // Verifica si el cliente ha iniciado sesión
    if (!req.session.client) {
      return res.redirect('/inicio'); // Redirige al inicio de sesión si no está autenticado
    }
  
    const client = req.session.client;
    const products = db.prepare('SELECT * FROM products WHERE active=1').all();
  
    res.render('catalog', {
      title: 'Catálogo',
      client: client,
      products: products
    });
  });

// ====== Comprar Producto ======
app.post('/comprar/:id', (req, res) => {
    // Verifica si el cliente ha iniciado sesión
    if (!req.session.client) {
      return res.redirect('/inicio'); // Redirige al inicio de sesión si no está autenticado
    }
  
    const productId = req.params.id;
    const client = req.session.client;
  
    // Obtiene el producto de la base de datos
    const product = db.prepare('SELECT * FROM products WHERE id=?').get(productId);
  
    if (!product) {
      return res.status(404).send('<script>alert("Producto no encontrado");window.location="/catalogo"</script>');
    }
  
    // Verifica si el cliente tiene suficientes puntos
    if (client.points < (product.price_cents / 100)) {
      return res.status(400).send('<script>alert("No tienes suficientes puntos");window.location="/catalogo"</script>');
    }
  
    // Crea un nuevo ID para la orden
    const orderId = uuidv4();
  
    // Define el estado inicial de la orden
    const orderStatus = 'pendiente';
  
    try {
      // Inicia una transacción para asegurar que la compra se realiza completamente
      db.prepare('BEGIN TRANSACTION').run();
  
      // Crea la orden en la base de datos
      db.prepare(`
        INSERT INTO orders(id, user_id, product_id, price_cents, status)
        VALUES(?,?,?,?,?)
      `).run(orderId, client.id, productId, product.price_cents, orderStatus);
  
      // Actualiza los puntos del cliente restando el precio del producto
      db.prepare('UPDATE users SET points = points - ? WHERE id = ?').run(product.price_cents, client.id);
  
      // Finaliza la transacción
      db.prepare('COMMIT').run();
  
      // Actualiza la información de la sesión del cliente con los nuevos puntos
      const updatedClient = db.prepare('SELECT * FROM users WHERE id=?').get(client.id);
      req.session.client = { id: updatedClient.id, email: updatedClient.email, points: updatedClient.points };
  
      // Redirige al panel del cliente para ver la orden
      res.redirect('/client/panel');
    } catch (e) {
      // Si hay un error, revierte la transacción
      db.prepare('ROLLBACK').run();
      console.error("Error al realizar la compra:", e);
      return res.status(500).send('<script>alert("Error al realizar la compra");window.location="/catalogo"</script>');
    }
  });
  
// ====== Panel del Cliente ======
app.get('/client/panel', (req, res) => {
    // Verifica si el cliente ha iniciado sesión
    if (!req.session.client) {
      return res.redirect('/inicio'); // Redirige al inicio de sesión si no está autenticado
    }
  
    const client = req.session.client;
  
    // Obtiene las órdenes del cliente desde la base de datos
    const orders = db.prepare(`
      SELECT orders.id, products.name as product_name, orders.price_cents, orders.status, orders.credentials
      FROM orders
      JOIN products ON orders.product_id = products.id
      WHERE orders.user_id = ?
    `).all(client.id);
  
    res.render('client/panel', {
      title: 'Mi Panel',
      client: client,
      orders: orders
    });
  });

// ====== Admin Login ======
app.get('/admin/login', (req, res) => {
  res.render('admin/login', { title: 'Admin Login' });
});

app.post('/admin/login', (req, res) => {
    const { user, pass } = req.body;
  
    if (user === process.env.ADMIN_USER && pass === process.env.ADMIN_PASS) {
      req.session.admin = true; // Establece una variable de sesión para indicar que el usuario es administrador
      res.redirect('/admin/dashboard');
    } else {
      res.status(401).send('<script>alert("Credenciales inválidas");window.location="/admin/login"</script>');
    }
  });

// Middleware para verificar si es administrador
const requireAdmin = (req, res, next) => {
  if (req.session.admin) {
    next(); // Permite el acceso a la ruta si es administrador
  } else {
    res.status(403).send('<script>alert("Acceso denegado");window.location="/admin/login"</script>'); // Redirige si no es administrador
  }
};

// ====== Admin Dashboard ======
app.get('/admin/dashboard', requireAdmin, (req, res) => {
    // Obtiene las estadísticas necesarias desde la base de datos
    const stats = {
      users: db.prepare('SELECT COUNT(*) as count FROM users WHERE role = "client"').get().count,
      sales: db.prepare('SELECT SUM(price_cents) as total FROM orders').get().total || 0,
      orders: db.prepare('SELECT COUNT(*) as count FROM orders').get().count
    };
  
    res.render('admin/dashboard', {
      title: 'Panel de Administración',
      stats: stats
    });
  });

// ====== Admin Clients ======
app.get('/admin/clients', requireAdmin, (req, res) => {
    const clients = db.prepare('SELECT * FROM users WHERE role = "client"').all();
    res.render('admin/clients', { title: 'Clientes', clients: clients });
  });

// Ruta para actualizar los puntos de un cliente
app.post('/admin/clients/:id/points', requireAdmin, (req, res) => {
    const clientId = req.params.id;
    const delta = parseInt(req.body.delta);
  
    if (isNaN(delta)) {
      return res.status(400).send('<script>alert("Por favor ingresa un número válido de puntos");window.location="/admin/clients"</script>');
    }
  
    try {
      // Actualiza los puntos del cliente sumando el valor delta
      db.prepare('UPDATE users SET points = points + ? WHERE id = ?').run(delta, clientId);
      res.redirect('/admin/clients');
    } catch (e) {
      console.error("Error al actualizar los puntos del cliente:", e);
      return res.status(500).send('<script>alert("Error al actualizar los puntos del cliente");window.location="/admin/clients"</script>');
    }
  });
  

// Ruta para eliminar un cliente
app.post('/admin/clients/:id/delete', requireAdmin, (req, res) => {
    const clientId = req.params.id;
  
    try {
      // Elimina el cliente de la base de datos
      db.prepare('DELETE FROM users WHERE id = ?').run(clientId);
      res.redirect('/admin/clients');
    } catch (e) {
      console.error("Error al eliminar el cliente:", e);
      return res.status(500).send('<script>alert("Error al eliminar el cliente");window.location="/admin/clients"</script>');
    }
  });

// ====== Admin Products ======
app.get('/admin/products', requireAdmin, (req, res) => {
  const products = db.prepare('SELECT * FROM products').all();
  res.render('admin/products', { title: 'Productos', products: products });
});

app.post('/admin/products', requireAdmin, (req, res) => {
    const { name, price, logo_url, period, category, details_template } = req.body;
  
    if (!name || !price || !logo_url || !period || !category || !details_template) {
      return res.status(400).send('<script>alert("Por favor llena todos los campos correctamente");window.location="/admin/products"</script>');
    }
  
    try {
      // Inserta el nuevo producto en la base de datos
      db.prepare(`
        INSERT INTO products(name, price_cents, period, category, logo_url, details_template)
        VALUES(?,?,?,?,?,?)
      `).run(
        safe(name),
        pesosToCents(price),
        safe(period),
        safe(category),
        safe(logo_url),
        safe(details_template)
      );
  
      res.redirect('/admin/products');
    } catch (e) {
      console.error("Error al crear el producto:", e);
      return res.status(500).send('<script>alert("Error al crear el producto");window.location="/admin/products"</script>');
    }
  });

// Ruta para activar/desactivar un producto
app.post('/admin/product/:id/toggle', requireAdmin, (req, res) => {
    const productId = req.params.id;
  
    try {
      // Obtiene el producto de la base de datos
      const product = db.prepare('SELECT * FROM products WHERE id = ?').get(productId);
  
      if (!product) {
        return res.status(404).send('<script>alert("Producto no encontrado");window.location="/admin/products"</script>');
      }
  
      // Invierte el estado del producto (activo/inactivo)
      const newActive = product.active === 1 ? 0 : 1;
  
      // Actualiza el estado del producto en la base de datos
      db.prepare('UPDATE products SET active = ? WHERE id = ?').run(newActive, productId);
  
      res.redirect('/admin/products');
    } catch (e) {
      console.error("Error al activar/desactivar el producto:", e);
      return res.status(500).send('<script>alert("Error al activar/desactivar el producto");window.location="/admin/products"</script>');
    }
  });
  

// Ruta para eliminar un producto
app.post('/admin/product/:id/delete', requireAdmin, (req, res) => {
    const productId = req.params.id;
  
    try {
      // Elimina el producto de la base de datos
      db.prepare('DELETE FROM products WHERE id = ?').run(productId);
      res.redirect('/admin/products');
    } catch (e) {
      console.error("Error al eliminar el producto:", e);
      return res.status(500).send('<script>alert("Error al eliminar el producto");window.location="/admin/products"</script>');
    }
  });

// ====== Admin Orders ======
app.get('/admin/orders', requireAdmin, (req, res) => {
    const orders = db.prepare(`
      SELECT orders.id, users.email as user_email, products.name as product_name,
             orders.price_cents, orders.status, orders.credentials
      FROM orders
      JOIN users ON orders.user_id = users.id
      JOIN products ON orders.product_id = products.id
    `).all();
  
    res.render('admin/orders', { title: 'Órdenes', orders: orders });
  });

// Ruta para actualizar las credenciales de una orden
app.post('/admin/orders/:id/credentials', requireAdmin, (req, res) => {
    const orderId = req.params.id;
    const credentials = req.body.credentials;
  
    try {
      // Actualiza las credenciales de la orden en la base de datos
      db.prepare('UPDATE orders SET credentials = ? WHERE id = ?').run(safe(credentials), orderId);
      res.redirect('/admin/orders');
    } catch (e) {
      console.error("Error al actualizar las credenciales de la orden:", e);
      return res.status(500).send('<script>alert("Error al actualizar las credenciales de la orden");window.location="/admin/orders"</script>');
    }
  });

// Ruta para cancelar una orden y reembolsar los puntos al cliente
app.post('/admin/orders/:id/cancel', requireAdmin, (req, res) => {
    const orderId = req.params.id;
  
    try {
      // Obtiene la orden de la base de datos
      const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(orderId);
  
      if (!order) {
        return res.status(404).send('<script>alert("Orden no encontrada");window.location="/admin/orders"</script>');
      }
  
      // Inicia una transacción para asegurar que la cancelación se realiza completamente
      db.prepare('BEGIN TRANSACTION').run();
  
      // Actualiza el estado de la orden a "cancelada"
      db.prepare('UPDATE orders SET status = "cancelada" WHERE id = ?').run(orderId);
  
      // Reembolsa los puntos al cliente sumando el precio de la orden
      db.prepare('UPDATE users SET points = points + ? WHERE id = ?').run(order.price_cents, order.user_id);
  
      // Finaliza la transacción
      db.prepare('COMMIT').run();
  
      res.redirect('/admin/orders');
    } catch (e) {
      // Si hay un error, revierte la transacción
      db.prepare('ROLLBACK').run();
      console.error("Error al cancelar la orden:", e);
      return res.status(500).send('<script>alert("Error al cancelar la orden");window.location="/admin/orders"</script>');
    }
  });
  

// ====== Layout helper ======
const originalRender = app.response.render;
app.response.render = function (view, options = {}, cb) {
  options.layout = (name) => { options._layoutFile = name; };
  options.body = '';
  const self = this;

  ejs.renderFile(path.join(__dirname, 'views', view + '.ejs'), { ...options }, (err, str) => {
    if (err) return originalRender.call(self, view, options, cb);

    if (options._layoutFile) {
      options.body = str;
      return ejs.renderFile(path.join(__dirname, 'views', options._layoutFile + '.ejs'), { ...options }, (e, str2) => {
        if (e) return self.send(str);
        return self.send(str2);
      });
    }

    return self.send(str);
  });
};

// ====== Puerto ======
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(✅ EliteStream listo en http://localhost:${PORT});
});
