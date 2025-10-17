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

// ==========================
//  Seguridad y Middlewares
// ==========================
app.use(helmet({ contentSecurityPolicy: false }));
app.use(morgan('dev'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ==========================
//  Sesión
// ==========================
app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-secret-elitestream',
  resave: false,
  saveUninitialized: false,
}));

// ==========================
//  Base de datos
// ==========================
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir);
const db = new Database(path.join(dataDir, 'elite.db'));

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

// ==========================
//  Utilidades
// ==========================
const pesosToCents = n => Math.round(Number(n) * 100);
const safe = t => sanitizeHtml(t || '', { allowedTags: [], allowedAttributes: {} });
const logo = domain => https://logo.clearbit.com/${domain};

// ==========================
//  Semillas iniciales
// ==========================
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

// ==========================
//  Middleware de sesión
// ==========================
app.use((req, res, next) => {
  res.locals.session = req.session;
  next();
});

// ==========================
//  Rutas principales
// ==========================
app.get('/', (req, res) => {
  res.render('landing', { title: 'EliteStream — Inicio' });
});

// ==========================
//  Registro
// ==========================
app.get('/registro', (req, res) => res.render('register', { title: 'Registrarme' }));

app.post('/registro', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password || !email.trim()) {
    return res.status(400).send('<script>alert("Por favor llena todos los campos correctamente");window.location="/registro"</script>');
  }

  try {
    const hash = await bcrypt.hash(password, 10);
    db.prepare('INSERT INTO users(email,password_hash,role,points) VALUES(?,?, "client", 0)').run(safe(email), hash);
    res.redirect('/inicio');
  } catch (e) {
    console.error("Error al registrar usuario:", e);
    return res.status(400).send('<script>alert("Ese correo ya existe o es inválido");window.location="/registro"</script>');
  }
});

// ==========================
//  Login
// ==========================
app.get('/inicio', (req, res) => res.render('login', { title: 'Iniciar sesión' }));

app.post('/inicio', async (req, res) => {
  const { email, password } = req.body;
  const u = db.prepare('SELECT * FROM users WHERE email=?').get(safe(email));

  if (!u) return res.status(401).send('<script>alert("Credenciales inválidas");window.location="/inicio"</script>');

  const ok = await bcrypt.compare(password, u.password_hash);

  if (!ok) return res.status(401).send('<script>alert("Credenciales inválidas");window.location="/inicio"</script>');

  req.session.client = { id: u.id, email: u.email, points: u.points };
  res.redirect('/catalogo');
});

// ==========================
//  Catálogo, compras, panel cliente, admin, etc.
//  (lo demás de tu código se mantiene igual 👌)
// ==========================

// ==========================
//  Puerto
// ==========================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(✅ EliteStream listo en http://localhost:${PORT});
});
