
const express = require("express");
const http = require("http");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);

app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || "change-this-secret-before-production";
const CREATOR_PHONE = process.env.CREATOR_PHONE || "";

const db = new Database("alpha.db");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  phone TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  password TEXT,
  banned_until INTEGER DEFAULT 0,
  created_at INTEGER
);

CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sender TEXT NOT NULL,
  receiver TEXT NOT NULL,
  message TEXT NOT NULL,
  created_at INTEGER
);
`);

const codes = new Map();
const online = new Map();

function token(phone) {
  return jwt.sign({ phone }, SECRET, { expiresIn: "7d" });
}

function auth(req, res, next) {
  try {
    const value = req.headers.authorization || "";
    const decoded = jwt.verify(value.replace("Bearer ", ""), SECRET);
    req.phone = decoded.phone;

    const user = db.prepare(
      "SELECT * FROM users WHERE phone = ?"
    ).get(req.phone);

    if (!user) return res.status(401).json({ error: "User not found" });

    if (user.banned_until > Date.now()) {
      return res.status(403).json({
        error: "Banned",
        until: user.banned_until
      });
    }

    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
}

function isCreator(phone) {
  return CREATOR_PHONE && phone === CREATOR_PHONE;
}

// درخواست کد آزمایشی
app.post("/api/request-code", (req, res) => {
  const phone = String(req.body.phone || "").trim();

  if (!/^\+?[0-9]{8,15}$/.test(phone)) {
    return res.status(400).json({ error: "Invalid phone" });
  }

  const code = "123456";
  codes.set(phone, {
    code,
    expires: Date.now() + 5 * 60 * 1000
  });

  // فقط برای آزمایش؛ ارسال پیامک واقعی انجام نمی‌شود.
  res.json({
    success: true,
    demo: true,
    message: "Test code generated",
    code
  });
});

// ورود یا ثبت نام
app.post("/api/verify-code", (req, res) => {
  const phone = String(req.body.phone || "").trim();
  const code = String(req.body.code || "").trim();
  const name = String(req.body.name || "").trim();

  const saved = codes.get(phone);

  if (!saved || saved.code !== code || saved.expires < Date.now()) {
    return res.status(400).json({ error: "Wrong or expired code" });
  }

  codes.delete(phone);

  let user = db.prepare(
    "SELECT * FROM users WHERE phone = ?"
  ).get(phone);

  if (!user) {
    if (!name) {
      return res.status(400).json({
        error: "Name required for new account"
      });
    }

    db.prepare(`
      INSERT INTO users (phone, name, created_at)
      VALUES (?, ?, ?)
    `).run(phone, name, Date.now());

    user = db.prepare(
      "SELECT * FROM users WHERE phone = ?"
    ).get(phone);
  }

  res.json({
    success: true,
    token: token(phone),
    user: {
      phone: user.phone,
      name: user.name,
      role: isCreator(phone) ? "creator" : "user"
    }
  });
});

// اطلاعات حساب
app.get("/api/me", auth, (req, res) => {
  const user = db.prepare(
    "SELECT phone, name FROM users WHERE phone = ?"
  ).get(req.phone);

  res.json({
    ...user,
    role: isCreator(req.phone) ? "creator" : "user"
  });
});

// تغییر نام
app.post("/api/profile", auth, (req, res) => {
  const name = String(req.body.name || "").trim();

  if (!name || name.length > 40) {
    return res.status(400).json({ error: "Invalid name" });
  }

  db.prepare("UPDATE users SET name = ? WHERE phone = ?")
    .run(name, req.phone);

  res.json({ success: true, name });
});

// دریافت پیام‌ها
app.get("/api/messages/:phone", auth, (req, res) => {
  const other = String(req.params.phone);

  const messages = db.prepare(`
    SELECT * FROM messages
    WHERE (sender = ? AND receiver = ?)
       OR (sender = ? AND receiver = ?)
    ORDER BY id ASC LIMIT 200
  `).all(req.phone, other, other, req.phone);

  res.json(messages);
});

// ارسال پیام
app.post("/api/messages", auth, (req, res) => {
  const receiver = String(req.body.receiver || "").trim();
  const message = String(req.body.message || "").trim();

  if (!receiver || !message || message.length > 3000) {
    return res.status(400).json({ error: "Invalid message" });
  }

  const target = db.prepare(
    "SELECT phone FROM users WHERE phone = ?"
  ).get(receiver);

  if (!target) {
    return res.status(404).json({ error: "User not found" });
  }

  const result = db.prepare(`
    INSERT INTO messages
    (sender, receiver, message, created_at)
    VALUES (?, ?, ?, ?)
  `).run(req.phone, receiver, message, Date.now());

  const data = {
    id: result.lastInsertRowid,
    sender: req.phone,
    receiver,
    message,
    created_at: Date.now()
  };

  io.to(receiver).emit("new_message", data);

  res.json({ success: true, message: data });
});

// پنل سازنده: فهرست کاربران
app.get("/api/creator/users", auth, (req, res) => {
  if (!isCreator(req.phone)) {
    return res.status(403).json({ error: "Creator only" });
  }

  const users = db.prepare(`
    SELECT phone, name, banned_until, created_at
    FROM users
  `).all();

  res.json(users);
});

// بن کاربر توسط سازنده
app.post("/api/creator/ban", auth, (req, res) => {
  if (!isCreator(req.phone)) {
    return res.status(403).json({ error: "Creator only" });
  }

  const phone = String(req.body.phone || "");
  const hours = Number(req.body.hours);

  if (!Number.isFinite(hours) || hours < 0 || hours > 8760) {
    return res.status(400).json({ error: "Invalid hours" });
  }

  const user = db.prepare(
    "SELECT phone FROM users WHERE phone = ?"
  ).get(phone);

  if (!user) return res.status(404).json({ error: "User not found" });

  const until = hours === 0 ? 0 : Date.now() + hours * 3600000;

  db.prepare(
    "UPDATE users SET banned_until = ? WHERE phone = ?"
  ).run(until, phone);

  res.json({ success: true, banned_until: until });
});

// بررسی سلامت سرور
app.get("/", (req, res) => {
  res.json({
    app: "ALPHA MESSAGE",
    status: "online",
    version: "1.0.0"
  });
});

const io = new Server(server, {
  cors: { origin: "*" }
});

io.use((socket, next) => {
  try {
    const decoded = jwt.verify(socket.handshake.auth.token, SECRET);
    socket.phone = decoded.phone;
    next();
  } catch {
    next(new Error("Unauthorized"));
  }
});

io.on("connection", socket => {
  socket.join(socket.phone);
  online.set(socket.phone, socket.id);

  io.emit("online_users", [...online.keys()]);

  socket.on("disconnect", () => {
    online.delete(socket.phone);
    io.emit("online_users", [...online.keys()]);
  });
});

server.listen(PORT, "0.0.0.0", () => {
  console.log("ALPHA MESSAGE server running on port " + PORT);
});

