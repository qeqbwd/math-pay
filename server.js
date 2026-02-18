import express from "express";
import dotenv from "dotenv";
import cookieParser from "cookie-parser";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import QRCode from "qrcode";
import { nanoid } from "nanoid";
import Database from "better-sqlite3";

dotenv.config();
const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(express.static("public"));

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "change_this_secret";

const db = new Database("app.db");

db.exec(`
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  pass_hash TEXT
);
CREATE TABLE IF NOT EXISTS unlocks(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT,
  problem_num TEXT,
  UNIQUE(username,problem_num)
);
CREATE TABLE IF NOT EXISTS orders(
  order_id TEXT PRIMARY KEY,
  username TEXT,
  problem_num TEXT,
  status TEXT
);
`);

function sign(username) {
  return jwt.sign({ username }, JWT_SECRET, { expiresIn: "7d" });
}

function auth(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ message: "未登录" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ message: "登录失效" });
  }
}

app.post("/api/auth/register", (req, res) => {
  const { username, password } = req.body;
  const hash = bcrypt.hashSync(password, 10);
  try {
    db.prepare("INSERT INTO users(username,pass_hash) VALUES(?,?)")
      .run(username, hash);
  } catch {
    return res.status(400).json({ message: "用户已存在" });
  }
  res.cookie("token", sign(username), { httpOnly: true });
  res.json({ ok: true });
});

app.post("/api/auth/login", (req, res) => {
  const { username, password } = req.body;
  const u = db.prepare("SELECT * FROM users WHERE username=?")
    .get(username);
  if (!u || !bcrypt.compareSync(password, u.pass_hash))
    return res.status(401).json({ message: "账号或密码错误" });
  res.cookie("token", sign(username), { httpOnly: true });
  res.json({ ok: true });
});

app.get("/api/auth/me", (req, res) => {
  const token = req.cookies.token;
  if (!token) return res.json({ loggedIn: false });
  try {
    const u = jwt.verify(token, JWT_SECRET);
    res.json({ loggedIn: true, username: u.username });
  } catch {
    res.json({ loggedIn: false });
  }
});

app.get("/api/user/unlocked", auth, (req, res) => {
  const rows = db.prepare("SELECT problem_num FROM unlocks WHERE username=?")
    .all(req.user.username);
  res.json({ unlocked: rows.map(r => r.problem_num) });
});

app.post("/api/pay/create", auth, async (req, res) => {
  const { problemNum } = req.body;
  const orderId = "O" + Date.now() + "_" + nanoid(6);

  db.prepare("INSERT INTO orders VALUES(?,?,?,?)")
    .run(orderId, req.user.username, problemNum, "pending");

  const payUrl = `${req.protocol}://${req.get("host")}/api/pay/mock?o=${orderId}`;
  const qr = await QRCode.toDataURL(payUrl);

  res.json({ orderId, qrImgUrl: qr });
});

app.get("/api/pay/status", auth, (req, res) => {
  const o = db.prepare("SELECT * FROM orders WHERE order_id=?")
    .get(req.query.orderId);
  if (!o) return res.json({ status: "closed" });
  res.json({ status: o.status });
});

app.get("/api/pay/mock", (req, res) => {
  const o = db.prepare("SELECT * FROM orders WHERE order_id=?")
    .get(req.query.o);
  if (!o) return res.send("订单不存在");

  db.prepare("UPDATE orders SET status='paid' WHERE order_id=?")
    .run(req.query.o);

  db.prepare("INSERT OR IGNORE INTO unlocks(username,problem_num) VALUES(?,?)")
    .run(o.username, o.problem_num);

  res.send("模拟支付成功，可以返回页面查看解锁状态");
});

app.listen(PORT, () => {
  console.log("Server running on port " + PORT);
});
