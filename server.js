import express from "express";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import pg from "pg";
import path from "node:path";
import { fileURLToPath } from "node:url";

const { Pool } = pg;
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3000;
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false });

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "30kb" }));
app.use("/api/auth", rateLimit({ windowMs: 15 * 60 * 1000, limit: 10 }));
app.use(express.static(path.join(__dirname, "public")));

async function init() {
  if (!process.env.DATABASE_URL) {
    console.warn("DATABASE_URL is missing. Add a PostgreSQL database before deploying.");
    return;
  }
  await pool.query(`
    CREATE TABLE IF NOT EXISTS admins (
      id SERIAL PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS questions (
      id SERIAL PRIMARY KEY, question TEXT NOT NULL,
      options JSONB NOT NULL, correct_index INTEGER NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS profiles (
      id TEXT PRIMARY KEY, nickname TEXT NOT NULL DEFAULT 'بازیکن',
      card_last4 TEXT, updated_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS scores (
      id BIGSERIAL PRIMARY KEY, profile_id TEXT NOT NULL,
      score INTEGER NOT NULL, total INTEGER NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  const email = process.env.ADMIN_EMAIL;
  const password = process.env.ADMIN_PASSWORD;
  if (email && password) {
    const existing = await pool.query("SELECT id FROM admins WHERE email=$1", [email.toLowerCase()]);
    if (!existing.rowCount) {
      const hash = await bcrypt.hash(password, 12);
      await pool.query("INSERT INTO admins(email,password_hash) VALUES($1,$2)", [email.toLowerCase(), hash]);
      console.log("Initial admin created.");
    }
  }
  const count = await pool.query("SELECT COUNT(*)::int AS n FROM questions");
  if (count.rows[0].n === 0) {
    const seed = [
      ["پایتخت ایران کدام شهر است؟", ["تهران", "اصفهان", "شیراز", "تبریز"], 0],
      ["کدام سیاره به سیاره سرخ معروف است؟", ["زهره", "مریخ", "مشتری", "عطارد"], 1],
      ["حاصل ۷ × ۸ چند است؟", ["۵۴", "۵۶", "۶۴", "۴۸"], 1]
    ];
    for (const q of seed) await pool.query(
      "INSERT INTO questions(question,options,correct_index) VALUES($1,$2,$3)", [q[0], JSON.stringify(q[1]), q[2]]
    );
  }
}

function requireAdmin(req, res, next) {
  const token = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  try {
    const data = jwt.verify(token, process.env.JWT_SECRET || "");
    if (data.role !== "admin") throw new Error("role");
    req.admin = data;
    next();
  } catch { res.status(401).json({ error: "ورود مدیر لازم است." }); }
}

app.get("/api/health", (_req, res) => res.json({ ok: true, app: "GOLD QUIZ" }));

app.post("/api/auth/login", async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    const result = await pool.query("SELECT * FROM admins WHERE email=$1", [email]);
    if (!result.rowCount || !(await bcrypt.compare(password, result.rows[0].password_hash)))
      return res.status(401).json({ error: "ایمیل یا رمز عبور اشتباه است." });
    const secret = process.env.JWT_SECRET;
    if (!secret) return res.status(500).json({ error: "JWT_SECRET روی سرور تنظیم نشده است." });
    const token = jwt.sign({ role: "admin", email }, secret, { expiresIn: "8h" });
    res.json({ token });
  } catch { res.status(500).json({ error: "خطای سرور یا پایگاه داده." }); }
});

app.get("/api/questions", async (_req, res) => {
  try {
    const result = await pool.query("SELECT id,question,options FROM questions ORDER BY id");
    res.json(result.rows);
  } catch { res.status(503).json({ error: "پایگاه داده هنوز تنظیم نشده است." }); }
});

app.post("/api/profile", async (req, res) => {
  try {
    const id = String(req.body.id || "").slice(0, 80);
    const nickname = String(req.body.nickname || "بازیکن").trim().slice(0, 40);
    const last4 = String(req.body.cardLast4 || "").replace(/\D/g, "").slice(0, 4);
    if (!id) return res.status(400).json({ error: "شناسه کاربر نامعتبر است." });
    await pool.query(
      `INSERT INTO profiles(id,nickname,card_last4) VALUES($1,$2,$3)
       ON CONFLICT(id) DO UPDATE SET nickname=EXCLUDED.nickname, card_last4=EXCLUDED.card_last4, updated_at=NOW()`,
      [id, nickname || "بازیکن", last4 || null]
    );
    res.json({ ok: true, nickname, cardLast4: last4 || null });
  } catch { res.status(503).json({ error: "پایگاه داده هنوز تنظیم نشده است." }); }
});

app.post("/api/answer", async (req, res) => {
  try {
    const questionId = Number(req.body.questionId);
    const choice = Number(req.body.choice);
    if (!Number.isInteger(questionId) || !Number.isInteger(choice) || choice < 0 || choice > 3)
      return res.status(400).json({ error: "پاسخ نامعتبر است." });
    const result = await pool.query("SELECT correct_index FROM questions WHERE id=$1", [questionId]);
    if (!result.rowCount) return res.status(404).json({ error: "سؤال پیدا نشد." });
    res.json({ correct: result.rows[0].correct_index === choice });
  } catch { res.status(503).json({ error: "بررسی پاسخ انجام نشد." }); }
});

app.post("/api/scores", async (req, res) => {
  try {
    const profileId = String(req.body.profileId || "").slice(0, 80);
    const score = Math.max(0, Math.min(1000, Number(req.body.score) || 0));
    const total = Math.max(1, Math.min(1000, Number(req.body.total) || 1));
    if (!profileId) return res.status(400).json({ error: "شناسه کاربر لازم است." });
    await pool.query("INSERT INTO scores(profile_id,score,total) VALUES($1,$2,$3)", [profileId, score, total]);
    res.json({ ok: true });
  } catch { res.status(503).json({ error: "ذخیره نتیجه انجام نشد." }); }
});

app.get("/api/admin/overview", requireAdmin, async (_req, res) => {
  try {
    const [q, p, s] = await Promise.all([
      pool.query("SELECT COUNT(*)::int AS n FROM questions"),
      pool.query("SELECT COUNT(*)::int AS n FROM profiles"),
      pool.query("SELECT COUNT(*)::int AS n FROM scores")
    ]);
    res.json({ questions: q.rows[0].n, users: p.rows[0].n, games: s.rows[0].n });
  } catch { res.status(503).json({ error: "پایگاه داده در دسترس نیست." }); }
});

app.get("/api/admin/questions", requireAdmin, async (_req, res) => {
  const result = await pool.query("SELECT * FROM questions ORDER BY id DESC");
  res.json(result.rows);
});

app.post("/api/admin/questions", requireAdmin, async (req, res) => {
  const question = String(req.body.question || "").trim().slice(0, 500);
  const options = Array.isArray(req.body.options) ? req.body.options.map(x => String(x).trim().slice(0, 120)) : [];
  const correct = Number(req.body.correctIndex);
  if (!question || options.length !== 4 || options.some(x => !x) || !Number.isInteger(correct) || correct < 0 || correct > 3)
    return res.status(400).json({ error: "سؤال، چهار گزینه و پاسخ صحیح را کامل وارد کنید." });
  const result = await pool.query(
    "INSERT INTO questions(question,options,correct_index) VALUES($1,$2,$3) RETURNING id",
    [question, JSON.stringify(options), correct]
  );
  res.json({ ok: true, id: result.rows[0].id });
});

app.delete("/api/admin/questions/:id", requireAdmin, async (req, res) => {
  await pool.query("DELETE FROM questions WHERE id=$1", [Number(req.params.id)]);
  res.json({ ok: true });
});

app.get("*", (_req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
init().catch(err => console.error("Startup error:", err.message));
app.listen(PORT, () => console.log(`GOLD QUIZ listening on ${PORT}`));
