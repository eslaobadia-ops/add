const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { PrismaClient } = require("@prisma/client");

const app = express();
const prisma = new PrismaClient();

/* ================== CONFIG ================== */
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "SUPER_SECRET_JWT_KEY";

/* HARD-CODED ADMIN (UNCHANGEABLE) */
const ADMIN_USERNAME = "Esla Obadiah";
const ADMIN_PASSWORD = "eslaobadiah";

/* ================== MIDDLEWARE ================== */
app.use(express.json());

app.use(
  cors({
    origin: "*", // allows any frontend
    methods: ["GET", "POST"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

/* ================== ADMIN SEED ================== */
async function ensureAdmin() {
  const admin = await prisma.user.findUnique({
    where: { username: ADMIN_USERNAME },
  });

  if (!admin) {
    const hashed = await bcrypt.hash(ADMIN_PASSWORD, 10);
    await prisma.user.create({
      data: {
        username: ADMIN_USERNAME,
        password: hashed,
        role: "ADMIN",
      },
    });
    console.log("✅ Admin account created");
  } else {
    console.log("ℹ️ Admin already exists");
  }
}

/* ================== AUTH MIDDLEWARE ================== */
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ message: "No token" });

  const token = header.split(" ")[1];
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ message: "Invalid token" });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== "ADMIN") {
    return res.status(403).json({ message: "Admin only" });
  }
  next();
}

/* ================== ROUTES ================== */

app.get("/", (req, res) => {
  res.json({ status: "Backend running" });
});

/* REGISTER */
app.post("/register", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password)
      return res.status(400).json({ message: "Missing fields" });

    const exists = await prisma.user.findUnique({ where: { username } });
    if (exists)
      return res.status(400).json({ message: "User already exists" });

    const hashed = await bcrypt.hash(password, 10);
    const user = await prisma.user.create({
      data: { username, password: hashed },
    });

    res.json({
      message: "Registration successful",
      userId: user.id,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* LOGIN */
app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await prisma.user.findUnique({ where: { username } });

    if (!user) return res.status(401).json({ message: "Invalid credentials" });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ message: "Invalid credentials" });

    const token = jwt.sign(
      { id: user.id, role: user.role },
      JWT_SECRET,
      { expiresIn: "1d" }
    );

    res.json({
      message: "Login successful",
      token,
      role: user.role,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* ADMIN ONLY TEST */
app.get("/admin", auth, adminOnly, (req, res) => {
  res.json({ message: "Welcome Admin 👑" });
});

/* ================== START SERVER ================== */
app.listen(PORT, async () => {
  await ensureAdmin();
  console.log(`🚀 Server running on port ${PORT}`);
});
