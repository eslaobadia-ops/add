const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { PrismaClient } = require("@prisma/client");

const app = express();
const prisma = new PrismaClient();

app.use(express.json());

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "SUPER_SECRET_KEY";

// 🔒 HARD-CODED ADMIN (UNCHANGEABLE)
const ADMIN_USERNAME = "Esla Obadiah";
const ADMIN_PASSWORD = "eslaobadiah";

/* =========================
   ADMIN AUTO-CREATE
========================= */
async function ensureAdmin() {
  const admin = await prisma.user.findUnique({
    where: { username: ADMIN_USERNAME },
  });

  if (!admin) {
    const hashedPassword = await bcrypt.hash(ADMIN_PASSWORD, 10);
    await prisma.user.create({
      data: {
        username: ADMIN_USERNAME,
        password: hashedPassword,
        role: "admin",
      },
    });
    console.log("✅ Admin account created");
  } else {
    console.log("✅ Admin already exists");
  }
}

/* =========================
   AUTH MIDDLEWARE
========================= */
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ message: "No token" });

  const token = header.split(" ")[1];
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(403).json({ message: "Invalid token" });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({ message: "Admins only" });
  }
  next();
}

/* =========================
   REGISTER
========================= */
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  const exists = await prisma.user.findUnique({ where: { username } });
  if (exists) return res.status(400).json({ message: "User exists" });

  const hashed = await bcrypt.hash(password, 10);

  const user = await prisma.user.create({
    data: {
      username,
      password: hashed,
      role: "student",
    },
  });

  res.json({ message: "Registered successfully", userId: user.id });
});

/* =========================
   LOGIN (ADMIN + USERS)
========================= */
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const user = await prisma.user.findUnique({ where: { username } });
  if (!user) return res.status(401).json({ message: "Invalid login" });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(401).json({ message: "Invalid login" });

  const token = jwt.sign(
    { id: user.id, role: user.role },
    JWT_SECRET,
    { expiresIn: "1d" }
  );

  res.json({ token, role: user.role });
});

/* =========================
   ADMIN: VIEW USERS
========================= */
app.get("/admin/users", auth, adminOnly, async (req, res) => {
  const users = await prisma.user.findMany({
    select: { id: true, username: true, role: true, paid: true },
  });
  res.json(users);
});

/* =========================
   HEALTH CHECK (IMPORTANT)
========================= */
app.get("/", (req, res) => {
  res.send("✅ Jaycrest School Backend is LIVE");
});

/* =========================
   START SERVER
========================= */
app.listen(PORT, async () => {
  await ensureAdmin();
  console.log(`🚀 Server running on port ${PORT}`);
});
