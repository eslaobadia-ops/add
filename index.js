// ===============================
// IMPORTS
// ===============================
const express = require("express");
const { PrismaClient } = require("@prisma/client");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

// ===============================
// APP & PRISMA
// ===============================
const app = express();
const prisma = new PrismaClient();

// ===============================
// CONFIG
// ===============================
const PORT = 3000;
const JWT_SECRET = "SUPER_SECRET_DO_NOT_SHARE";

// ===============================
// MIDDLEWARE
// ===============================
app.use(express.json());

// ===============================
// HARD-CODED ADMIN (UNCHANGEABLE)
// ===============================
const ADMIN_USERNAME = "Esla Obadiah";
const ADMIN_PASSWORD = "esla_obadiah"; // hard-coded as requested

// ===============================
// AUTH MIDDLEWARE
// ===============================
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "No token provided" });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: "Invalid token" });
    }
    req.user = user;
    next();
  });
}

function adminOnly(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({ message: "Admin access only" });
  }
  next();
}

// ===============================
// TEST ROUTE
// ===============================
app.get("/", (req, res) => {
  res.send("School Backend Running");
});

// ===============================
// ADMIN LOGIN (HARDCODED)
// ===============================
app.post("/admin/login", async (req, res) => {
  const { username, password } = req.body;

  if (
    username !== ADMIN_USERNAME ||
    password !== ADMIN_PASSWORD
  ) {
    return res.status(401).json({ message: "Invalid admin credentials" });
  }

  const token = jwt.sign(
    { username: ADMIN_USERNAME, role: "admin" },
    JWT_SECRET,
    { expiresIn: "1d" }
  );

  res.json({
    message: "Admin login successful",
    token
  });
});

// ===============================
// USER REGISTRATION (STUDENTS)
// ===============================
app.post("/register", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ message: "All fields required" });
    }

    const existingUser = await prisma.user.findUnique({
      where: { username }
    });

    if (existingUser) {
      return res.status(400).json({ message: "Username already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await prisma.user.create({
      data: {
        username,
        password: hashedPassword,
        role: "student",
        paid: false
      }
    });

    res.json({
      message: "Registration successful",
      user: {
        id: user.id,
        username: user.username,
        role: user.role
      }
    });

  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
});

// ===============================
// USER LOGIN (STUDENTS)
// ===============================
app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    const user = await prisma.user.findUnique({
      where: { username }
    });

    if (!user) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign(
      { id: user.id, role: user.role },
      JWT_SECRET,
      { expiresIn: "1d" }
    );

    res.json({
      message: "Login successful",
      token,
      paid: user.paid
    });

  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
});

// ===============================
// ADMIN: VIEW ALL USERS
// ===============================
app.get(
  "/admin/users",
  authenticateToken,
  adminOnly,
  async (req, res) => {
    try {
      const users = await prisma.user.findMany({
        select: {
          id: true,
          username: true,
          role: true,
          paid: true
        }
      });

      res.json(users);
    } catch (error) {
      res.status(500).json({ message: "Server error" });
    }
  }
);

// ===============================
// ADMIN: MARK STUDENT AS PAID
// ===============================
app.put(
  "/admin/mark-paid/:id",
  authenticateToken,
  adminOnly,
  async (req, res) => {
    try {
      const userId = parseInt(req.params.id);

      const user = await prisma.user.update({
        where: { id: userId },
        data: { paid: true }
      });

      res.json({
        message: "Student marked as paid",
        user
      });
    } catch (error) {
      res.status(500).json({ message: "Server error" });
    }
  }
);

// ===============================
// START SERVER
// ===============================
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
// ===============================
// ADMIN: ADD RESULT
// ===============================
app.post(
  "/admin/add-result",
  authenticateToken,
  adminOnly,
  async (req, res) => {
    try {
      const { userId, subject, score } = req.body;

      let grade = "F";
      if (score >= 70) grade = "A";
      else if (score >= 60) grade = "B";
      else if (score >= 50) grade = "C";
      else if (score >= 45) grade = "D";
      else if (score >= 40) grade = "E";

      const result = await prisma.result.create({
        data: {
          subject,
          score,
          grade,
          userId
        }
      });

      res.json({
        message: "Result added",
        result
      });
    } catch (error) {
      res.status(500).json({ message: "Server error" });
    }
  }
);

// ===============================
// STUDENT: VIEW MY RESULTS
// ===============================
app.get(
  "/my-results",
  authenticateToken,
  async (req, res) => {
    try {
      if (req.user.role !== "student") {
        return res.status(403).json({ message: "Students only" });
      }

      const results = await prisma.result.findMany({
        where: { userId: req.user.id }
      });

      res.json(results);
    } catch (error) {
      res.status(500).json({ message: "Server error" });
    }
  }
);
