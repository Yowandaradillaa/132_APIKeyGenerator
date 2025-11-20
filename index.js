// index.js
const express = require("express");
const cors = require("cors");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3001;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// ========== DATABASE ==========
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "12345",
  database: "apikey_manager"
});

db.connect((err) => {
  if (err) {
    console.error("DB connect error:", err);
    process.exit(1);
  }
  console.log("✅ Connected to MySQL");
});

// ========== ROUTES ==========

// Generate API key
app.post("/generate-key", (req, res) => {
  const key = crypto.randomBytes(24).toString("hex");
  return res.json({ success: true, apikey: key });
});

// Register: save apikey → user
app.post("/register", (req, res) => {
  const { first_name, last_name, apikey } = req.body;

  if (!first_name || !last_name || !apikey) {
    return res.json({ success: false, message: "first_name, last_name and apikey required" });
  }

  const q1 = "INSERT INTO apikeys (apikey) VALUES (?)";
  db.execute(q1, [apikey], (err1, result1) => {
    if (err1) {
      console.error("Insert apikey error:", err1);
      return res.json({ success: false, message: "DB error (apikey)" });
    }

    const apikey_id = result1.insertId;

    const q2 = "INSERT INTO users (first_name, last_name, apikey_id) VALUES (?, ?, ?)";
    db.execute(q2, [first_name, last_name, apikey_id], (err2) => {
      if (err2) {
        console.error("Insert user error:", err2);

        // rollback apikey
        db.execute("DELETE FROM apikeys WHERE apikey_id = ?", [apikey_id], () => {
          return res.json({ success: false, message: "DB error (user)" });
        });
      } else {
        return res.json({ success: true, message: "User and API key created", apikey });
      }
    });
  });
});

app.post("/admin/register", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.json({ success: false, message: "Email dan password wajib." });
  }

  const hashed = await bcrypt.hash(password, 10);

  db.query(
    "INSERT INTO admin (email, password) VALUES (?, ?)",
    [email, hashed],
    (err) => {
      if (err) return res.json({ success: false, message: "Email sudah terdaftar atau error." });
      res.json({ success: true, message: "Admin registered." });
    }
  );
});


// ========== ADMIN LOGIN (dengan auto-hash) ==========
app.post("/admin/login", (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) 
    return res.json({ success: false, message: "email & password required" });

  db.execute("SELECT * FROM admin WHERE email = ?", [email], async (err, results) => {
    if (err) return res.json({ success: false, message: "DB error" });

    if (!results || results.length === 0)
      return res.json({ success: false, message: "Admin not found" });

    const admin = results[0];

    // cek apakah password DB sudah hash atau masih plaintext
    const isHashed = admin.password.startsWith("$2");

    if (!isHashed) {
      // kalau plaintext → hash + simpan ke DB
      const newHash = await bcrypt.hash(admin.password, 10);

      db.execute("UPDATE admin SET password = ? WHERE id = ?", [newHash, admin.id], (err2) => {
        if (err2) console.error("Auto-hash update error:", err2);
      });

      admin.password = newHash;
    }

    // compare password input dengan hash
    const match = await bcrypt.compare(password, admin.password);
    if (!match) return res.json({ success: false, message: "Wrong password" });

    return res.json({
      success: true,
      admin: { id: admin.id, email: admin.email }
    });
  });
});



// Get all users
app.get("/users", (req, res) => {
  const q = `
    SELECT u.id, u.first_name, u.last_name, a.apikey_id, a.apikey, a.out_of_date
    FROM users u
    LEFT JOIN apikeys a ON u.apikey_id = a.apikey_id
    ORDER BY u.id ASC
  `;

  db.execute(q, (err, results) => {
    if (err) return res.json([]);

    const out = results.map(r => ({
      id: r.id,
      first_name: r.first_name,
      last_name: r.last_name,
      apikey_id: r.apikey_id,
      apikey_value: r.apikey,
      status: r.out_of_date ? "inactive" : "active"
    }));
    res.json(out);
  });
});

// Delete user + apikey
app.delete("/users/:id", (req, res) => {
  const id = Number(req.params.id);
  if (!id) return res.json({ success: false });

  db.execute("SELECT apikey_id FROM users WHERE id = ?", [id], (err, rows) => {
    if (err) return res.json({ success: false });

    const apikey_id = rows.length ? rows[0].apikey_id : null;

    db.execute("DELETE FROM users WHERE id = ?", [id], () => {
      if (apikey_id) {
        db.execute("DELETE FROM apikeys WHERE apikey_id = ?", [apikey_id], () => {
          return res.json({ success: true });
        });
      } else {
        return res.json({ success: true });
      }
    });
  });
});

// Toggle apikey active/inactive
app.post("/apikeys/:id/toggle", (req, res) => {
  const id = Number(req.params.id);
  if (!id) return res.json({ success: false });

  db.execute("SELECT out_of_date FROM apikeys WHERE apikey_id = ?", [id], (err, rows) => {
    if (err || !rows.length) return res.json({ success: false });

    const current = rows[0].out_of_date ? 1 : 0;
    const next = current ? 0 : 1;

    db.execute("UPDATE apikeys SET out_of_date = ? WHERE apikey_id = ?", [next, id], (err2) => {
      if (err2) return res.json({ success: false });
      return res.json({ success: true, new_status: next ? "inactive" : "active" });
    });
  });
});

// serve index.html
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Start server
app.listen(PORT, () => console.log(`Backend running on http://localhost:${PORT}`));
