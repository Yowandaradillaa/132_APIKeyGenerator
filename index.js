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

const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "12345",
  database: "apikey_manager"
});

db.connect(err => {
  if (err) {
    console.error("DB connect error:", err);
    process.exit(1);
  }
  console.log("✅ Connected to MySQL");
});

// Generate key
app.post("/generate-key", (req, res) => {
  const key = crypto.randomBytes(24).toString("hex");
  res.json({ success: true, apikey: key });
});

// Register user
app.post("/register", (req, res) => {
  const { first_name, last_name, apikey } = req.body;
  if (!first_name || !last_name || !apikey)
    return res.json({ success: false });

  db.execute(
    "INSERT INTO apikeys (apikey, out_of_date) VALUES (?, 0)",
    [apikey],
    (err1, result1) => {
      if (err1) return res.json({ success: false });

      const apikey_id = result1.insertId;

      db.execute(
        "INSERT INTO users (first_name, last_name, apikey_id) VALUES (?, ?, ?)",
        [first_name, last_name, apikey_id],
        err2 => {
          if (err2) {
            db.execute("DELETE FROM apikeys WHERE apikey_id = ?", [apikey_id]);
            return res.json({ success: false });
          }
          res.json({ success: true });
        }
      );
    }
  );
});

// Register admin
app.post("/admin/register", async (req, res) => {
  const { email, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);

  db.query(
    "INSERT INTO admin (email, password) VALUES (?, ?)",
    [email, hashed],
    err => {
      if (err) return res.json({ success: false });
      res.json({ success: true });
    }
  );
});

app.get("/admin", (req, res) => {
  const sql = "SELECT id, email FROM admin";

  db.query(sql, (err, result) => {
    if (err) return res.status(500).json({ error: err });
    res.json(result);
  });
});


// Login admin
app.post("/admin/login", (req, res) => {
  const { email, password } = req.body;

  db.execute("SELECT * FROM admin WHERE email = ?", [email], async (err, rows) => {
    if (err || rows.length === 0)
      return res.json({ success: false, message: "Email tidak ditemukan" });

    const admin = rows[0];
    const match = await bcrypt.compare(password, admin.password);

    if (!match) return res.json({ success: false, message: "Password salah" });

    res.json({ success: true, admin: { id: admin.id, email: admin.email } });
  });
});

app.delete("/admin/:id", (req, res) => {
  const { id } = req.params;

  const sql = "DELETE FROM admin WHERE id = ?";

  db.query(sql, [id], (err, result) => {
    if (err) return res.status(500).json({ error: err });

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Admin not found" });
    }

    res.json({ message: "Admin deleted successfully" });
  });
});

// Get users + status
app.get("/users", (req, res) => {
  const q = `
    SELECT u.id, u.first_name, u.last_name, a.apikey, a.out_of_date
    FROM users u
    LEFT JOIN apikeys a ON u.apikey_id = a.apikey_id
  `;

  db.execute(q, (err, results) => {
    if (err) return res.json([]);

    res.json(results.map(r => ({
      id: r.id,
      first_name: r.first_name,
      last_name: r.last_name,
      apikey_value: r.apikey,
      out_of_date: r.out_of_date
    })));
  });
});

// Delete user
app.delete("/users/:id", (req, res) => {
  const id = Number(req.params.id);

  db.execute("SELECT apikey_id FROM users WHERE id = ?", [id], (err, row) => {
    if (err || !row.length) return res.json({ success: false });

    const apikey_id = row[0].apikey_id;

    db.execute("DELETE FROM users WHERE id = ?", [id], () => {
      db.execute("DELETE FROM apikeys WHERE apikey_id = ?", [apikey_id], () => {
        res.json({ success: true });
      });
    });
  });
});

// frontend
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public/index.html"));
});

app.listen(PORT, () =>
  console.log(`Server running on http://localhost:${PORT}`)
);
