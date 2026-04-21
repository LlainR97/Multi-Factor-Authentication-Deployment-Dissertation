require('dotenv').config();
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
const PORT = process.env.PORT || 4000;

app.use(cors());
app.use(bodyParser.json());

// Initialize SQLite database
const db = new sqlite3.Database('./database.db');

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    password TEXT,
    verified INTEGER DEFAULT 0,
    email_code TEXT,
    totp_secret TEXT,
    participant_code TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
});

// Email transporter setup
let transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: process.env.SMTP_PORT,
  secure: false, // true for 465, false for other ports
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

// ---------------- Registration ----------------
app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.json({ success: false, message: "Email and password required" });

  const hashedPassword = await bcrypt.hash(password, 10);
  const emailCode = Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit code

  db.run(`INSERT INTO users (email, password, email_code) VALUES (?, ?, ?)`,
    [email, hashedPassword, emailCode], (err) => {
      if (err) {
        return res.json({ success: false, message: "User already exists" });
      }

      // Send email code
      let mailOptions = {
        from: process.env.FROM_EMAIL,
        to: email,
        subject: 'Your Verification Code - MFA Research Study',
        text: `Thank you for participating in this research study.\n\nYour verification code is: ${emailCode}\n\nThis code will expire in 10 minutes.`
      };

transporter.sendMail(mailOptions, (error, info) => {
  if (error) {
    console.log('Email error:', error);
    return res.json({ success: false, message: "Failed to send email. Please try again." });
  }
  console.log('Email sent:', info.response);
  res.json({ success: true, message: "Account created! Verification code sent to email." });
});
    });
});

// ---------------- Email Verification ----------------
app.post('/verify-email', (req, res) => {
  const { email, code } = req.body;
  db.get(`SELECT * FROM users WHERE email = ?`, [email], (err, row) => {
    if (!row) return res.json({ success: false, message: "User not found" });
    if (row.verified) return res.json({ success: false, message: "Already verified" });

    if (row.email_code === code) {
      const totpSecret = speakeasy.generateSecret({ length: 20 }).base32;
      db.run(`UPDATE users SET verified = 1, totp_secret = ? WHERE email = ?`, [totpSecret, email]);
      res.json({ success: true, message: "Email verified! Proceed to TOTP setup." });
    } else {
      res.json({ success: false, message: "Incorrect code" });
    }
  });
});

// ---------------- TOTP Setup (QR code) ----------------
app.get('/totp-setup', (req, res) => {
  const email = req.query.email;
  db.get(`SELECT totp_secret FROM users WHERE email = ?`, [email], (err, row) => {
    if (!row || !row.totp_secret) return res.json({ qr: null });

    const otpAuthUrl = `otpauth://totp/MFA-Research:${email}?secret=${row.totp_secret}&issuer=MFA-Research`;
    qrcode.toDataURL(otpAuthUrl, (err, qr) => {
      res.json({ qr });
    });
  });
});

// ---------------- TOTP Verification ----------------
app.post('/login-totp', (req, res) => {
  const { email, totp } = req.body;
  db.get(`SELECT totp_secret FROM users WHERE email = ?`, [email], (err, row) => {
    if (!row) return res.json({ success: false, message: "User not found" });

    const verified = speakeasy.totp.verify({
      secret: row.totp_secret,
      encoding: 'base32',
      token: totp,
      window: 2 // Allow 1 minute before/after for clock skew
    });

    if (verified) {
      const participantCode = 'P' + Math.floor(100000 + Math.random() * 900000).toString();
      db.run(`UPDATE users SET participant_code = ? WHERE email = ?`, [participantCode, email]);
      res.json({ success: true, message: "TOTP verified! Logged in successfully." });
    } else {
      res.json({ success: false, message: "Invalid TOTP code" });
    }
  });
});

// ---------------- Unique Participant Code ----------------
app.get('/unique-code', (req, res) => {
  const email = req.query.email;
  db.get(`SELECT participant_code FROM users WHERE email = ?`, [email], (err, row) => {
    if (!row) return res.json({ code: "Not found" });
    res.json({ code: row.participant_code });
  });
});

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
