-- users
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  email_verified INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  totp_secret TEXT NULL
);

-- email codes
CREATE TABLE IF NOT EXISTS email_codes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  code TEXT,
  expires_at DATETIME,
  FOREIGN KEY(user_id) REFERENCES users(id)
);

-- login metrics
CREATE TABLE IF NOT EXISTS login_metrics (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  login_start DATETIME,
  login_end DATETIME,
  duration_ms INTEGER,
  mfa_method TEXT,
  unique_code TEXT,
  questionnaire_json TEXT,
  FOREIGN KEY(user_id) REFERENCES users(id)
);
