PRAGMA journal_mode = WAL;

-- Auth data (contains email). This is TEMPORARY and will be deleted after success.
CREATE TABLE IF NOT EXISTS auth_records (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  mfa_method TEXT NOT NULL,           -- 'EMAIL' or 'TOTP'
  otp_hash TEXT,                      -- for EMAIL option (hashed)
  otp_expires_at INTEGER,             -- unix ms
  totp_secret_enc TEXT,               -- for TOTP option (encrypted)
  created_at INTEGER NOT NULL
);

-- Research dataset (anonymous). NO EMAIL here.
CREATE TABLE IF NOT EXISTS research_records (
  participant_id TEXT PRIMARY KEY,     -- UUID
  completion_code TEXT NOT NULL,        -- short code shown to user
  mfa_method TEXT NOT NULL,             -- 'EMAIL' or 'TOTP'
  signup_started_at INTEGER NOT NULL,
  signup_completed_at INTEGER,
  verify_started_at INTEGER,
  verify_completed_at INTEGER,
  created_at INTEGER NOT NULL
);
