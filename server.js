import express from "express";
import session from "express-session";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import nodemailer from "nodemailer";
import crypto from "crypto";
import cryptoRandomString from "crypto-random-string";
import speakeasy from "speakeasy";
import QRCode from "qrcode";
import { v4 as uuidv4 } from "uuid";
import Database from "better-sqlite3";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// ---------- Config ----------
const PORT = process.env.PORT || 8080;
const SESSION_SECRET = process.env.SESSION_SECRET || "4JhkP40weqev4eeMkQv11bz4ZGuWgssPPc/yaqaEOE0=";
const APP_BASE_URL = process.env.APP_BASE_URL || `https://mfa.cybersandbox.org`;
const DATA_ENCRYPTION_KEY = process.env.DATA_ENCRYPTION_KEY || "ab//Vio0zD9flpP3dt9yA/XbCNQpewl3tfSiWU9tKEI";

app.set("trust proxy", 1);
// ---------- Security middleware ----------
app.use(helmet({
	contentSecurityPolicy: {
	   directives: {
	     defaultSrc: ["'self'"],
             scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
	     styleSrc: ["'self'", "'unsafe-inline'", "'https:"],
             imgSrc: ["'self'", "data:", "https"],
	     connectSrc: ["'self'","data:", "https:"],
  	     fontSrc: ["'self'", "data:", "https:"],
	     frameSrc: ["'self'", "https:"],
             objectSrc: ["'none'"],
	     objectSrc: ["'self'"],
             formAction: ["'self'"],
	    // upgradeInsecureRequests: null,
	   },
	 },
       }));

 // contentSecurityPolicy: false // CSP temporarily disbaled but will be enabled for project going live
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

app.use(session({
  name: "mfa_study_sid",
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: true // once domain is live change to true over encrpyted HTTPS
  }
}));

// Rate limit login/verify endpoints
const authLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10
});

// ---------- Views ----------
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use((req, res, next) => {
  res.locals.baseUrl = APP_BASE_URL;
  next();
});

// ---------- Database ----------
const db = new Database(path.join(__dirname, "study.db")); //creates the database file called study.db
const schema = `
${await (async () => {
  // where the scehma.sql database will be loaded
  // Creation of tables
  return `
  PRAGMA journal_mode = WAL;

  CREATE TABLE IF NOT EXISTS auth_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    mfa_method TEXT NOT NULL,
    otp_hash TEXT,
    otp_expires_at INTEGER,
    totp_secret_enc TEXT,
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS research_records (
    participant_id TEXT PRIMARY KEY,
    completion_code TEXT NOT NULL,
    mfa_method TEXT NOT NULL,
    signup_started_at INTEGER NOT NULL,
    signup_completed_at INTEGER,
    verify_started_at INTEGER,
    verify_completed_at INTEGER,
    completion_status TEXT DEFAULT 'COMPLETED',
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS questionnaire_responses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  participant_id TEXT NOT NULL,
  completion_code TEXT NOT NULL,
  submitted_at INTEGER NOT NULL,

  q2_age_group TEXT NOT NULL,
  q3_gender TEXT NOT NULL,
  q4_computer_confidence TEXT NOT NULL,
  q5_ease TEXT NOT NULL,
  q6_mfa_familiarity TEXT NOT NULL,
  q7_mfa_security TEXT,
  q8_mfa_trust TEXT NOT NULL,
  q9_problems TEXT,
  q10_duration_feel TEXT NOT NULL,
  q11_satisfaction TEXT NOT NULL,
  q12_recommend TEXT NOT NULL,
  q13_comments TEXT,

  UNIQUE(participant_id)
);
  `;
})()}
`;
db.exec(schema);

// Auth record cleanup (GDPR)
// -----------------------------
function cleanupAuthRecords() {
  const cutoff = Date.now() - (20 * 60 * 1000); // 30 minutes
  db.prepare(
    "DELETE FROM auth_records WHERE created_at < ?"
  ).run(cutoff);
}

// Run cleanup on every request
app.use((req, res, next) => {
  cleanupAuthRecords();
  next();
});

// Prepared statements
const stmtInsertAuth = db.prepare(`
  INSERT INTO auth_records (email, password_hash, mfa_method, otp_hash, otp_expires_at, totp_secret_enc, created_at)
  VALUES (@email, @password_hash, @mfa_method, @otp_hash, @otp_expires_at, @totp_secret_enc, @created_at)
`);
const stmtGetAuthById = db.prepare(`SELECT * FROM auth_records WHERE id = ?`);
const stmtUpdateAuthOtp = db.prepare(`UPDATE auth_records SET otp_hash=?, otp_expires_at=? WHERE id=?`);
const stmtUpdateAuthTotpSecret = db.prepare(`UPDATE auth_records SET totp_secret_enc=? WHERE id=?`);
const stmtDeleteAuthById = db.prepare(`DELETE FROM auth_records WHERE id = ?`);

const stmtInsertResearch = db.prepare(`
  INSERT INTO research_records (participant_id, completion_code, mfa_method, signup_started_at, created_at)
  VALUES (@participant_id, @completion_code, @mfa_method, @signup_started_at, @created_at)
`);
const stmtUpdateResearchSignupComplete = db.prepare(`
  UPDATE research_records SET signup_completed_at=? WHERE participant_id=?
`);
const stmtUpdateResearchVerifyStarted = db.prepare(`
  UPDATE research_records SET verify_started_at=? WHERE participant_id=?
`);
const stmtUpdateResearchVerifyComplete = db.prepare(`
  UPDATE research_records SET verify_completed_at=? WHERE participant_id=?
`);
const stmtGetResearch = db.prepare(`SELECT * FROM research_records WHERE participant_id=?`);

// ---------- Helper: randomise A/B ----------
function assignMfaMethod(req) {
  if (!req.session.mfa_method) {
    // Randomise assignment (Option A vs Option B)
    req.session.mfa_method = Math.random() < 0.5 ? "EMAIL" : "TOTP";
  }
  return req.session.mfa_method;
}

// ---------- Helper: encryption for TOTP secrets ----------
function encryptText(plain) {
  const iv = crypto.randomBytes(12);
  const key = crypto.createHash("sha256").update(DATA_ENCRYPTION_KEY).digest();
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const enc = Buffer.concat([cipher.update(plain, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, enc]).toString("base64");
}

function decryptText(encB64) {
  const buf = Buffer.from(encB64, "base64");
  const iv = buf.subarray(0, 12);
  const tag = buf.subarray(12, 28);
  const enc = buf.subarray(28);
  const key = crypto.createHash("sha256").update(DATA_ENCRYPTION_KEY).digest();
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  const dec = Buffer.concat([decipher.update(enc), decipher.final()]);
  return dec.toString("utf8");
}

// ---------- Helper: OTP ----------
function generate6DigitCode() {
  // avoid leading zeros issues by padding
  const n = crypto.randomInt(0, 1000000);
  return String(n).padStart(6, "0");
}

async function sendOtpEmail(toEmail, code) {
  const user = process.env.GMAIL_USER;
  const pass = process.env.GMAIL_APP_PASSWORD;
  if (!user || !pass) {
    throw new Error("Missing GMAIL_USER or GMAIL_APP_PASSWORD in .env");
  }

  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: { user, pass }
  });

  await transporter.sendMail({
    from: `"MFA Research Study" <${user}>`,
    to: toEmail,
    subject: "Your 6-digit verification code",
    text: `Your verification code is: ${code}\n\nThis code expires in 10 minutes.`,
  });
}

// ---------- Routes ----------

// Instruction / landing
app.get("/", (req, res) => {
  const method = assignMfaMethod(req);

  // Create anonymous participant + research record at first entry
  if (!req.session.participant_id) {
    const participant_id = uuidv4();
    const completion_code = cryptoRandomString({ length: 10, type: "alphanumeric" }).toUpperCase();

    req.session.participant_id = participant_id;
    req.session.completion_code = completion_code;

    const now = Date.now();
    stmtInsertResearch.run({
      participant_id,
      completion_code,
      mfa_method: method,
      signup_started_at: now,
      created_at: now
    });
  }

res.render("instructions", {
  mfa_method: method
});

});

// Signup form
app.get("/signup", (req, res) => {
  const method = assignMfaMethod(req); 
  console.log("ASSIGNED MFA METHOD:", method, "SESSION:", req.sessionID);
  if (!req.session.participant_id) return res.redirect("/");
  res.render("signup", { method, error: null });
});

app.post("/signup", authLimiter, async (req, res) => {
  const method = assignMfaMethod(req);
  const { email, password } = req.body;

  if (!req.session.participant_id) return res.redirect("/");
  if (!email || !password) {
    return res.render("signup", { method, error: "Please enter an email and password." });
  }

  // Hash password with bcrypt
  const password_hash = await bcrypt.hash(password, 12);

  // Create auth record (contains email) -- SEPARATE from research table
  const now = Date.now();
  const info = stmtInsertAuth.run({
    email: email.trim().toLowerCase(),
    password_hash,
    mfa_method: method,
    otp_hash: null,
    otp_expires_at: null,
    totp_secret_enc: null,
    created_at: now
  });

  // Tie auth record to session only (not stored in research table)
  req.session.auth_record_id = info.lastInsertRowid;

  // mark signup completed in anonymous research table
  stmtUpdateResearchSignupComplete.run(now, req.session.participant_id);

  // proceed based on method
  if (method === "EMAIL") return res.redirect("/verify-email");
  return res.redirect("/setup-totp");
});

// Option A: email verification page
app.get("/verify-email", async (req, res) => {
  if (!req.session.auth_record_id || !req.session.participant_id) return res.redirect("/");
  const auth = stmtGetAuthById.get(req.session.auth_record_id);
  if (!auth) return res.redirect("/");

  // mark verify started once
  const research = stmtGetResearch.get(req.session.participant_id);
  if (research && !research.verify_started_at) {
    stmtUpdateResearchVerifyStarted.run(Date.now(), req.session.participant_id);
  }

  res.render("verify_email", { error: null, info: null });
});

// Send code
app.post("/verify-email/send", authLimiter, async (req, res) => {
  if (!req.session.auth_record_id) return res.redirect("/");
  const auth = stmtGetAuthById.get(req.session.auth_record_id);
  if (!auth) return res.redirect("/");

  try {
    const code = generate6DigitCode();
    const otp_hash = await bcrypt.hash(code, 12);
    const expires = Date.now() + 10 * 60 * 1000;

    stmtUpdateAuthOtp.run(otp_hash, expires, auth.id);
    await sendOtpEmail(auth.email, code);

    res.render("verify_email", { error: null, info: "Code sent. Check your email." });
  } catch (e) {
  console.error("EMAIL SEND ERROR:", e);
  res.render("verify_email", { error: "Failed to send code. Please try again.", info: null });
}
});

// Verify code
app.post("/verify-email/check", authLimiter, async (req, res) => {
  const { code } = req.body;
  if (!req.session.auth_record_id || !req.session.participant_id) return res.redirect("/");
  const auth = stmtGetAuthById.get(req.session.auth_record_id);
  if (!auth) return res.redirect("/");

  if (!code || !auth.otp_hash || !auth.otp_expires_at) {
    return res.render("verify_email", { error: "Please request a code and enter it.", info: null });
  }
  if (Date.now() > auth.otp_expires_at) {
    return res.render("verify_email", { error: "Code expired. Please request a new one.", info: null });
  }

  const ok = await bcrypt.compare(code.trim(), auth.otp_hash);
  if (!ok) {
    return res.render("verify_email", { error: "Incorrect code. Try again.", info: null });
  }

  // success: complete verify metrics
  stmtUpdateResearchVerifyComplete.run(Date.now(), req.session.participant_id);
  db.prepare(`
  UPDATE research_records
  SET completion_status = 'COMPLETED'
  WHERE participant_id = ?
`).run(req.session.participant_id);
  // delete email-containing record (per your requirement)
  stmtDeleteAuthById.run(auth.id);
  req.session.auth_record_id = null;

  res.redirect("/success");
});

// Option B: setup TOTP
app.get("/setup-totp", async (req, res) => {
  if (!req.session.auth_record_id || !req.session.participant_id) return res.redirect("/");
  const auth = stmtGetAuthById.get(req.session.auth_record_id);
  if (!auth) return res.redirect("/");

  // mark verify started once
  const research = stmtGetResearch.get(req.session.participant_id);
  if (research && !research.verify_started_at) {
    stmtUpdateResearchVerifyStarted.run(Date.now(), req.session.participant_id);
  }

  // generate secret if not already stored
  let secret;
  if (auth.totp_secret_enc) {
    secret = decryptText(auth.totp_secret_enc);
  } else {
    secret = speakeasy.generateSecret({
      name: `MFA Research Study (${auth.email})` // authenticator label (visible to participant)
    }).base32;
    const enc = encryptText(secret);
    stmtUpdateAuthTotpSecret.run(enc, auth.id);
  }

  // Create otpauth URL for QR
  const otpauth = speakeasy.otpauthURL({
    secret,
    label: `MFA Research Study`,
    issuer: `MFA Research Study`,
    encoding: "base32"
  });

  const qrDataUrl = await QRCode.toDataURL(otpauth);

  res.render("setup_totp", { qrDataUrl });
});

// Verify TOTP code
app.get("/verify-totp", (req, res) => {
  if (!req.session.auth_record_id || !req.session.participant_id) return res.redirect("/");
  res.render("verify_totp", { error: null });
});

app.post("/verify-totp", authLimiter, async (req, res) => {
  const { code } = req.body;
  if (!req.session.auth_record_id || !req.session.participant_id) return res.redirect("/");
  const auth = stmtGetAuthById.get(req.session.auth_record_id);
  if (!auth || !auth.totp_secret_enc) return res.redirect("/");

  const secret = decryptText(auth.totp_secret_enc);
  const ok = speakeasy.totp.verify({
    secret,
    encoding: "base32",
    token: (code || "").trim(),
    window: 1
  });

  if (!ok) {
    return res.render("verify_totp", { error: "Invalid code. Please try again." });
  }

  // success: complete verify metrics
  stmtUpdateResearchVerifyComplete.run(Date.now(), req.session.participant_id);
  
  db.prepare(`
  UPDATE research_records
  SET completion_status = 'COMPLETED'
  WHERE participant_id = ?
`).run(req.session.participant_id);

  // delete email-containing record (per your requirement)
  stmtDeleteAuthById.run(auth.id);
  req.session.auth_record_id = null;

  res.redirect("/success");
});

app.post("/mfa-unable", (req, res) => {
  if (!req.session.participant_id || !req.session.completion_code) {
    return res.redirect("/");
  }

  const method = req.session.mfa_method || "UNKNOWN";
  const now = Date.now();

  db.prepare(`
    UPDATE research_records
    SET verify_started_at = COALESCE(verify_started_at, ?),
        verify_completed_at = ?,
        completion_status = ?
    WHERE participant_id = ?
  `).run(
    now,
    now,
    `UNABLE_${method}`,
    req.session.participant_id
  );

  return res.redirect("/success");
});

app.get("/success", (req, res) => {
  if (!req.session.participant_id || !req.session.completion_code) {
    return res.redirect("/");
  }

  const record = stmtGetResearch.get(req.session.participant_id);

  res.render("success", {
    completion_code: req.session.completion_code,
    error: null,
    info: null,
    completion_status: record?.completion_status || "COMPLETED"
  });
});

app.post("/questionnaire", (req, res) => {
  if (!req.session.participant_id || !req.session.completion_code) {
    return res.redirect("/");
  }

  const participant_id = req.session.participant_id;
  const completion_code = req.session.completion_code;

  // Ensure code matches session (prevents tampering)
  if ((req.body.q1_code || "").trim() !== completion_code) {
    
    const record = stmtGetResearch.get(participant_id);

    return res.render("success", { completion_code, error: "Unique code mismatch. Please refresh the page and try again.", info: null, 
    completion_status: record?.completion_status || "COMPLETED"
    });
  }

  const q2 = (req.body.q2_age_group || "").trim();
  const q3 = (req.body.q3_gender || "").trim();
  const q4 = (req.body.q4_computer_confidence || "").trim();
  const q5 = (req.body.q5_ease || "").trim();
  const q6 = (req.body.q6_mfa_familiarity || "").trim();
  const q7 = (req.body.q7_mfa_security || "").trim();
  const q8 = (req.body.q8_mfa_trust || "").trim();
  const q9 = (req.body.q9_problems || "").trim();
  const q10 = (req.body.q10_duration_feel || "").trim();
  const q11 = (req.body.q11_satisfaction|| "").trim();
  const q12 = (req.body.q12_recommend|| "").trim();
  const q13 = (req.body.q13_comments || "").trim();
  const q14 = (req.body.q14_reason || "").trim();
  const q15 = (req.body.q15_device || "").trim();
  const q16 = (req.body.q16_stage || "").trim();

  const allowedQ2 = new Set(["18-24","25-34","35-44","45-54","55-64","65+"]);
  const allowedQ3 = new Set(["Male","Female"]);
  const allowedQ4 = new Set(["Very Confident","Confident","Neutral","Not very confident","Not confident at all"]);
  const allowedQ5 = new Set(["Extremely easy","Easy","Neutral","Difficult","Very difficult"]);
  const allowedQ6 = new Set(["Very familiar","Somewhat familiar","Heard of it but never used","Not familiar at all"]);
  const allowedQ7 = new Set(["Very Secure","Secure","Neutral","Insecure","Very Insecure"]);
  const allowedQ8 = new Set(["Yes definitely","Probably","Unsure","Probably not","Definitely not"]);
  const allowedQ10 = new Set(["Very Quick","Quick","Average","Slightly long","Too long"]);
  const allowedQ11 = new Set(["Very satisfied","Satisfied","Neutral","Dissatisfied","Very Dissatisfied"]);
  const allowedQ12 = new Set(["Yes","Maybe","No"]);

if (
  !allowedQ2.has(q2) ||
  !allowedQ3.has(q3) ||
  !allowedQ4.has(q4) ||
  !allowedQ5.has(q5) ||
  !allowedQ6.has(q6) ||
  !allowedQ7.has(q7) ||
  !allowedQ8.has(q8) ||
  !allowedQ10.has(q10) ||
  !allowedQ11.has(q11) ||
  !allowedQ12.has(q12)
) {

  const record = stmtGetResearch.get(participant_id);

return res.render("success", {
  completion_code,
  error: "Please complete all required questions.",
  info: null,
  completion_status: record?.completion_status || "COMPLETED"
});
}

try {
  db.prepare(`
    INSERT INTO questionnaire_responses (
      participant_id,
      completion_code,
      submitted_at,
      q2_age_group,
      q3_gender,
      q4_computer_confidence,
      q5_ease,
      q6_mfa_familiarity,
      q7_mfa_security,
      q8_mfa_trust,
      q9_problems,
      q10_duration_feel,
      q11_satisfaction,
      q12_recommend,
      q13_comments,
      q14_reason,
      q15_device,
      q16_stage
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    participant_id,
    completion_code,
    Date.now(),
    q2,
    q3,
    q4,
    q5,
    q6,
    q7,
    q8,
    q9 || null,
    q10,
    q11,
    q12,
    q13 || null,
    q14 || null,
    q15 || null,
    q16 || null,
  );

return res.redirect("/complete");

} catch (e) {
  console.error("QUESTIONNAIRE INSERT ERROR:", e);
  return res.redirect("/complete");
}
});

app.get("/complete", (req, res) => {
  res.render("complete");
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Running on ${APP_BASE_URL}`);
});
