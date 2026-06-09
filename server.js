require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const nodemailer = require('nodemailer');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const cors = require('cors');
const path = require('path');
const { jsPDF } = require('jspdf');
const { google } = require('googleapis');

const app = express();
const PORT = process.env.PORT || 3000;

// ─── GMAIL OAUTH2 ─────────────────────────────────────────
const GMAIL_CLIENT_ID = process.env.GMAIL_CLIENT_ID;
const GMAIL_CLIENT_SECRET = process.env.GMAIL_CLIENT_SECRET;
const RAILWAY_URL = process.env.RAILWAY_URL || 'https://triangle-rea-production.up.railway.app';
const REDIRECT_URI = RAILWAY_URL + '/auth/google/callback';

const oauth2Client = new google.auth.OAuth2(
  GMAIL_CLIENT_ID,
  GMAIL_CLIENT_SECRET,
  REDIRECT_URI
);

// ─── DATABASE ─────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS courses (
      id TEXT PRIMARY KEY,
      num TEXT, name TEXT, hours TEXT,
      start_date TEXT, end_date TEXT, loc TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS students (
      id TEXT PRIMARY KEY,
      course_id TEXT REFERENCES courses(id) ON DELETE CASCADE,
      name TEXT, license_num TEXT, email TEXT, phone TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY, value TEXT
    );
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE, password TEXT
    );
    CREATE TABLE IF NOT EXISTS gmail_tokens (
      id SERIAL PRIMARY KEY,
      access_token TEXT,
      refresh_token TEXT,
      expiry_date BIGINT,
      updated_at TIMESTAMP DEFAULT NOW()
    );
  `);

  const existing = await pool.query("SELECT * FROM users WHERE username='admin'");
  if (existing.rows.length === 0) {
    const hash = await bcrypt.hash(process.env.ADMIN_PASSWORD || 'triangleREA2024!', 10);
    await pool.query("INSERT INTO users(username,password) VALUES('admin',$1)", [hash]);
  }

  const defaultSettings = {
    school: 'Triangle Real Estate Academy',
    prov: '1642',
    instructor: 'Keith E. Green',
    instCode: '1976',
    addr1: '127 W. Main Street',
    addr2: 'Spring Hope, NC 27882',
    phone: '919-373-3577',
    email: 'keg@trianglerealestateacademy.com',
    web: 'www.trianglerealestateacademy.com'
  };
  for (const [key, value] of Object.entries(defaultSettings)) {
    await pool.query(
      'INSERT INTO settings(key,value) VALUES($1,$2) ON CONFLICT(key) DO NOTHING',
      [key, value]
    );
  }
  console.log('Database initialized successfully');
}

// ─── MIDDLEWARE ───────────────────────────────────────────
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'trea-secret-2024',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 }
}));
app.use(express.static(path.join(__dirname, 'public')));

function requireAuth(req, res, next) {
  if (req.session && req.session.user) return next();
  res.status(401).json({ error: 'Not authenticated' });
}

// ─── HELPERS ──────────────────────────────────────────────
async function getSettings() {
  const result = await pool.query('SELECT key, value FROM settings');
  const s = {};
  result.rows.forEach(r => s[r.key] = r.value);
  return s;
}

function fmtDate(d) {
  if (!d) return '';
  const p = String(d).split('-');
  return p.length === 3 ? p[1] + '/' + p[2] + '/' + p[0] : d;
}

function toNCRECName(n) {
  if (!n) return '';
  const p = n.trim().toUpperCase().split(/\s+/);
  if (p.length === 1) return p[0];
  if (p.length === 2) return p[1] + ', ' + p[0];
  return p[p.length-1] + ', ' + p[0] + ' ' + p.slice(1,-1).join(' ');
}

function ncrecCode(course) {
  if (course.name === 'Prelicense') return 'PRE';
  if (course.name === 'Post-License 301') return '301';
  if (course.name === 'Post-License 302') return '302';
  if (course.name === 'Post-License 303') return '303';
  return course.num || '';
}

// ─── GMAIL OAUTH2 ROUTES ──────────────────────────────────
app.get('/auth/google', requireAuth, (req, res) => {
  const url = oauth2Client.generateAuthUrl({
    access_type: 'offline',
    scope: ['https://www.googleapis.com/auth/gmail.send'],
    prompt: 'consent'
  });
  res.redirect(url);
});

app.get('/auth/google/callback', requireAuth, async (req, res) => {
  const { code } = req.query;
  try {
    const { tokens } = await oauth2Client.getToken(code);
    oauth2Client.setCredentials(tokens);
    await pool.query('DELETE FROM gmail_tokens');
    await pool.query(
      'INSERT INTO gmail_tokens(access_token, refresh_token, expiry_date) VALUES($1,$2,$3)',
      [tokens.access_token, tokens.refresh_token, tokens.expiry_date]
    );
    res.redirect('/?gmail=connected');
  } catch (err) {
    console.error('Gmail OAuth error:', err);
    res.redirect('/?gmail=error');
  }
});

app.get('/api/gmail-status', requireAuth, async (req, res) => {
  const result = await pool.query('SELECT * FROM gmail_tokens LIMIT 1');
  res.json({ connected: result.rows.length > 0 });
});

app.delete('/api/gmail-disconnect', requireAuth, async (req, res) => {
  await pool.query('DELETE FROM gmail_tokens');
  res.json({ success: true });
});

async function getGmailTransporter() {
  const result = await pool.query('SELECT * FROM gmail_tokens LIMIT 1');
  if (!result.rows.length) throw new Error('Gmail not connected. Please connect Gmail first.');
  const tokens = result.rows[0];
  oauth2Client.setCredentials({
    access_token: tokens.access_token,
    refresh_token: tokens.refresh_token,
    expiry_date: tokens.expiry_date
  });
  const accessToken = await oauth2Client.getAccessToken();
  return nodemailer.createTransport({
    service: 'gmail',
    auth: {
      type: 'OAuth2',
      user: process.env.GMAIL_USER || 'keg@trianglerealestateacademy.com',
      clientId: GMAIL_CLIENT_ID,
      clientSecret: GMAIL_CLIENT_SECRET,
      refreshToken: tokens.refresh_token,
      accessToken: accessToken.token
    }
  });
}

// ─── AUTH ROUTES ──────────────────────────────────────────
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const result = await pool.query('SELECT * FROM users WHERE username=$1', [username]);
    if (!result.rows.length) return res.status(401).json({ error: 'Invalid credentials' });
    const valid = await bcrypt.compare(password, result.rows[0].password);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
    req.session.user = { username };
    res.json({ success: true });
  } catch(err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

app.get('/api/me', (req, res) => {
  if (req.session && req.session.user) {
    res.json({ user: req.session.user });
  } else {
    res.status(401).json({ error: 'Not authenticated' });
  }
});

// ─── COURSES ──────────────────────────────────────────────
app.get('/api/courses', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM courses ORDER BY created_at DESC');
    res.json(result.rows.map(r => ({
      id: r.id, num: r.num, name: r.name, hours: r.hours,
      start: r.start_date, end: r.end_date, loc: r.loc
    })));
  } catch(err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/courses', requireAuth, async (req, res) => {
  try {
    const { id, num, name, hours, start, end, loc } = req.body;
    await pool.query(
      'INSERT INTO courses(id,num,name,hours,start_date,end_date,loc) VALUES($1,$2,$3,$4,$5,$6,$7)',
      [id, num, name, hours, start, end, loc]
    );
    res.json({ success: true });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/courses/:id', requireAuth, async (req, res) => {
  try {
    await pool.query('DELETE FROM courses WHERE id=$1', [req.params.id]);
    res.json({ success: true });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

// ─── STUDENTS ─────────────────────────────────────────────
app.get('/api/students', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM students ORDER BY created_at DESC');
    res.json(result.rows.map(r => ({
      id: r.id, cid: r.course_id, name: r.name,
      lic: r.license_num, email: r.email, phone: r.phone
    })));
  } catch(err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/students', requireAuth, async (req, res) => {
  try {
    const { id, cid, name, lic, email, phone } = req.body;
    await pool.query(
      'INSERT INTO students(id,course_id,name,license_num,email,phone) VALUES($1,$2,$3,$4,$5,$6)',
      [id, cid, name, lic, email, phone || '']
    );
    res.json({ success: true });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/students/:id', requireAuth, async (req, res) => {
  try {
    await pool.query('DELETE FROM students WHERE id=$1', [req.params.id]);
    res.json({ success: true });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

// ─── SETTINGS ─────────────────────────────────────────────
app.get('/api/settings', requireAuth, async (req, res) => {
  try {
    const s = await getSettings();
    res.json(s);
  } catch(err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/settings', requireAuth, async (req, res) => {
  try {
    for (const [key, value] of Object.entries(req.body)) {
      await pool.query(
        'INSERT INTO settings(key,value) VALUES($1,$2) ON CONFLICT(key) DO UPDATE SET value=$2',
        [key, value]
      );
    }
    res.json({ success: true });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

// ─── SEND CERTIFICATES ────────────────────────────────────
app.post('/api/send-certificates', requireAuth, async (req, res) => {
  const { courseId, studentIds } = req.body;
  if (!courseId || !studentIds || !studentIds.length) {
    return res.status(400).json({ error: 'Missing courseId or studentIds' });
  }
  try {
    const s = await getSettings();
    const courseResult = await pool.query('SELECT * FROM courses WHERE id=$1', [courseId]);
    if (!courseResult.rows.length) return res.status(404).json({ error: 'Course not found' });
    const course = courseResult.rows[0];
    const studResult = await pool.query(
      'SELECT * FROM students WHERE id = ANY($1::text[])', [studentIds]
    );
    const transporter = await getGmailTransporter();
    const results = { sent: [], failed: [] };
    for (const student of studResult.rows) {
      try {
        const pdfBuffer = generateCertPDFBuffer(student, course, s);
        const emailBody = buildEmailBody(student, course);
        await transporter.sendMail({
          from: `"${s.school}" <${process.env.GMAIL_USER || s.email}>`,
          to: student.email,
          subject: `Certificate of Completion — ${course.name} — Triangle Real Estate Academy`,
          text: emailBody,
          attachments: [{
            filename: student.name.replace(/[^a-zA-Z0-9]/g,'_') + '_Certificate.pdf',
            content: pdfBuffer,
            contentType: 'application/pdf'
          }]
        });
        results.sent.push(student.name);
      } catch(err) {
        console.error('Failed:', student.name, err.message);
        results.failed.push({ name: student.name, error: err.message });
      }
    }
    res.json(results);
  } catch(err) {
    res.status(500).json({ error: err.message });
  }
});

function buildEmailBody(student, course) {
  return `Dear ${student.name},\n\nGreetings,\n\nCongratulations on completing your course! Attached is your certificate of completion. If you have any questions, please do not hesitate to contact me. Thank you so much for using Triangle Real Estate Academy.\n\nCourse: ${course.name}\nCourse #: ${course.num}\nHours: ${course.hours || ''}\nStart Date: ${fmtDate(course.start_date)}\nCompletion Date: ${fmtDate(course.end_date)}\n\nKeith E. Green, M.Ed, GSI\nEducation Director/Instructor\nTriangle Real Estate Academy\n127 W. Main Street | Spring Hope, NC 27882\nPhone: 919-373-3577\nEmail: keg@trianglerealestateacademy.com\nWeb: www.trianglerealestateacademy.com`;
}

// ─── PDF GENERATION ───────────────────────────────────────
function generateCertPDFBuffer(student, course, s) {
  const doc = new jsPDF({ orientation: 'landscape', unit: 'mm', format: 'letter' });
  const pw = 279.4, ph = 215.9, margin = 10;
  const courseShort = course.name
    .replace(/^Post-License\s*/,'').replace(/^Elective:\s*/,'')
    .replace(/\sv\.\d+$/,'').trim() || course.name;

  doc.setDrawColor(44,44,42); doc.setLineWidth(1.2);
  doc.rect(margin, margin, pw-(margin*2), ph-(margin*2));
  doc.setLineWidth(0.4);
  doc.rect(margin+4, margin+4, pw-(margin*2)-8, ph-(margin*2)-8);

  doc.setFont('helvetica','bold'); doc.setFontSize(11);
  doc.setTextColor(192,57,43);
  doc.text(s.school || 'Triangle Real Estate Academy', margin+8, margin+14);

  doc.setFont('helvetica','normal'); doc.setFontSize(8); doc.setTextColor(60,60,60);
  [s.addr1, s.addr2, 'Phone: '+s.phone, 'Email: '+s.email, 'Web: '+s.web].forEach((line,i) => {
    doc.text(line||'', pw-margin-6, margin+10+(i*4.2), {align:'right'});
  });

  doc.setFont('helvetica','bold'); doc.setFontSize(24); doc.setTextColor(0,0,0);
  doc.text('CERTIFICATE OF COMPLETION', pw/2, 52, {align:'center'});
  doc.setFontSize(13);
  doc.text('For ' + course.name, pw/2, 61, {align:'center'});
  doc.setFontSize(11);
  doc.text('Approved by the North Carolina Real Estate Commission', pw/2, 69, {align:'center'});

  doc.setDrawColor(200,200,200); doc.setLineWidth(0.3);
  doc.line(margin+20, 73, pw-margin-20, 73);

  doc.setFont('helvetica','normal'); doc.setFontSize(22); doc.setTextColor(0,0,0);
  doc.text(student.name, pw/2, 92, {align:'center'});
  doc.setDrawColor(0,0,0); doc.setLineWidth(0.5);
  doc.line(pw/2-80, 95, pw/2+80, 95);
  doc.setFontSize(8); doc.setTextColor(120,120,120);
  doc.text('Name', pw/2, 99, {align:'center'});

  const fields = [
    {label:'Course', val:courseShort},
    {label:'Course Hours', val:String(course.hours||'')},
    {label:'Course Start Date', val:fmtDate(course.start_date)},
    {label:'Course End Date', val:fmtDate(course.end_date)}
  ];
  const colW = (pw-80)/fields.length;
  fields.forEach((f,i) => {
    const cx = 40+(i*colW)+colW/2;
    doc.setFont('helvetica','normal'); doc.setFontSize(11); doc.setTextColor(0,0,0);
    doc.text(f.val, cx, 120, {align:'center'});
    doc.setLineWidth(0.4); doc.setDrawColor(0,0,0);
    doc.line(cx-colW/2+6, 123, cx+colW/2-6, 123);
    doc.setFontSize(8); doc.setTextColor(120,120,120);
    doc.text(f.label, cx, 128, {align:'center'});
  });

  doc.setFont('helvetica','normal'); doc.setFontSize(11); doc.setTextColor(0,0,0);
  doc.text((s.school||'') + ' / ' + (s.prov||''), 70, 150, {align:'center'});
  doc.setLineWidth(0.4); doc.line(margin+8, 153, 130, 153);
  doc.setFontSize(8); doc.setTextColor(120,120,120);
  doc.text('Education Provider / Code', 70, 158, {align:'center'});

  doc.setFont('helvetica','normal'); doc.setFontSize(11); doc.setTextColor(0,0,0);
  doc.text((s.instructor||'') + ' / ' + (s.instCode||''), pw-70, 150, {align:'center'});
  doc.setLineWidth(0.4); doc.line(148, 153, pw-margin-8, 153);
  doc.setFontSize(8); doc.setTextColor(120,120,120);
  doc.text('Instructor / Code', pw-70, 158, {align:'center'});

  doc.setFont('times','italic'); doc.setFontSize(16); doc.setTextColor(40,40,40);
  doc.text('Keith E. Green', 70, 174, {align:'center'});
  doc.setLineWidth(0.4); doc.setDrawColor(0,0,0);
  doc.line(margin+8, 178, 130, 178);
  doc.setFont('helvetica','normal'); doc.setFontSize(8); doc.setTextColor(120,120,120);
  doc.text('Education Director Signature', 70, 183, {align:'center'});

  doc.setFont('helvetica','normal'); doc.setFontSize(11); doc.setTextColor(0,0,0);
  doc.text(fmtDate(course.end_date), pw-70, 174, {align:'center'});
  doc.setLineWidth(0.4); doc.setDrawColor(0,0,0);
  doc.line(148, 178, pw-margin-8, 178);
  doc.setFontSize(8); doc.setTextColor(120,120,120);
  doc.text('Date', pw-70, 183, {align:'center'});

  doc.setFont('helvetica','italic'); doc.setFontSize(8); doc.setTextColor(140,140,140);
  doc.text("This certificate should be retained as the licensee's personal record of course completion.", pw/2, ph-margin-10, {align:'center'});
  doc.text("It should NOT be submitted to the Commission unless the Commission specifically requests it.", pw/2, ph-margin-5, {align:'center'});

  return Buffer.from(doc.output('arraybuffer'));
}

// ─── NCREC ROSTER ─────────────────────────────────────────
app.post('/api/ncrec-roster', requireAuth, async (req, res) => {
  try {
    const { courseId, overrideDate } = req.body;
    const s = await getSettings();
    const courseResult = await pool.query('SELECT * FROM courses WHERE id=$1', [courseId]);
    if (!courseResult.rows.length) return res.status(404).json({ error: 'Course not found' });
    const course = courseResult.rows[0];
    const studResult = await pool.query('SELECT * FROM students WHERE course_id=$1', [courseId]);

    const prov = (s.prov || '1642').padEnd(4,'0').slice(0,4);
    const instCode = (s.instCode || '1976').padEnd(4,'0').slice(0,4);
    let dateStr = overrideDate;
    if (!dateStr && course.end_date) {
      const p = course.end_date.split('-');
      dateStr = p[1]+'-'+p[2]+'-'+p[0].slice(2);
    }
    const code = ncrecCode(course);
    const isPre = course.name === 'Prelicense';
    let lines = [`"${prov}","${instCode}","${dateStr}","${code}"`];
    studResult.rows.forEach(stu => {
      let line = `"${stu.license_num}","${toNCRECName(stu.name)}"`;
      if (isPre) line += `,"${stu.phone||''}","${stu.email||''}"`;
      lines.push(line);
    });
    res.setHeader('Content-Type', 'text/plain');
    res.setHeader('Content-Disposition', `attachment; filename="NCREC_Roster_${course.num}.txt"`);
    res.send(lines.join('\r\n'));
  } catch(err) { res.status(500).json({ error: err.message }); }
});

// ─── STUDENT PORTAL ───────────────────────────────────────
app.get('/api/portal/:licenseNum', async (req, res) => {
  try {
    const lic = req.params.licenseNum.trim();
    const result = await pool.query(`
      SELECT s.*, c.num as course_num, c.name as course_name,
             c.hours, c.start_date, c.end_date
      FROM students s
      JOIN courses c ON s.course_id = c.id
      WHERE LOWER(s.license_num) = LOWER($1)
      ORDER BY c.end_date DESC
    `, [lic]);
    if (!result.rows.length) return res.status(404).json({ error: 'No records found for this license number.' });
    res.json(result.rows);
  } catch(err) { res.status(500).json({ error: err.message }); }
});

app.get('/portal', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'portal.html'));
});

// ─── START ────────────────────────────────────────────────
initDB().then(() => {
  app.listen(PORT, () => {
    console.log(`Triangle REA Server running on port ${PORT}`);
    console.log(`Railway URL: ${RAILWAY_URL}`);
  });
}).catch(err => {
  console.error('DB init failed:', err);
  process.exit(1);
});
