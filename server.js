require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const pool = require('./db');
const { check, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const crypto = require('crypto'); // Added for backup codes

const app = express();
app.use(express.json());
app.use(helmet());

// Rate limiting: 100 requests per 15 minutes
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, 
  max: 100,
  message: 'Too many requests, please try again later.'
});
app.use(limiter);

// Email Service
const { sendVerificationEmail, generateVerificationToken } = require('./emailService');

// Backup Code Generation Utility
function generateBackupCodes(count = 10) {
  return Array(count).fill().map(() => 
    crypto.randomBytes(6).toString('hex').toUpperCase().match(/.{1,4}/g).join('-')
  );
}

// ============ REGISTRATION & EMAIL VERIFICATION (UNCHANGED) ============
app.post('/register', 
  [
    check('email').isEmail().normalizeEmail(),
    check('password').isLength({ min: 8 })
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

      const { email, password } = req.body;
      const verificationToken = generateVerificationToken();
      const hashedPassword = await bcrypt.hash(password, 10);

      const [result] = await pool.execute(
        'INSERT INTO users (email, password, verification_token, is_verified) VALUES (?, ?, ?, ?)',
        [email, hashedPassword, verificationToken, false]
      );

      await sendVerificationEmail(email, verificationToken);

      res.status(201).json({ 
        message: 'Registration successful! Please check your email.' 
      });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Registration failed' });
    }
  }
);

app.get('/verify-email', async (req, res) => {
  try {
    const { token } = req.query;
    
    const [result] = await pool.execute(
      'UPDATE users SET is_verified = true, verification_token = NULL WHERE verification_token = ?',
      [token]
    );

    if (result.affectedRows === 0) {
      return res.status(400).json({ error: 'Invalid or expired token' });
    }

    res.json({ message: 'Email verified successfully!' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Verification failed' });
  }
});

// ============ UPDATED MFA ENDPOINTS WITH BACKUP CODES ============
app.post('/mfa/setup', async (req, res) => {
  try {
    const { userId } = req.body;
    
    const secret = speakeasy.generateSecret({
      length: 20,
      name: `AuthApp (${userId})`,
      issuer: 'AuthSystem'
    });

    // Generate backup codes
    const backupCodes = generateBackupCodes();
    const hashedCodes = await Promise.all(
      backupCodes.map(code => bcrypt.hash(code, 10))
    );

    // Store both MFA secret and backup codes
    await pool.execute(
      'UPDATE users SET mfa_secret = ?, backup_codes = ? WHERE id = ?',
      [secret.base32, JSON.stringify(hashedCodes), userId]
    );

    // Generate QR Code
    QRCode.toDataURL(secret.otpauth_url, (err, qrCodeUrl) => {
      if (err) throw err;
      
      res.json({
        secret: secret.base32,
        qrCodeUrl,
        manualEntryCode: secret.otpauth_url.match(/secret=([^&]+)/)[1],
        backupCodes, // Show only once!
        warning: "Save these backup codes securely. They won't be shown again."
      });
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'MFA setup failed' });
  }
});

app.post('/mfa/verify', async (req, res) => {
  try {
    const { userId, token } = req.body;
    
    const [users] = await pool.execute(
      'SELECT mfa_secret FROM users WHERE id = ?',
      [userId]
    );
    
    if (!users[0].mfa_secret) {
      return res.status(400).json({ error: 'MFA not configured' });
    }

    const verified = speakeasy.totp.verify({
      secret: users[0].mfa_secret,
      encoding: 'base32',
      token,
      window: 2
    });

    if (verified) {
      await pool.execute(
        'UPDATE users SET mfa_enabled = true WHERE id = ?',
        [userId]
      );
    }

    res.json({ verified });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'MFA verification failed' });
  }
});

// ============ UPDATED LOGIN FLOW WITH BACKUP CODE SUPPORT ============
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const [users] = await pool.execute(
      'SELECT * FROM users WHERE email = ?',
      [email]
    );
    
    if (users.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const user = users[0];
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    if (user.mfa_enabled) {
      return res.json({ 
        mfaRequired: true,
        tempToken: jwt.sign(
          { userId: user.id, mfaPending: true },
          process.env.JWT_SECRET,
          { expiresIn: '5m' }
        )
      });
    }
    
    const token = jwt.sign(
      { userId: user.id }, 
      process.env.JWT_SECRET, 
      { expiresIn: '1h' }
    );
    
    res.json({ token, mfaRequired: false });
  } catch (err) {
    console.error(err);
    res.status(500).json({ 
      error: "Login failed",
      systemMessage: err.message
    });
  }
});

// ============ UPDATED MFA FINALIZE WITH BACKUP CODE OPTION ============
app.post('/mfa/finalize', async (req, res) => {
  try {
    const { tempToken, mfaToken, useBackupCode } = req.body;
    
    const decoded = jwt.verify(tempToken, process.env.JWT_SECRET);
    if (!decoded.mfaPending) {
      return res.status(400).json({ error: 'Invalid token' });
    }

    if (useBackupCode) {
      return res.json({ 
        backupCodeRequired: true,
        tempToken // Reuse same temp token
      });
    }

    // Original MFA verification
    const [users] = await pool.execute(
      'SELECT mfa_secret FROM users WHERE id = ?',
      [decoded.userId]
    );
    
    const verified = speakeasy.totp.verify({
      secret: users[0].mfa_secret,
      encoding: 'base32',
      token: mfaToken,
      window: 2
    });
    
    if (!verified) {
      return res.status(401).json({ error: 'Invalid MFA code' });
    }
    
    const finalToken = jwt.sign(
      { userId: decoded.userId },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    
    res.json({ token: finalToken });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'MFA finalization failed' });
  }
});

// ============ NEW BACKUP CODE ENDPOINTS ============
app.post('/mfa/backup-verify', async (req, res) => {
  try {
    const { tempToken, backupCode } = req.body;

    const decoded = jwt.verify(tempToken, process.env.JWT_SECRET);
    if (!decoded.mfaPending) {
      return res.status(400).json({ error: 'Invalid token' });
    }

    // Get hashed codes from DB
    const [users] = await pool.execute(
      'SELECT backup_codes FROM users WHERE id = ?',
      [decoded.userId]
    );
    const hashedCodes = JSON.parse(users[0].backup_codes || '[]');

    // Check if any code matches
    let isValid = false;
    for (const hashedCode of hashedCodes) {
      if (await bcrypt.compare(backupCode, hashedCode)) {
        isValid = true;
        break;
      }
    }

    if (!isValid) {
      return res.status(401).json({ error: 'Invalid backup code' });
    }

    // Invalidate used code
    const updatedCodes = hashedCodes.filter(
      code => !bcrypt.compareSync(backupCode, code)
    );
    await pool.execute(
      'UPDATE users SET backup_codes = ? WHERE id = ?',
      [JSON.stringify(updatedCodes), decoded.userId]
    );

    // Issue final token
    const finalToken = jwt.sign(
      { userId: decoded.userId },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({ token: finalToken });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Backup verification failed' });
  }
});

app.post('/mfa/regenerate-backup-codes', async (req, res) => {
  try {
    const { userId } = req.body;
    
    // Verify user has MFA enabled
    const [users] = await pool.execute(
      'SELECT mfa_enabled FROM users WHERE id = ?',
      [userId]
    );
    
    if (!users[0]?.mfa_enabled) {
      return res.status(400).json({ error: 'MFA not enabled' });
    }

    // Generate new codes
    const backupCodes = generateBackupCodes();
    const hashedCodes = await Promise.all(
      backupCodes.map(code => bcrypt.hash(code, 10))
    );

    await pool.execute(
      'UPDATE users SET backup_codes = ? WHERE id = ?',
      [JSON.stringify(hashedCodes), userId]
    );

    res.json({
      success: true,
      backupCodes, // Show only once!
      warning: "Old backup codes are now invalid. Save these new codes securely."
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to regenerate codes' });
  }
});

// Start server
app.listen(process.env.PORT, () => {
  console.log(`Server running on port ${process.env.PORT}`);
});