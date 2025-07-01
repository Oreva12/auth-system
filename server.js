require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const pool = require('./db');
const { check, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');


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

// Registration Endpoint
const { sendVerificationEmail, generateVerificationToken } = require('./emailService');

// Updated /register route
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

      // Save user with verification token (add this column to your DB)
      const [result] = await pool.execute(
        'INSERT INTO users (email, password, verification_token, is_verified) VALUES (?, ?, ?, ?)',
        [email, hashedPassword, verificationToken, false]
      );

      // Send verification email
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

// Add this new route
app.get('/verify-email', async (req, res) => {
  try {
    const { token } = req.query;
    
    // Mark user as verified
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

// Login Endpoint
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Find user
    const [users] = await pool.execute(
      'SELECT * FROM users WHERE email = ?',
      [email]
    );
    
    if (users.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Check password
    const user = users[0];
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Create token with 1-hour expiration
    const token = jwt.sign(
      { userId: user.id }, 
      process.env.JWT_SECRET, 
      { expiresIn: '1h' }
    );
    
    res.json({ token });
  } catch (err) {
    console.error(err);
    
    // Improved error response
    res.status(500).json({ 
      error: "Login failed",
      systemMessage: err.message  // Provides technical details for debugging
    });
  }
});



// Start server
app.listen(process.env.PORT, () => {
  console.log(`Server running on port ${process.env.PORT}`);
});