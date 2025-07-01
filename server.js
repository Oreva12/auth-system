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
app.post('/register', 
    [
      // Email validation
      check('email')
        .isEmail()
        .withMessage('Please provide a valid email')
        .normalizeEmail(),
        
      // Password validation
      check('password')
        .isLength({ min: 8 })
        .withMessage('Password must be at least 8 characters')
        .matches(/[0-9]/)
        .withMessage('Password must contain a number')
        .matches(/[a-zA-Z]/)
        .withMessage('Password must contain a letter')
    ],
    async (req, res) => {
      try {
        // Check for validation errors
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
          return res.status(400).json({ 
            error: 'Validation failed',
            details: errors.array().map(err => ({
              field: err.param,
              message: err.msg
            }))
          });
        }
  
        const { email, password } = req.body;
        
        // Check if user already exists
        const [existingUsers] = await pool.execute(
          'SELECT id FROM users WHERE email = ?', 
          [email]
        );
        
        if (existingUsers.length > 0) {
          return res.status(409).json({
            error: 'Registration failed',
            details: 'Email already in use'
          });
        }
  
        // Hash password and create user
        const hashedPassword = await bcrypt.hash(password, 10);
        const [result] = await pool.execute(
          'INSERT INTO users (email, password) VALUES (?, ?)',
          [email, hashedPassword]
        );
  
        res.status(201).json({ 
          success: true,
          user: { 
            id: result.insertId, 
            email 
          }
        });
  
      } catch (err) {
        console.error('Registration error:', err);
        
        // Improved error response
        res.status(500).json({
          error: 'Registration failed',
          details: process.env.NODE_ENV === 'development' 
            ? err.message 
            : 'Please try again later'
        });
      }
    }
  );

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