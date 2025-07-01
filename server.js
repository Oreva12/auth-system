require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const pool = require('./db');

const app = express();
app.use(express.json());

// Registration Endpoint
app.post('/register', async (req, res) => {
    try {
      console.log('Received body:', req.body); // Add this line
      
      if (!req.body || !req.body.email || !req.body.password) {
        return res.status(400).json({ error: "Email and password are required" });
      }
  
      const { email, password } = req.body;
      const hashedPassword = await bcrypt.hash(password, 10);
      
      console.log('Attempting to insert:', email); // Add this line
      
      const [result] = await pool.execute(
        'INSERT INTO users (email, password) VALUES (?, ?)',
        [email, hashedPassword]
      );
      
      res.status(201).json({ id: result.insertId, email });
    } catch (err) {
      console.error('Registration error:', err); // Enhanced error logging
      res.status(500).json({ error: err.message }); // Return actual error message
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
    
    // Create token
    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    
    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Start server
app.listen(process.env.PORT, () => {
  console.log(`Server running on port ${process.env.PORT}`);
});