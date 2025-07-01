require('dotenv').config();
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');

// 1. Create email transporter
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: process.env.EMAIL_PORT,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Test connection on startup
transporter.verify((error) => {
  if (error) {
    console.error('❌ SMTP Connection FAILED:', error.message);
  } else {
    console.log('✅ SMTP Connection READY');
  }
});

// 2. Email sending function
const sendVerificationEmail = async (email, token) => {
  try {
    console.log(`📨 Attempting to send email to: ${email}`);
    
    const mailOptions = {
      from: process.env.EMAIL_FROM,
      to: email,
      subject: 'Verify Your Email',
      html: `
        <p>Please click the link below to verify your email:</p>
        <a href="${process.env.BASE_URL}/verify-email?token=${token}">
          Verify Email
        </a>
        <p>Or copy this link: ${process.env.BASE_URL}/verify-email?token=${token}</p>
      `
    };

    const info = await transporter.sendMail(mailOptions);
    console.log('✉️ Email sent successfully:', info.messageId);
    return true;
  } catch (error) {
    console.error('❌ Email send error:', error.message);
    throw error;
  }
};

// 3. Token generation
const generateVerificationToken = () => uuidv4();

module.exports = {
  sendVerificationEmail,
  generateVerificationToken
};