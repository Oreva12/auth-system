# 🔐 Advanced Authentication API

This is a secure, production-ready **Authentication API** built with **Node.js**, **Express**, and **MySQL**.  
It includes support for:

- ✅ Registration & Login with JWT
- ✅ Email verification via Mailtrap
- ✅ Multi-Factor Authentication (MFA) using Google Authenticator & backup codes
- ✅ Rate limiting, input validation, and HTTPS-readiness
- ✅ (WIP) Role-Based Access (RBA) features like device fingerprinting and login monitoring

---


# Install dependencies
npm install Speakeasy Express Nodemailer express-rate-limit bcryptjs jsonwebtoken express-validator qrcode crypto

# Run the server
npm start
Then open: http://localhost:3000

🧪 API Testing with Postman
A Postman Collection is recommended to test endpoints such as:

Endpoint	Method	Description
- /register	POST	Register a new user
- /verify-email	GET	Verify email with token
- /login	POST	Login user, optionally trigger MFA
- /mfa/setup	POST	Setup MFA + get QR + backup codes
- /mfa/verify	POST	Enable MFA after scanning
- /mfa/finalize	POST	Finalize login using TOTP
- /mfa/backup-verify	POST	Login using a backup code
- /mfa/regenerate-backup-codes	POST	Generate new backup codes

You can group requests in Postman and optionally export/share documentation.


🧰 Tech Stack

- Node.js, Express

- MySQL (mysql2)

- JWT for session management

- Bcrypt for password security

- Mailtrap (via Nodemailer)

- TOTP via Speakeasy

- QRCode, Helmet, Express middleware

📌 To-Do (Next Steps)

 - Add RBA fingerprinting and anomaly alerts

-  Admin panel or analytics for login patterns

-  Password reset via email

🧑‍💻 Author

- Oreva
- Backend Developer
- GitHub: @Oreva12
