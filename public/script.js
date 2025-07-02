const registerForm = document.getElementById('register-form');
const loginForm = document.getElementById('login-form');
const mfaSection = document.getElementById('mfa-section');
const verifyMfaBtn = document.getElementById('verify-mfa-btn');

let tempToken = null; // Store temporary JWT if MFA is required

registerForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = document.getElementById('reg-email').value;
  const password = document.getElementById('reg-password').value;

  try {
    const res = await fetch('/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    const data = await res.json();
    if (res.ok) {
      showMessage(data.message + ' (Check Mailtrap)');
    } else {
      showError(data.error || data.errors?.[0]?.msg);
    }
  } catch (err) {
    showError('Registration error: ' + err.message);
  }
});

loginForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = document.getElementById('login-email').value;
  const password = document.getElementById('login-password').value;

  try {
    const res = await fetch('/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    const data = await res.json();

    if (data.mfaRequired) {
      tempToken = data.tempToken;
      mfaSection.style.display = 'block';
      showMessage('MFA required. Enter your authenticator code.');
    } else if (data.token) {
      showMessage('Login successful. Token: ' + data.token);
    } else {
      showError(data.error || 'Login failed');
    }
  } catch (err) {
    showError('Login error: ' + err.message);
  }
});

verifyMfaBtn.addEventListener('click', async () => {
  const mfaToken = document.getElementById('mfa-token').value;

  try {
    const res = await fetch('/mfa/finalize', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tempToken, mfaToken })
    });
    const data = await res.json();

    if (data.token) {
      showMessage('MFA successful. Token: ' + data.token);
      mfaSection.style.display = 'none';
    } else {
      showError(data.error || 'MFA failed');
    }
  } catch (err) {
    showError('MFA error: ' + err.message);
  }
});

function showMessage(msg) {
  document.getElementById('message').textContent = msg;
  document.getElementById('error').textContent = '';
}

function showError(msg) {
  document.getElementById('error').textContent = msg;
  document.getElementById('message').textContent = '';
}

const mfaSetupForm = document.getElementById('mfa-setup-form');

mfaSetupForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const userId = document.getElementById('mfa-user-id').value;

  try {
    const res = await fetch('/mfa/setup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userId })
    });

    const data = await res.json();

    if (res.ok) {
      document.getElementById('qr-code').src = data.qrCodeUrl;
      document.getElementById('manual-code').textContent = data.manualEntryCode;
      document.getElementById('backup-codes').textContent = data.backupCodes.join('\n');
      document.getElementById('mfa-setup-result').style.display = 'block';
      showMessage("MFA setup successful. Scan the QR code and save backup codes.");
    } else {
      showError(data.error || 'MFA setup failed');
    }
  } catch (err) {
    showError('MFA setup error: ' + err.message);
  }
});