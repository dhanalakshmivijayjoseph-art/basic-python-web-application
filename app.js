const API = 'http://127.0.0.1:5000/api';
const form = document.querySelector('#auth-form');
const emailInput = document.querySelector('#email');
const passwordInput = document.querySelector('#password');
const nameInput = document.querySelector('#name');
const feedback = document.querySelector('#feedback');
const togglePassword = document.querySelector('#toggle-password');
const switchMode = document.querySelector('#switch-mode');
const submitButton = document.querySelector('#submit');
const forgotButton = document.querySelector('#forgot');
const signedIn = document.querySelector('#signed-in');
const tokenKey = 'figma-login-session';
let mode = 'login';

function message(text, kind = '') {
  feedback.textContent = text;
  feedback.className = `feedback ${kind}`.trim();
}

function setMode(nextMode) {
  mode = nextMode;
  const signup = mode === 'signup';
  document.querySelector('#title').textContent = signup ? 'Create Account' : 'Welcome Back!';
  document.querySelector('#subtitle').textContent = signup ? 'Sign up to get started' : 'Please login to your account';
  document.querySelector('#prompt').textContent = signup ? 'Already have an account?' : 'Don’t have an account?';
  switchMode.textContent = signup ? 'Login' : 'Sign up';
  submitButton.textContent = signup ? 'Sign up' : 'Login';
  nameInput.required = signup;
  nameInput.closest('.field').hidden = !signup;
  passwordInput.autocomplete = signup ? 'new-password' : 'current-password';
  message('');
}

async function apiRequest(path, options = {}) {
  const headers = { ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...(options.headers || {}) };
  const token = localStorage.getItem(tokenKey);
  if (token) headers.Authorization = `Bearer ${token}`;
  const response = await fetch(`${API}${path}`, { ...options, headers });
  const data = await response.json();
  if (!response.ok) throw new Error(data.message || 'The request could not be completed.');
  return data;
}

function showSignedIn(user) {
  form.hidden = true;
  document.querySelector('.signup-prompt').hidden = true;
  signedIn.hidden = false;
  document.querySelector('#title').textContent = `Welcome, ${user.name}!`;
  document.querySelector('#subtitle').textContent = 'You are signed in.';
  document.querySelector('#signed-in-copy').textContent = user.email;
  message('');
}

togglePassword.addEventListener('click', () => {
  const showing = passwordInput.type === 'text';
  passwordInput.type = showing ? 'password' : 'text';
  togglePassword.setAttribute('aria-label', showing ? 'Show password' : 'Hide password');
  togglePassword.title = showing ? 'Show password' : 'Hide password';
});

switchMode.addEventListener('click', () => setMode(mode === 'login' ? 'signup' : 'login'));

forgotButton.addEventListener('click', () => {
  const email = emailInput.value.trim();
  if (!email || !emailInput.checkValidity()) {
    emailInput.focus();
    message('Enter a valid email address first.');
    return;
  }
  message('Password reset email delivery is not configured on this local demo.');
});

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  message('');
  if (!emailInput.checkValidity()) {
    emailInput.reportValidity();
    return message('Please enter a valid email address.');
  }
  if (mode === 'signup' && !nameInput.checkValidity()) {
    nameInput.reportValidity();
    return message('Please enter your name.');
  }
  if (!passwordInput.checkValidity()) {
    passwordInput.reportValidity();
    return message('Your password needs at least 6 characters.');
  }

  const originalLabel = submitButton.textContent;
  submitButton.disabled = true;
  submitButton.textContent = mode === 'signup' ? 'Creating…' : 'Signing in…';
  try {
    const path = mode === 'signup' ? '/register' : '/login';
    const payload = { email: emailInput.value.trim(), password: passwordInput.value };
    if (mode === 'signup') payload.name = nameInput.value.trim();
    const result = await apiRequest(path, { method: 'POST', body: JSON.stringify(payload) });
    localStorage.setItem(tokenKey, result.token);
    showSignedIn(result.user);
  } catch (error) {
    message(error.message || 'Cannot reach the Python API. Start backend.py and try again.');
  } finally {
    submitButton.disabled = false;
    submitButton.textContent = originalLabel;
  }
});

document.querySelector('#logout').addEventListener('click', async () => {
  try { await apiRequest('/logout', { method: 'POST' }); } catch (_) { /* clear the local session even if the API is offline */ }
  localStorage.removeItem(tokenKey);
  signedIn.hidden = true;
  form.hidden = false;
  document.querySelector('.signup-prompt').hidden = false;
  emailInput.value = '';
  passwordInput.value = '';
  nameInput.value = '';
  setMode('login');
  document.querySelector('#title').textContent = 'Welcome Back!';
  document.querySelector('#subtitle').textContent = 'Please login to your account';
  emailInput.focus();
});

const savedToken = localStorage.getItem(tokenKey);
if (savedToken) {
  apiRequest('/me').then(result => showSignedIn(result.user)).catch(() => localStorage.removeItem(tokenKey));
}
