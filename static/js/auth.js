/* ============================================
   VulneraBlog — Auth JS
   Form validation for login and register
   ============================================ */

'use strict';

// ── Login form validation ───────────────────────
const loginForm = document.getElementById('loginForm');
if (loginForm) {
    loginForm.addEventListener('submit', function (e) {
        const userIdInput = this.querySelector('input[name="user_id_code"]');
        const passwordInput = this.querySelector('input[name="password"]');
        let valid = true;

        // Clear previous errors
        clearErrors(this);

        if (!userIdInput.value.trim()) {
            showError(userIdInput, 'Please enter your User ID.');
            valid = false;
        }

        if (!passwordInput.value) {
            showError(passwordInput, 'Please enter your password.');
            valid = false;
        }

        if (!valid) e.preventDefault();
    });
}

// ── Register form validation ────────────────────
const registerForm = document.getElementById('registerForm');
if (registerForm) {
    registerForm.addEventListener('submit', function (e) {
        clearErrors(this);
        let valid = true;

        const password1 = this.querySelector('input[name="password1"]');
        const password2 = this.querySelector('input[name="password2"]');
        const email = this.querySelector('input[name="email"]');

        if (email && !isValidEmail(email.value)) {
            showError(email, 'Please enter a valid email address.');
            valid = false;
        }

        if (password1 && password1.value.length < 8) {
            showError(password1, 'Password must be at least 8 characters.');
            valid = false;
        }

        if (password2 && password1.value !== password2.value) {
            showError(password2, 'Passwords do not match.');
            valid = false;
        }

        if (!valid) e.preventDefault();
    });
}

// ── Helpers ─────────────────────────────────────
function showError(inputEl, message) {
    // Remove existing error first
    const existing = inputEl.parentElement.querySelector('.form-error');
    if (existing) existing.remove();

    const errorEl = document.createElement('span');
    errorEl.className = 'form-error';
    errorEl.textContent = message;
    inputEl.parentElement.appendChild(errorEl);
    inputEl.style.borderColor = '#cc4e4e';
}

function clearErrors(formEl) {
    formEl.querySelectorAll('.form-error').forEach(el => el.remove());
    formEl.querySelectorAll('input').forEach(input => {
        input.style.borderColor = '';
    });
}

function isValidEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// ── Input focus effects ──────────────────────────
document.querySelectorAll('.form-input').forEach(input => {
    input.addEventListener('focus', function () {
        this.style.borderColor = '';
    });
});