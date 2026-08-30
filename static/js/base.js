/* ============================================
   VulneraBlog — Base JS
   Navigation, dropdown, and global utilities
   ============================================ */

'use strict';

// ── CSRF Token Helper ───────────────────────────
/**
 * Get Django CSRF token from cookie.
 * Required for all AJAX POST requests.
 */
function getCsrfToken() {
    const name = 'csrftoken';
    const cookies = document.cookie.split(';');
    for (let cookie of cookies) {
        const trimmed = cookie.trim();
        if (trimmed.startsWith(name + '=')) {
            return decodeURIComponent(trimmed.substring(name.length + 1));
        }
    }
    return null;
}

// Export for use in other scripts
window.getCsrfToken = getCsrfToken;

// ── Nav Avatar Dropdown ─────────────────────────
const avatarToggle = document.getElementById('avatarToggle');
if (avatarToggle) {
    avatarToggle.addEventListener('click', function (e) {
        e.stopPropagation();
        this.classList.toggle('open');
    });

    document.addEventListener('click', function () {
        avatarToggle.classList.remove('open');
    });
}

// ── Flash message auto-dismiss ──────────────────
const flashMessages = document.querySelectorAll('.flash');
flashMessages.forEach(flash => {
    setTimeout(() => {
        flash.style.transition = 'opacity 0.4s ease';
        flash.style.opacity = '0';
        setTimeout(() => flash.remove(), 400);
    }, 5000);
});

// ── Navbar scroll style ─────────────────────────
const navbar = document.getElementById('navbar');
if (navbar) {
    window.addEventListener('scroll', function () {
        if (window.scrollY > 10) {
            navbar.style.background = 'rgba(8, 14, 26, 0.98)';
        } else {
            navbar.style.background = 'rgba(8, 14, 26, 0.92)';
        }
    });
}

// ── Cover image preview on upload form ─────────
const coverImageInput = document.querySelector('input[type="file"][name="cover_image"]');
const coverPreview = document.getElementById('coverPreview');

if (coverImageInput && coverPreview) {
    coverImageInput.addEventListener('change', function () {
        const file = this.files[0];
        if (file && file.type.startsWith('image/')) {
            const reader = new FileReader();
            reader.onload = function (e) {
                coverPreview.innerHTML = `<img src="${e.target.result}" alt="Cover preview">`;
            };
            reader.readAsDataURL(file);
        } else {
            coverPreview.innerHTML = '';
        }
    });
}