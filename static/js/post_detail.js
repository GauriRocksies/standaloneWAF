/* ============================================
   VulneraBlog — Post Detail JS
   Like, bookmark, comment like, reply, share
   ============================================ */

'use strict';

// ── Like Post ───────────────────────────────────
document.querySelectorAll('.like-btn').forEach(btn => {
    btn.addEventListener('click', async function () {
        const url = this.dataset.url;
        if (!url) return;

        try {
            const resp = await fetch(url, {
                method: 'POST',
                headers: {
                    'X-CSRFToken': window.getCsrfToken(),
                    'Content-Type': 'application/json',
                },
            });

            if (!resp.ok) throw new Error('Request failed');
            const data = await resp.json();

            // Update liked state and count
            this.classList.toggle('liked', data.liked);

            // Update the heart SVG fill
            const heartPath = this.querySelector('path');
            if (heartPath) {
                heartPath.setAttribute('fill', data.liked ? 'currentColor' : 'none');
            }

            // Update count display
            const countEl = this.querySelector('.like-count');
            if (countEl && data.count !== undefined) {
                countEl.textContent = formatCount(data.count);
            }

        } catch (err) {
            console.error('Like failed:', err);
        }
    });
});


// ── Bookmark Post ────────────────────────────────
document.querySelectorAll('.bookmark-btn').forEach(btn => {
    btn.addEventListener('click', async function () {
        const url = this.dataset.url;
        if (!url) return;

        try {
            const resp = await fetch(url, {
                method: 'POST',
                headers: {
                    'X-CSRFToken': window.getCsrfToken(),
                    'Content-Type': 'application/json',
                },
            });

            if (!resp.ok) throw new Error('Request failed');
            const data = await resp.json();

            // Update bookmarked state
            this.classList.toggle('bookmarked', data.bookmarked);

            // Update SVG fill
            const bookmarkPath = this.querySelector('path');
            if (bookmarkPath) {
                bookmarkPath.setAttribute('fill', data.bookmarked ? 'currentColor' : 'none');
            }

        } catch (err) {
            console.error('Bookmark failed:', err);
        }
    });
});


// ── Like Comment ─────────────────────────────────
document.querySelectorAll('.comment-like-btn').forEach(btn => {
    btn.addEventListener('click', async function () {
        const url = this.dataset.url;
        if (!url) return;

        try {
            const resp = await fetch(url, {
                method: 'POST',
                headers: {
                    'X-CSRFToken': window.getCsrfToken(),
                    'Content-Type': 'application/json',
                },
            });

            if (!resp.ok) throw new Error('Request failed');
            const data = await resp.json();

            const countEl = this.querySelector('.comment-like-count');
            if (countEl) countEl.textContent = data.count;

            this.style.color = data.liked ? 'var(--accent)' : '';

        } catch (err) {
            console.error('Comment like failed:', err);
        }
    });
});


// ── Reply toggle ─────────────────────────────────
document.querySelectorAll('.comment-reply-btn').forEach(btn => {
    btn.addEventListener('click', function () {
        const commentId = this.dataset.commentId;
        const replyForm = document.getElementById(`reply-form-${commentId}`);
        if (replyForm) {
            const isVisible = replyForm.style.display !== 'none';
            replyForm.style.display = isVisible ? 'none' : 'block';
            if (!isVisible) {
                replyForm.querySelector('textarea').focus();
            }
        }
    });
});

document.querySelectorAll('.btn-cancel-reply').forEach(btn => {
    btn.addEventListener('click', function () {
        const commentId = this.dataset.commentId;
        const replyForm = document.getElementById(`reply-form-${commentId}`);
        if (replyForm) replyForm.style.display = 'none';
    });
});


// ── Share button ──────────────────────────────────
const shareBtn = document.getElementById('shareBtn');
if (shareBtn) {
    shareBtn.addEventListener('click', async function () {
        if (navigator.share) {
            try {
                await navigator.share({
                    title: document.title,
                    url: window.location.href,
                });
            } catch (err) {
                // User cancelled
            }
        } else {
            // Fallback: copy to clipboard
            await navigator.clipboard.writeText(window.location.href);
            showToast('Link copied to clipboard!');
        }
    });
}


// ── Helpers ──────────────────────────────────────
function formatCount(n) {
    if (n >= 1000) return (n / 1000).toFixed(1) + 'k';
    return String(n);
}

function showToast(message) {
    const toast = document.createElement('div');
    toast.style.cssText = `
        position: fixed;
        bottom: 24px;
        right: 24px;
        background: var(--bg-card);
        border: 1px solid var(--border-light);
        color: var(--text-primary);
        font-size: 13.5px;
        padding: 12px 20px;
        border-radius: 6px;
        z-index: 9999;
        animation: slideIn 0.3s ease;
        font-family: var(--font-body, sans-serif);
    `;
    toast.textContent = message;
    document.body.appendChild(toast);
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transition = 'opacity 0.3s ease';
        setTimeout(() => toast.remove(), 300);
    }, 2500);
}