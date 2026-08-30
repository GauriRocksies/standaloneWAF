/* ============================================
   VulneraBlog — Profile JS
   Follow/unfollow toggle, view toggle
   ============================================ */

'use strict';

// ── Follow / Unfollow ────────────────────────────
const followBtn = document.getElementById('followBtn');
if (followBtn) {
    followBtn.addEventListener('click', async function () {
        const url = this.dataset.url;
        if (!url) return;

        // Optimistic UI update
        const wasFollowing = this.classList.contains('following');
        this.disabled = true;

        try {
            const resp = await fetch(url, {
                method: 'POST',
                headers: {
                    'X-CSRFToken': window.getCsrfToken(),
                    'Content-Type': 'application/json',
                },
            });

            if (!resp.ok) throw new Error('Follow request failed');
            const data = await resp.json();

            // Update button state
            this.classList.toggle('following', data.following);
            this.textContent = data.following ? 'Following' : 'Follow';

            // Update followers count
            const followersCountEl = document.getElementById('followersCount');
            if (followersCountEl && data.followers_count !== undefined) {
                followersCountEl.textContent = formatCount(data.followers_count);
            }

        } catch (err) {
            console.error('Follow failed:', err);
            // Revert on error
            this.classList.toggle('following', wasFollowing);
            this.textContent = wasFollowing ? 'Following' : 'Follow';
        } finally {
            this.disabled = false;
        }
    });
}


// ── Grid / List view toggle ───────────────────────
const gridViewBtn = document.getElementById('gridViewBtn');
const listViewBtn = document.getElementById('listViewBtn');
const postsGrid = document.getElementById('profilePostsGrid');

if (gridViewBtn && listViewBtn && postsGrid) {
    gridViewBtn.addEventListener('click', function () {
        postsGrid.classList.remove('list-view');
        gridViewBtn.classList.add('active');
        listViewBtn.classList.remove('active');
        localStorage.setItem('vb_profile_view', 'grid');
    });

    listViewBtn.addEventListener('click', function () {
        postsGrid.classList.add('list-view');
        listViewBtn.classList.add('active');
        gridViewBtn.classList.remove('active');
        localStorage.setItem('vb_profile_view', 'list');
    });

    // Restore saved preference
    const savedView = localStorage.getItem('vb_profile_view');
    if (savedView === 'list') {
        listViewBtn.click();
    }
}


// ── Helper ───────────────────────────────────────
function formatCount(n) {
    if (n >= 1000) return (n / 1000).toFixed(1) + 'k';
    return String(n);
}