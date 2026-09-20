// CyberShield front-end scripts

// ---------------------------------------------------------------------------
// Dark mode toggle
// ---------------------------------------------------------------------------
(function () {
    const toggleBtn = document.getElementById('themeToggle');
    const icon = document.getElementById('themeIcon');
    if (!toggleBtn) return;

    function updateIcon() {
        const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
        icon.className = isDark ? 'bi bi-sun-fill' : 'bi bi-moon-stars-fill';
    }
    updateIcon();

    toggleBtn.addEventListener('click', function () {
        toggleBtn.classList.add('spin');
        setTimeout(function () { toggleBtn.classList.remove('spin'); }, 350);

        const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
        if (isDark) {
            document.documentElement.removeAttribute('data-theme');
            localStorage.setItem('cs-theme', 'light');
        } else {
            document.documentElement.setAttribute('data-theme', 'dark');
            localStorage.setItem('cs-theme', 'dark');
        }
        updateIcon();
    });
})();

// ---------------------------------------------------------------------------
// Tools page search filter
// ---------------------------------------------------------------------------
(function () {
    const searchInput = document.getElementById('toolSearch');
    if (!searchInput) return;

    searchInput.addEventListener('input', function () {
        const query = this.value.trim().toLowerCase();
        document.querySelectorAll('[data-tool-name]').forEach(function (card) {
            const name = card.getAttribute('data-tool-name').toLowerCase();
            const column = card.closest('.col-md-4, .col-sm-6');
            if (column) {
                column.style.display = name.includes(query) ? '' : 'none';
            }
        });
    });
})();

// ---------------------------------------------------------------------------
// Scan form: loading spinner + indeterminate progress bar
// Applies to any <form> with class "scan-form" and a submit button with
// class "scan-submit-btn" whose text is wrapped in <span class="btn-label">.
// ---------------------------------------------------------------------------
(function () {
    document.querySelectorAll('form.scan-form').forEach(function (form) {
        form.addEventListener('submit', function () {
            const btn = form.querySelector('.scan-submit-btn');
            const progress = form.querySelector('.scan-progress-bar') || document.getElementById('scanProgress');
            if (btn) {
                btn.classList.add('is-loading');
                btn.disabled = true;
            }
            if (progress) {
                progress.classList.add('active');
            }
        });
    });
})();

// ---------------------------------------------------------------------------
// Dashboard stat count-up animation
// Applies to any element with class "stat-number" and a data-value attribute.
// ---------------------------------------------------------------------------
(function () {
    const counters = document.querySelectorAll('.stat-number');
    if (!counters.length) return;

    counters.forEach(function (el) {
        const target = parseInt(el.getAttribute('data-value'), 10) || 0;
        const duration = 600; // ms
        const startTime = performance.now();

        function tick(now) {
            const progress = Math.min((now - startTime) / duration, 1);
            const eased = 1 - Math.pow(1 - progress, 3); // ease-out cubic
            el.textContent = Math.round(eased * target);
            if (progress < 1) {
                requestAnimationFrame(tick);
            } else {
                el.textContent = target;
            }
        }
        requestAnimationFrame(tick);
    });
})();

console.log("CyberShield dashboard loaded.");
