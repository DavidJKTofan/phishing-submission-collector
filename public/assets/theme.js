(function () {
	var STORAGE_KEY = 'theme';
	var root = document.documentElement;

	function getStoredTheme() {
		try {
			var v = localStorage.getItem(STORAGE_KEY);
			return v === 'light' || v === 'dark' ? v : null;
		} catch (_) {
			return null;
		}
	}

	function getSystemTheme() {
		try {
			return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
		} catch (_) {
			return 'light';
		}
	}

	function applyTheme(theme, notify) {
		root.setAttribute('data-theme', theme);
		// Notify listeners (e.g. the Turnstile widget) that the theme changed.
		// Skipped for the initial pre-paint application: nothing listens yet.
		if (notify) {
			try {
				document.dispatchEvent(new CustomEvent('themechange', { detail: { theme: theme } }));
			} catch (_) {}
		}
	}

	applyTheme(getStoredTheme() || getSystemTheme(), false);

	function syncToggleState(toggle) {
		var current = root.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
		var next = current === 'dark' ? 'light' : 'dark';
		toggle.setAttribute('aria-label', 'Switch to ' + next + ' theme');
		toggle.setAttribute('aria-pressed', String(current === 'dark'));
		toggle.title = 'Switch to ' + next + ' theme';
	}

	function setupToggle() {
		var toggle = document.getElementById('theme-toggle');
		if (!toggle) return;

		syncToggleState(toggle);

		toggle.addEventListener('click', function () {
			var current = root.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
			var next = current === 'dark' ? 'light' : 'dark';
			applyTheme(next, true);
			try {
				localStorage.setItem(STORAGE_KEY, next);
			} catch (_) {}
			syncToggleState(toggle);
		});

		try {
			if (window.matchMedia) {
				var mq = window.matchMedia('(prefers-color-scheme: dark)');
				var listener = function (e) {
					if (getStoredTheme()) return;
					applyTheme(e.matches ? 'dark' : 'light', true);
					syncToggleState(toggle);
				};
				if (mq.addEventListener) mq.addEventListener('change', listener);
				else if (mq.addListener) mq.addListener(listener);
			}
		} catch (_) {}
	}

	if (document.readyState === 'loading') {
		document.addEventListener('DOMContentLoaded', setupToggle);
	} else {
		setupToggle();
	}
})();
