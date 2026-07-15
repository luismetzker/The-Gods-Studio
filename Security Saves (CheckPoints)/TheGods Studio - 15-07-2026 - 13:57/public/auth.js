'use strict';

(function () {
  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function getParam(name) {
    return new URLSearchParams(window.location.search).get(name);
  }

  function toast(msg) {
    let el = document.getElementById('toast');
    if (!el) {
      el = document.createElement('div');
      el.className = 'toast';
      el.id = 'toast';
      document.body.appendChild(el);
    }
    el.textContent = msg;
    el.classList.add('show');
    clearTimeout(el._t);
    el._t = setTimeout(() => el.classList.remove('show'), 3200);
  }

  async function apiFetch(path, opts) {
    opts = opts || {};
    opts.headers = Object.assign(
      { 'X-Requested-With': 'xmlhttprequest', 'Content-Type': 'application/json' },
      opts.headers || {}
    );
    if (opts.body && typeof opts.body !== 'string') opts.body = JSON.stringify(opts.body);
    const res = await fetch(path, opts);
    let data = null;
    try {
      data = await res.json();
    } catch (_) {}
    return { ok: res.ok, status: res.status, data };
  }

  async function getMe() {
    try {
      const res = await fetch('/api/me', { headers: { 'X-Requested-With': 'xmlhttprequest' } });
      if (res.status === 401) return null;
      const j = await res.json();
      return j.authenticated ? j.user : null;
    } catch (_) {
      return null;
    }
  }

  async function logout() {
    try {
      await apiFetch('/api/logout', { method: 'POST' });
    } catch (_) {}
    window.location.reload();
  }

  function applyIndexState(user) {
    const topButtons = document.querySelector('.top-buttons');
    if (topButtons) {
      if (user) {
        topButtons.innerHTML =
          '<span class="user-chip">@' +
          escapeHtml(user.username) +
          '</span>';
      } else {
        topButtons.querySelectorAll('.btn').forEach((b) => b.classList.add('pulse-attention'));
      }
    }

    const navLinks = document.querySelectorAll('.sidebar a[data-protected]');
    navLinks.forEach((a) => {
      if (user) {
        a.classList.remove('locked');
        a.removeAttribute('aria-disabled');
      } else {
        a.classList.add('locked');
        a.setAttribute('aria-disabled', 'true');
      }
    });

    const settingsBtn = document.getElementById('settings-btn');
    if (settingsBtn) settingsBtn.hidden = !user;
  }

  function setupIndex() {
    const navLinks = document.querySelectorAll('.sidebar a[data-protected]');
    navLinks.forEach((a) => {
      a.addEventListener('click', (e) => {
        if (a.classList.contains('locked')) {
          e.preventDefault();
          toast('Faça login para acessar esta área.');
        }
      });
    });
  }

  function setupAuthForm(formId, isSignup) {
    const form = document.getElementById(formId);
    if (!form) return;
    const errorEl = document.getElementById('auth-error');
    const submit = form.querySelector('button[type="submit"]');

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      if (errorEl) errorEl.textContent = '';
      const fd = new FormData(form);
      const payload = {};
      for (const [k, v] of fd.entries()) payload[k] = v;

      if (submit) submit.disabled = true;
      try {
        const r = await apiFetch(isSignup ? '/api/signup' : '/api/login', {
          method: 'POST',
          body: payload,
        });
        if (r.ok) {
          if (r.data && r.data.twoFactor) {
            const info = document.getElementById('auth-info');
            if (info) {
              info.textContent = r.data.message;
              info.style.color = 'rgb(0, 255, 234)';
            }
            form.reset();
            if (submit) submit.disabled = false;
            return;
          }
          const next = getParam('next');
          const target = next && next.startsWith('/') ? next : '/';
          window.location.href = target;
        } else {
          if (errorEl) errorEl.textContent = (r.data && r.data.error) || 'Algo deu errado.';
        }
      } catch (err) {
        if (errorEl) errorEl.textContent = 'Erro de conexão. Tente novamente.';
      } finally {
        if (submit) submit.disabled = false;
      }
    });
  }

  function setupGoogleButton() {
    const btn = document.getElementById('google-login');
    if (!btn) return;
    fetch('/api/config', { headers: { 'X-Requested-With': 'xmlhttprequest' } })
      .then((r) => r.json())
      .then((cfg) => {
        if (cfg.googleEnabled) {
          btn.style.display = 'inline-block';
          const next = getParam('next') || '';
          btn.addEventListener('click', () => {
            window.location.href = '/api/auth/google/start' + (next ? '?next=' + encodeURIComponent(next) : '');
          });
        }
      })
      .catch(() => {});
  }

  function setupPasswordToggles() {
    document.querySelectorAll('.pw-toggle').forEach((btn) => {
      btn.addEventListener('click', () => {
        const input = document.getElementById(btn.dataset.target);
        if (!input) return;
        const show = input.type === 'password';
        input.type = show ? 'text' : 'password';
        btn.classList.toggle('show', show);
        btn.setAttribute('aria-label', show ? 'Ocultar senha' : 'Mostrar senha');
        btn.setAttribute('aria-pressed', show ? 'true' : 'false');
      });
    });
  }

  document.addEventListener('DOMContentLoaded', async () => {
    const user = await getMe();

    if (document.querySelector('.sidebar')) {
      setupIndex();
      applyIndexState(user);
    }
    setupAuthForm('login-form', false);
    setupAuthForm('signup-form', true);
    setupGoogleButton();
    setupPasswordToggles();
  });
})();
