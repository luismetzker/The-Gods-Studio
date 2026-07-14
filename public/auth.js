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

  async function sha256Hex(str) {
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
    return Array.from(new Uint8Array(buf))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
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

  async function solveCaptcha() {
    const res = await fetch('/api/captcha');
    const { token, challenge, difficulty } = await res.json();
    const target = '0'.repeat(difficulty);
    let nonce = 0;
    while (true) {
      const h = await sha256Hex(challenge + ':' + nonce);
      if (h.startsWith(target)) return { token, nonce: String(nonce) };
      nonce++;
      if (nonce > 20000000) throw new Error('captcha');
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
          '</span><button class="btn btn-outline" id="logout-top">Sair</button>';
        const lb = document.getElementById('logout-top');
        if (lb) lb.addEventListener('click', logout);
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
    if (settingsBtn) {
      settingsBtn.hidden = !user;
      if (user) {
        const info = document.getElementById('settings-info');
        if (info) info.textContent = 'Conectado como ' + user.email;
      }
    }
  }

  function setupSettingsModal() {
    const modal = document.getElementById('settings-modal');
    const openBtn = document.getElementById('settings-btn');
    const closeBtn = document.getElementById('settings-close');
    const form = document.getElementById('change-pw-form');
    const errEl = document.getElementById('change-pw-error');

    if (!modal) return;
    const open = () => modal.classList.add('open');
    const close = () => modal.classList.remove('open');

    if (openBtn) openBtn.addEventListener('click', open);
    if (closeBtn) closeBtn.addEventListener('click', close);
    modal.addEventListener('click', (e) => {
      if (e.target === modal) close();
    });

    const logoutModal = document.getElementById('logout-btn-modal');
    if (logoutModal) logoutModal.addEventListener('click', logout);

    if (form) {
      form.addEventListener('submit', async (e) => {
        e.preventDefault();
        if (errEl) errEl.textContent = '';
        const fd = new FormData(form);
        const current = fd.get('current') || '';
        const next = fd.get('next') || '';
        const r = await apiFetch('/api/change-password', {
          method: 'POST',
          body: { current, next },
        });
        if (r.ok) {
          form.reset();
          close();
          toast('Senha alterada com sucesso.');
        } else {
          if (errEl) errEl.textContent = (r.data && r.data.error) || 'Não foi possível alterar a senha.';
        }
      });
    }
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
    setupSettingsModal();
  }

  function setupAuthForm(formId, isSignup) {
    const form = document.getElementById(formId);
    if (!form) return;
    const errorEl = document.getElementById('auth-error');
    const submit = form.querySelector('button[type="submit"]');
    const captchaStatus = document.getElementById('captcha-status');

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      if (errorEl) errorEl.textContent = '';
      const fd = new FormData(form);
      const payload = {};
      for (const [k, v] of fd.entries()) payload[k] = v;

      if (submit) submit.disabled = true;
      try {
        if (isSignup) {
          if (captchaStatus) {
            captchaStatus.className = 'captcha-status';
            captchaStatus.textContent = 'Verificando que você não é um robô...';
          }
          const cap = await solveCaptcha();
          payload.captchaToken = cap.token;
          payload.captchaNonce = cap.nonce;
          if (captchaStatus) {
            captchaStatus.className = 'captcha-status ok';
            captchaStatus.textContent = 'Verificado ✓';
          }
        }
        const r = await apiFetch(isSignup ? '/api/signup' : '/api/login', {
          method: 'POST',
          body: payload,
        });
        if (r.ok) {
          const next = getParam('next');
          const target = next && next.startsWith('/') ? next : '/';
          window.location.href = target;
        } else {
          if (errorEl) errorEl.textContent = (r.data && r.data.error) || 'Algo deu errado.';
          if (captchaStatus) {
            captchaStatus.className = 'captcha-status fail';
            captchaStatus.textContent = 'Tente novamente.';
          }
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
        btn.textContent = show ? '🙈' : '👁';
        btn.setAttribute('aria-label', show ? 'Ocultar senha' : 'Mostrar senha');
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
