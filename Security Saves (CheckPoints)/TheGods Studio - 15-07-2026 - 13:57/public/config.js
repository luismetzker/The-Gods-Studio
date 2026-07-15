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

  function toast(msg, ok) {
    var el = document.getElementById('toast');
    if (!el) return;
    el.textContent = msg;
    el.classList.add('show');
    if (ok) el.style.borderColor = 'rgba(0,255,160,0.6)';
    else el.style.borderColor = '';
    clearTimeout(el._t);
    el._t = setTimeout(function () {
      el.classList.remove('show');
    }, 3600);
  }

  async function apiFetch(path, opts) {
    opts = opts || {};
    opts.headers = Object.assign(
      { 'X-Requested-With': 'xmlhttprequest', 'Content-Type': 'application/json' },
      opts.headers || {}
    );
    if (opts.body && typeof opts.body !== 'string') opts.body = JSON.stringify(opts.body);
    var res = await fetch(path, opts);
    var data = null;
    try {
      data = await res.json();
    } catch (_) {}
    return { ok: res.ok, status: res.status, data: data };
  }

  async function getMe() {
    try {
      var res = await fetch('/api/me', { headers: { 'X-Requested-With': 'xmlhttprequest' } });
      if (res.status === 401) return null;
      var j = await res.json();
      return j.authenticated ? j.user : null;
    } catch (_) {
      return null;
    }
  }

  async function logout() {
    try {
      await apiFetch('/api/logout', { method: 'POST' });
    } catch (_) {}
    window.location.href = '/index.html';
  }

  function censorEmail(email) {
    if (!email || !email.includes('@')) return email || '';
    var parts = email.split('@');
    var local = parts[0];
    var domain = parts.slice(1).join('@');
    if (local.length <= 4) return local.charAt(0) + '****@' + domain;
    var first = local.slice(0, 3);
    var last = local.slice(-1);
    var stars = '*'.repeat(Math.max(5, local.length - 4));
    return first + stars + last + '@' + domain;
  }

  // === Estado da página ===
  var user = null;
  var pendingToken = null;
  var pendingAction = null;

  // === Navegação entre seções ===
  function showSection(name) {
    document.querySelectorAll('.config-section').forEach(function (s) {
      s.hidden = s.id !== 'section-' + name;
    });
    document.querySelectorAll('.config-nav[data-section]').forEach(function (a) {
      a.classList.toggle('active', a.getAttribute('data-section') === name);
    });
    if (window.location.hash) {
      try {
        history.replaceState(null, '', window.location.pathname + window.location.search);
      } catch (_) {}
    }
  }

  function setupNav() {
    document.querySelectorAll('.config-nav[data-section]').forEach(function (a) {
      a.addEventListener('click', function (e) {
        e.preventDefault();
        showSection(a.getAttribute('data-section'));
      });
    });
    var back = document.querySelector('.config-nav.back');
    if (back) back.addEventListener('click', function () {});
  }

  // === HUD da conta ===
  function renderHud() {
    if (!user) return;
    document.getElementById('hud-username').textContent = '@' + user.username;
    document.getElementById('hud-email').textContent = censorEmail(user.email);
    document.getElementById('hud-password').textContent = '**********';

    var verifyBtn = document.getElementById('verify-email-btn');
    if (user.emailVerified) {
      verifyBtn.textContent = 'Verificado com Sucesso';
      verifyBtn.classList.add('verified');
      verifyBtn.disabled = true;
    } else {
      verifyBtn.textContent = 'Verificar';
      verifyBtn.classList.remove('verified');
      verifyBtn.disabled = false;
    }
  }

  // === Verificar e-mail ===
  function setupVerifyEmail() {
    document.getElementById('verify-email-btn').addEventListener('click', async function () {
      if (user.emailVerified) return;
      var r = await apiFetch('/api/account/request-verify-email', { method: 'POST' });
      if (r.ok) {
        toast('Enviamos um link de verificação para o seu e-mail. Abra-o para confirmar.', true);
      } else {
        toast((r.data && r.data.error) || 'Não foi possível enviar o e-mail.');
      }
    });
  }

  // === Editar nome de usuário (direto) ===
  function setupEditUsername() {
    var form = document.getElementById('edit-username-form');
    var err = document.getElementById('username-error');
    document.getElementById('edit-username-btn').addEventListener('click', function () {
      form.hidden = !form.hidden;
      err.textContent = '';
      if (!form.hidden) document.getElementById('new-username').value = user.username;
    });
    document.getElementById('cancel-username').addEventListener('click', function () {
      form.hidden = true;
    });
    form.addEventListener('submit', async function (e) {
      e.preventDefault();
      err.textContent = '';
      var name = document.getElementById('new-username').value.trim();
      var r = await apiFetch('/api/account/change-username', {
        method: 'POST',
        body: { username: name },
      });
      if (r.ok) {
        user.username = r.data.username;
        renderHud();
        form.hidden = true;
        toast('Nome de usuário atualizado.', true);
      } else {
        err.textContent = (r.data && r.data.error) || 'Não foi possível alterar.';
      }
    });
  }

  // === Editar e-mail (confirmação por e-mail) ===
  function setupEditEmail() {
    var form = document.getElementById('edit-email-form');
    var msg = document.getElementById('email-msg');
    document.getElementById('edit-email-btn').addEventListener('click', function () {
      form.hidden = !form.hidden;
      msg.textContent = '';
    });
    document.getElementById('cancel-email').addEventListener('click', function () {
      form.hidden = true;
    });
    form.addEventListener('submit', async function (e) {
      e.preventDefault();
      msg.textContent = '';
      var r = await apiFetch('/api/account/request-change-email', { method: 'POST' });
      if (r.ok) {
        form.hidden = true;
        toast('Link de confirmação enviado para o seu e-mail atual.', true);
      } else {
        msg.textContent = (r.data && r.data.error) || 'Não foi possível enviar.';
      }
    });
  }

  // === Editar senha (confirmação por e-mail) ===
  function setupEditPassword() {
    var form = document.getElementById('edit-password-form');
    document.getElementById('edit-password-btn').addEventListener('click', function () {
      form.hidden = !form.hidden;
    });
    document.getElementById('cancel-password').addEventListener('click', function () {
      form.hidden = true;
    });
    form.addEventListener('submit', async function (e) {
      e.preventDefault();
      var r = await apiFetch('/api/account/request-change-password', { method: 'POST' });
      if (r.ok) {
        form.hidden = true;
        toast('Link de confirmação enviado para o seu e-mail.', true);
      } else {
        toast((r.data && r.data.error) || 'Não foi possível enviar.');
      }
    });
  }

  // === Esqueci minha senha ===
  function setupForgotPassword() {
    document.getElementById('forgot-password-btn').addEventListener('click', async function () {
      var r = await apiFetch('/api/account/forgot-password', { method: 'POST' });
      if (r.ok) {
        toast('Enviamos um link de redefinição para o seu e-mail.', true);
      } else {
        toast((r.data && r.data.error) || 'Não foi possível enviar.');
      }
    });
  }

  // === Formulários autorizados por link de e-mail ===
  function setupAuthorizedForms() {
    var emailForm = document.getElementById('authorized-email-form');
    var emailErr = document.getElementById('auth-email-error');
    emailForm.addEventListener('submit', async function (e) {
      e.preventDefault();
      emailErr.textContent = '';
      var newEmail = document.getElementById('auth-new-email').value.trim();
      var r = await apiFetch('/api/account/change-email', {
        method: 'POST',
        body: { token: pendingToken, newEmail: newEmail },
      });
      if (r.ok) {
        user.email = newEmail;
        user.emailVerified = false;
        toast('E-mail alterado com sucesso.', true);
        cleanReload();
      } else {
        emailErr.textContent = (r.data && r.data.error) || 'Não foi possível alterar.';
      }
    });

    var pwForm = document.getElementById('authorized-password-form');
    var pwErr = document.getElementById('auth-password-error');
    pwForm.addEventListener('submit', async function (e) {
      e.preventDefault();
      pwErr.textContent = '';
      var next = document.getElementById('auth-new-password').value;
      var r = await apiFetch('/api/account/set-password', {
        method: 'POST',
        body: { token: pendingToken, next: next },
      });
      if (r.ok) {
        toast('Senha alterada com sucesso.', true);
        cleanReload();
      } else {
        pwErr.textContent = (r.data && r.data.error) || 'Não foi possível alterar.';
      }
    });
  }

  function showAuthorizedForm() {
    // Esconde HUD normal e mostra o formulário autorizado
    document.getElementById('edit-username-form').hidden = true;
    document.getElementById('edit-email-form').hidden = true;
    document.getElementById('edit-password-form').hidden = true;
    if (pendingAction === 'change_email') {
      document.getElementById('authorized-email-form').hidden = false;
    } else if (pendingAction === 'change_password' || pendingAction === 'reset_password') {
      document.getElementById('authorized-password-form').hidden = false;
    }
    showSection('account');
  }

  function cleanReload() {
    window.location.href = '/config.html';
  }

  // === Segurança: 2FA ===
  function setupTwoFactor() {
    var btn = document.getElementById('twofa-toggle');
    function render() {
      if (user.twoFactorEnabled) {
        btn.textContent = 'Desativar';
        btn.classList.remove('btn-primary');
      } else {
        btn.textContent = 'Ativar';
        btn.classList.add('btn-primary');
      }
    }
    render();
    btn.addEventListener('click', async function () {
      var enabling = !user.twoFactorEnabled;
      if (enabling && !window.confirm('Ativar a verificação de duas etapas? Você precisará confirmar o login por e-mail.')) return;
      if (!enabling && !window.confirm('Desativar a verificação de duas etapas?')) return;
      var r = await apiFetch('/api/account/set-two-factor', {
        method: 'POST',
        body: { enabled: enabling },
      });
      if (r.ok) {
        user.twoFactorEnabled = r.data.twoFactorEnabled;
        render();
        toast(enabling ? 'Verificação de duas etapas ativada.' : 'Verificação de duas etapas desativada.', true);
      } else {
        toast((r.data && r.data.error) || 'Não foi possível alterar.');
      }
    });
  }

  // === Segurança: dispositivos ===
  async function loadSessions() {
    var list = document.getElementById('devices-list');
    var r = await apiFetch('/api/account/sessions', { method: 'GET' });
    if (!r.ok) {
      list.innerHTML = '<p class="hint">Não foi possível carregar os dispositivos.</p>';
      return;
    }
    var sessions = r.data.sessions || [];
    list.innerHTML = '';
    if (!sessions.length) {
      list.innerHTML = '<p class="hint">Nenhum dispositivo encontrado.</p>';
      return;
    }
    sessions.forEach(function (s) {
      var row = document.createElement('div');
      row.className = 'device-row';
      var info = document.createElement('div');
      info.className = 'device-info';
      var when = new Date(s.lastSeen).toLocaleString('pt-BR');
      info.innerHTML =
        '<span class="device-name">' +
        escapeHtml(s.device) +
        (s.current ? ' (este dispositivo)' : '') +
        '</span>' +
        '<span class="device-meta">' +
        escapeHtml(s.location) +
        ' · visto em ' +
        escapeHtml(when) +
        '</span>';
      var btn = document.createElement('button');
      btn.className = 'btn-mini btn-danger';
      btn.textContent = 'Desconectar';
      btn.addEventListener('click', function () {
        requestDisconnect(s.id);
      });
      row.appendChild(info);
      row.appendChild(btn);
      list.appendChild(row);
    });
  }

  function requestDisconnect(sessionId) {
    apiFetch('/api/account/request-disconnect', {
      method: 'POST',
      body: { sessionId: sessionId },
    }).then(function (r) {
      if (r.ok) {
        toast('Link de confirmação enviado para o seu e-mail.', true);
      } else {
        toast((r.data && r.data.error) || 'Não foi possível enviar.');
      }
    });
  }

  function setupDisconnectAll() {
    document.getElementById('disconnect-all-btn').addEventListener('click', function () {
      if (!window.confirm('Desconectar TODOS os dispositivos? Isso pedirá confirmação por e-mail.')) return;
      apiFetch('/api/account/request-disconnect-all', { method: 'POST' }).then(function (r) {
        if (r.ok) {
          toast('Link de confirmação enviado para o seu e-mail.', true);
        } else {
          toast((r.data && r.data.error) || 'Não foi possível enviar.');
        }
      });
    });
  }

  // === Mostrar/ocultar senha ===
  function setupPasswordToggles() {
    document.querySelectorAll('.pw-toggle').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var input = document.getElementById(btn.dataset.target);
        if (!input) return;
        var show = input.type === 'password';
        input.type = show ? 'text' : 'password';
        btn.classList.toggle('show', show);
        btn.setAttribute('aria-pressed', String(show));
      });
    });
  }

  // === Tratar parâmetros de URL (links de e-mail) ===
  function handleUrlParams() {
    var verified = getParam('verified');
    var disconnected = getParam('disconnected');
    pendingAction = getParam('action');
    pendingToken = getParam('token');

    if (verified) {
      toast('E-mail verificado com sucesso!', true);
    }
    if (disconnected) {
      toast('Dispositivo(s) desconectado(s) com sucesso.', true);
    }
    if (pendingAction && pendingToken) {
      showAuthorizedForm();
    } else {
      showSection('account');
    }

    // Limpa a query string sem recarregar
    if (verified || disconnected || pendingAction || pendingToken) {
      try {
        history.replaceState(null, '', '/config.html');
      } catch (_) {}
    }
  }

  // === Init ===
  async function init() {
    user = await getMe();
    if (!user) {
      window.location.href = '/login.html?next=/config.html';
      return;
    }
    setupNav();
    setupVerifyEmail();
    setupEditUsername();
    setupEditEmail();
    setupEditPassword();
    setupForgotPassword();
    setupAuthorizedForms();
    setupTwoFactor();
    setupDisconnectAll();
    setupPasswordToggles();

    document.getElementById('logout-btn').addEventListener('click', function (e) {
      e.preventDefault();
      logout();
    });

    renderHud();
    handleUrlParams();
    loadSessions();
  }

  document.addEventListener('DOMContentLoaded', init);
})();
