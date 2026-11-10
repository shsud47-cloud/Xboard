/*
 * In-app passkeys for the Xboard member theme and the admin panel.
 * Matches Dee Panel (dee.finn47.xyz): register only after a password session,
 * login with 「使用通行钥匙」, cancel/timeout shows 「已取消或超时」, challenge is
 * 5 minutes. Cross-device login is the browser/OS WebAuthn hybrid dialog
 * (the system QR), not a TOTP QR drawn by this page. Dee Panel's login
 * options omit allowCredentials so that dialog includes "use a phone".
 */
(function () {
  if (window.__xboardPasskey) return;
  window.__xboardPasskey = true;

  var API = '/api/v1';

  function $(sel, root) { return (root || document).querySelector(sel); }
  function b64urlToBuf(s) {
    s = String(s || '').replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    var bin = atob(s);
    var u = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
    return u.buffer;
  }
  function bufToB64url(buf) {
    var u = new Uint8Array(buf);
    var s = '';
    for (var i = 0; i < u.length; i++) s += String.fromCharCode(u[i]);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  }
  function publicKeyOptionsFromJson(o) {
    var opts = JSON.parse(JSON.stringify(o || {}));
    if (opts.challenge) opts.challenge = b64urlToBuf(opts.challenge);
    if (opts.user && opts.user.id) opts.user.id = b64urlToBuf(opts.user.id);
    ['excludeCredentials', 'allowCredentials'].forEach(function (key) {
      if (opts[key]) opts[key] = opts[key].map(function (c) { c.id = b64urlToBuf(c.id); return c; });
    });
    return opts;
  }
  function credentialToJSON(cred) {
    var rid = bufToB64url(cred.rawId);
    return {
      id: rid,
      rawId: rid,
      type: cred.type || 'public-key',
      clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
      authenticatorAttachment: cred.authenticatorAttachment || undefined,
      response: {
        clientDataJSON: bufToB64url(cred.response.clientDataJSON),
        attestationObject: cred.response.attestationObject ? bufToB64url(cred.response.attestationObject) : undefined,
        authenticatorData: cred.response.authenticatorData ? bufToB64url(cred.response.authenticatorData) : undefined,
        signature: cred.response.signature ? bufToB64url(cred.response.signature) : undefined,
        userHandle: cred.response.userHandle ? bufToB64url(cred.response.userHandle) : undefined
      }
    };
  }
  function passkeyDefaultName() {
    try {
      var ua = navigator.userAgent || '';
      if (/iPad|Macintosh/.test(ua) && navigator.maxTouchPoints > 1) return 'iPad';
      if (/Android/i.test(ua)) return 'Android';
      if (/Mac OS X/.test(ua) && !/iPhone|iPad/.test(ua)) return 'Mac';
      if (/Windows/i.test(ua)) return 'Windows';
      if (/iPhone/.test(ua)) return 'iPhone';
    } catch (e) {}
    return '本机';
  }
  function readStored(prefix, storage) {
    try {
      var raw = storage.getItem((prefix + 'access_token').toUpperCase());
      if (!raw) return '';
      var parsed = JSON.parse(raw);
      if (parsed.expire && Date.now() > parsed.expire) return '';
      return parsed.value || '';
    } catch (e) { return ''; }
  }
  function writeStored(prefix, storage, value, seconds) {
    storage.setItem((prefix + 'access_token').toUpperCase(), JSON.stringify({
      value: value,
      time: Date.now(),
      expire: Date.now() + seconds * 1000
    }));
  }
  function isAdminUi() {
    return !!(document.getElementById('root') && window.settings && typeof window.settings.secure_path === 'string');
  }
  function hashPath() {
    var h = location.hash || '';
    var q = h.indexOf('?');
    return (q >= 0 ? h.slice(0, q) : h);
  }
  function routeIs(hashPrefix, pathSuffix) {
    var h = hashPath();
    if (h === hashPrefix || h.indexOf(hashPrefix + '/') === 0) return true;
    if (!pathSuffix) return false;
    var p = location.pathname || '';
    return p === pathSuffix || p.slice(-pathSuffix.length) === pathSuffix;
  }
  async function api(path, options) {
    options = options || {};
    var headers = { Accept: 'application/json' };
    if (options.token) headers.Authorization = options.token;
    var init = { method: options.method || 'GET', headers: headers, credentials: 'same-origin' };
    if (options.body !== undefined) {
      headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(options.body);
    }
    var res = await fetch(API + path, init);
    var json = await res.json().catch(function () { return {}; });
    if (!res.ok || json.status === 'fail') {
      var err = new Error(json.message || '请求失败');
      err.status = res.status;
      throw err;
    }
    return json.data;
  }
  function cancelled(e) {
    return e && (e.name === 'NotAllowedError' || e.name === 'AbortError');
  }
  function ensureStyle() {
    if (document.getElementById('xb-passkey-style')) return;
    var style = document.createElement('style');
    style.id = 'xb-passkey-style';
    style.textContent = [
      '.xb-pk-btn{width:100%;margin-top:10px}',
      '.xb-pk-hint{margin:8px 0 0;font-size:12px;line-height:1.5;color:#888;text-align:center}',
      '.xb-pk-card{margin-top:16px;padding:16px;border:1px solid rgba(127,127,127,.28);border-radius:12px}',
      '.xb-pk-card h3{margin:0 0 6px;font-size:16px}',
      '.xb-pk-row{display:flex;justify-content:space-between;gap:12px;align-items:flex-start;flex-wrap:wrap}',
      '.xb-pk-item{display:flex;justify-content:space-between;gap:8px;align-items:center;padding:8px 0;border-bottom:1px dashed rgba(127,127,127,.35)}',
      '.xb-pk-actions{display:flex;gap:8px;flex-wrap:wrap}',
      '.xb-pk-actions button,.xb-pk-item button{cursor:pointer}',
      '.xb-pk-err{color:#dc2626;font-size:13px;margin-top:8px}'
    ].join('');
    document.head.appendChild(style);
  }
  function el(tag, attrs, text) {
    var node = document.createElement(tag);
    if (attrs) Object.keys(attrs).forEach(function (k) {
      if (k === 'class') node.className = attrs[k];
      else if (k.indexOf('on') === 0 && typeof attrs[k] === 'function') node.addEventListener(k.slice(2), attrs[k]);
      else node.setAttribute(k, attrs[k]);
    });
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function emailValue() {
    var input = document.querySelector('input[autocomplete="username"], input[autocomplete="email"], input[type="email"]');
    return input ? String(input.value || '').trim() : '';
  }

  async function runAssertion(email, forAdmin) {
    var data = await api('/passport/auth/passkey/options', {
      method: 'POST',
      body: { email: email, for_admin: !!forAdmin }
    });
    var cred = await navigator.credentials.get({ publicKey: publicKeyOptionsFromJson(data.options) });
    return api('/passport/auth/passkey/login', {
      method: 'POST',
      body: {
        credential: credentialToJSON(cred),
        challenge: data.challenge,
        email: email,
        for_admin: !!forAdmin
      }
    });
  }

  function mountLogin(anchor, forAdmin) {
    if (!anchor || !anchor.parentNode || anchor.parentNode.querySelector('[data-xb-passkey-login]')) return;
    if (!window.PublicKeyCredential) return;
    ensureStyle();
    var wrap = el('div', { 'data-xb-passkey-login': '1' });
    var btn = el('button', { type: 'button', class: (anchor.className || '') + ' xb-pk-btn' }, '使用通行钥匙');
    wrap.hidden = true;
    var hint = el('div', { class: 'xb-pk-hint' }, '也可在系统弹窗里选择手机扫码');
    var err = el('div', { class: 'xb-pk-err' });
    hint.hidden = true;
    wrap.appendChild(btn);
    wrap.appendChild(hint);
    wrap.appendChild(err);
    anchor.insertAdjacentElement('afterend', wrap);

    async function refresh() {
      try {
        var email = emailValue();
        var q = '/passport/auth/passkey/status?for_admin=' + (forAdmin ? '1' : '0');
        if (email) q += '&email=' + encodeURIComponent(email);
        var st = await api(q);
        var show = email ? !!st.available : !!st.enabled;
        wrap.hidden = !show;
        hint.hidden = !show;
      } catch (e) {
        wrap.hidden = true;
      }
    }
    btn.addEventListener('click', async function () {
      err.textContent = '';
      btn.disabled = true;
      var prev = btn.textContent;
      btn.textContent = '等待面容/指纹…';
      try {
        var out = await runAssertion(emailValue(), forAdmin);
        if (forAdmin && !out.is_admin) throw new Error('该账号不能登录管理后台');
        if (forAdmin) {
          writeStored('Xboard_', localStorage, out.auth_data, 259200);
          location.hash = '#/';
        } else {
          writeStored('Vue_Naive_', localStorage, out.auth_data, 21600);
          location.hash = '#/dashboard';
        }
        location.reload();
      } catch (e) {
        err.textContent = cancelled(e) ? '已取消或超时' : (e.message || '通行钥匙登录失败');
      } finally {
        btn.disabled = false;
        btn.textContent = prev;
      }
    });
    document.addEventListener('input', function (ev) {
      if (ev.target && (ev.target.type === 'email' || ev.target.autocomplete === 'email' || ev.target.autocomplete === 'username')) refresh();
    });
    refresh();
  }

  function findLoginButton(labels) {
    var buttons = document.querySelectorAll('button');
    for (var i = 0; i < buttons.length; i++) {
      var text = (buttons[i].textContent || '').replace(/\s+/g, '');
      if (labels.indexOf(text) >= 0 && !buttons[i].closest('[data-xb-passkey-login]')) return buttons[i];
    }
    return null;
  }

  function renderManager(box, token) {
    box.innerHTML = '';
    var title = el('h3', null, '登录安全');
    var head = el('div', { class: 'xb-pk-row' });
    var intro = el('div');
    intro.appendChild(el('b', null, '通行钥匙（Face ID / 触控 ID）'));
    var sub = el('div', { class: 'xb-pk-hint', style: 'text-align:left;margin:4px 0 0' });
    intro.appendChild(sub);
    var reg = el('button', { type: 'button', class: 'xb-pk-btn', style: 'width:auto;margin:0' }, '在本机注册');
    head.appendChild(intro);
    head.appendChild(reg);
    var list = el('div');
    var msg = el('div', { class: 'xb-pk-err' });
    box.appendChild(title);
    box.appendChild(head);
    box.appendChild(list);
    box.appendChild(msg);
    box.appendChild(el('div', { class: 'xb-pk-hint', style: 'text-align:left' }, '电脑上登录时，在系统弹窗里选择手机扫码。这是通行钥匙的跨设备登录，不是两步验证二维码。密码登录仍然可用。'));

    if (!window.PublicKeyCredential) {
      sub.textContent = '当前浏览器不支持通行钥匙';
      reg.disabled = true;
      return;
    }

    async function load() {
      var data = await api('/user/passkey', { token: token });
      var creds = data.credentials || [];
      sub.textContent = creds.length
        ? ('已注册 ' + creds.length + ' 枚。登录页会出现「使用通行钥匙」。')
        : '尚未注册；注册后可在登录页一键登录，无需密码。';
      list.innerHTML = '';
      creds.forEach(function (c) {
        var row = el('div', { class: 'xb-pk-item' });
        var meta = el('div');
        meta.appendChild(el('b', null, c.name || 'Passkey'));
        var when = c.created ? new Date(c.created * 1000).toLocaleString() : '';
        meta.appendChild(el('div', { class: 'xb-pk-hint', style: 'text-align:left;margin:0' }, when + (c.backed_up ? ' · 已同步' : '')));
        var del = el('button', { type: 'button' }, '删除');
        del.addEventListener('click', async function () {
          if (!confirm('确定删除这枚通行钥匙？')) return;
          try {
            await api('/user/passkey/delete', { method: 'POST', token: token, body: { id: c.id } });
            load();
          } catch (e) { msg.textContent = e.message || '删除失败'; }
        });
        row.appendChild(meta);
        row.appendChild(del);
        list.appendChild(row);
      });
    }

    reg.addEventListener('click', async function () {
      msg.textContent = '';
      reg.disabled = true;
      try {
        var data = await api('/user/passkey/options', { method: 'POST', token: token, body: {} });
        var cred = await navigator.credentials.create({ publicKey: publicKeyOptionsFromJson(data.options) });
        var transports = [];
        try { if (cred.response.getTransports) transports = cred.response.getTransports(); } catch (e) {}
        var name = passkeyDefaultName();
        await api('/user/passkey/register', {
          method: 'POST',
          token: token,
          body: { credential: credentialToJSON(cred), challenge: data.challenge, name: name, transports: transports }
        });
        msg.style.color = '#16a34a';
        msg.textContent = '通行钥匙已注册（' + name + '）';
        await load();
      } catch (e) {
        msg.style.color = '#dc2626';
        msg.textContent = cancelled(e) ? '已取消或超时' : (e.message || '注册失败');
      } finally {
        reg.disabled = false;
      }
    });
    load().catch(function (e) { msg.textContent = e.message || '加载失败'; });
  }

  function mountManager(anchor, token, where) {
    if (!anchor || document.querySelector('[data-xb-passkey-manage]')) return;
    ensureStyle();
    var box = el('div', { class: 'xb-pk-card', 'data-xb-passkey-manage': '1' });
    if (where === 'before') anchor.parentNode.insertBefore(box, anchor);
    else anchor.insertAdjacentElement('afterend', box);
    renderManager(box, token);
  }

  function tick() {
    var admin = isAdminUi();
    if (admin) {
      if (routeIs('#/sign-in', '/sign-in')) {
        var loginBtn = findLoginButton(['登录', '登入', 'Login', 'Signin', 'Войти']);
        if (loginBtn) mountLogin(loginBtn, true);
      }
      if (routeIs('#/config/system/safe', '/config/system/safe')) {
        var token = readStored('Xboard_', localStorage);
        if (!token) return;
        var heading = null;
        var titles = ['安全设置', 'Security Settings'];
        document.querySelectorAll('h1,h2,h3').forEach(function (node) {
          if (!heading && titles.indexOf((node.textContent || '').trim()) >= 0) heading = node;
        });
        if (heading) mountManager(heading, token, 'before');
      }
      return;
    }
    if (routeIs('#/login', '/login')) {
      var userBtn = findLoginButton(['登入', '登录', 'Login', 'ログイン', '로그인']);
      if (userBtn) mountLogin(userBtn, false);
    }
    if (routeIs('#/profile', '/profile')) {
      var userToken = readStored('Vue_Naive_', localStorage);
      if (!userToken) return;
      var cardTitle = null;
      var titles = ['修改密码', 'Change Password'];
      document.querySelectorAll('div,span,h1,h2,h3').forEach(function (node) {
        if (!cardTitle && node.childNodes.length <= 3 && titles.indexOf((node.textContent || '').trim()) >= 0) cardTitle = node;
      });
      if (!cardTitle) return;
      var card = cardTitle.closest('.n-card') || cardTitle.parentElement;
      if (card) mountManager(card, userToken, 'after');
    }
  }

  var scheduled = false;
  function schedule() {
    if (scheduled) return;
    scheduled = true;
    requestAnimationFrame(function () { scheduled = false; tick(); });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', schedule);
  else schedule();
  window.addEventListener('hashchange', schedule);
  new MutationObserver(schedule).observe(document.documentElement, { childList: true, subtree: true });
})();
