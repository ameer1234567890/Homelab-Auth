'use strict';
const root = document.getElementById('app');
const state = { me: null, users: [], q: '', gateway: false };
const API = '/_auth/api';
// When served at any URL outside /_auth/, we are the login gate in front of the proxied app.
const GATE = !location.pathname.startsWith('/_auth');

/* ---------- helpers ---------- */
const ICONS = {
  sun: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>',
  moon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>',
  plus: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 5v14M5 12h14"/></svg>',
  edit: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z"/></svg>',
  trash: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6M10 11v6M14 11v6"/></svg>',
  key: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="8" cy="15" r="4"/><path d="M10.8 12.2L20 3M16 7l3 3"/></svg>',
  out: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/></svg>',
  logo: '<svg viewBox="0 0 32 32"><rect width="32" height="32" rx="8" fill="var(--primary)"/><path d="M16 6l8 3v6c0 5-3.4 8.6-8 11-4.6-2.4-8-6-8-11V9z" fill="none" stroke="var(--on-primary)" stroke-width="2" stroke-linejoin="round"/><path d="M12.5 16l2.5 2.5 4.5-5" fill="none" stroke="var(--on-primary)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>'
};
const icon = n => { const s = document.createElement('span'); s.style.display = 'contents'; s.innerHTML = ICONS[n]; return s.firstChild; };

function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v === false || v == null) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k in el && k !== 'list') el[k] = v;
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const kid of kids.flat()) if (kid != null && kid !== false) el.append(kid.nodeType ? kid : document.createTextNode(kid));
  return el;
}

async function api(method, url, body) {
  const r = await fetch(url, {
    method, credentials: 'same-origin',
    headers: { 'X-Requested-With': 'fetch', ...(body ? { 'Content-Type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined
  });
  let data = {};
  try { data = await r.json(); } catch (e) {}
  if (!r.ok) { const e = new Error(data.error || 'Request failed (' + r.status + ')'); e.status = r.status; throw e; }
  return data;
}

function toast(msg, bad) {
  const t = h('div', { class: 'toast' + (bad ? ' bad' : '') }, msg);
  document.getElementById('toasts').append(t);
  setTimeout(() => t.remove(), 3500);
}

function applyTheme(t) {
  document.documentElement.dataset.theme = t;
  try { localStorage.setItem('theme', t); } catch (e) {}
  document.cookie = 'hl_theme=' + t + '; Path=/; Max-Age=31536000; SameSite=Lax' + (location.protocol === 'https:' ? '; Secure' : '');
}

function themeSwitch() {
  const b = h('button', { class: 'switch', type: 'button', role: 'switch', title: 'Toggle dark mode' }, h('span', { class: 'knob' }));
  const paint = () => {
    const dark = document.documentElement.dataset.theme === 'dark';
    b.setAttribute('aria-checked', dark);
    b.setAttribute('aria-label', dark ? 'Dark mode on' : 'Dark mode off');
    b.firstChild.replaceChildren(icon(dark ? 'moon' : 'sun'));
  };
  b.addEventListener('click', () => {
    const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
    applyTheme(next); paint();
    if (state.me) api('POST', API + '/me/theme', { theme: next }).catch(() => {});  // remember per user
  });
  paint();
  return b;
}

function openDialog({ title, fields, submit, danger, onSubmit }) {
  const err = h('div', { class: 'err' });
  const btn = h('button', { class: 'btn ' + (danger ? 'danger' : 'primary'), type: 'submit' }, submit);
  const dlg = h('dialog');
  const form = h('form', { class: 'form', method: 'dialog' }, h('h2', null, title), fields, err,
    h('div', { class: 'dlg-actions' }, h('button', { class: 'btn', type: 'button', onclick: () => dlg.close() }, 'Cancel'), btn));
  form.addEventListener('submit', async ev => {
    ev.preventDefault();
    err.textContent = ''; btn.disabled = true;
    try { await onSubmit(); dlg.close(); } catch (e) { err.textContent = e.message; } finally { btn.disabled = false; }
  });
  dlg.append(form);
  dlg.addEventListener('close', () => dlg.remove());
  document.body.append(dlg);
  dlg.showModal();
  const first = dlg.querySelector('input:not([readonly]):not([type=checkbox])');
  if (first) first.focus();
}

const initial = u => (u.display_name || u.username).trim().charAt(0).toUpperCase();
const fmtDate = ts => ts ? new Date(ts * 1000).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' }) : 'Never';

/* ---------- login ---------- */
function renderLogin(rd) {
  const err = h('div', { class: 'err', role: 'alert' });
  const user = h('input', { type: 'text', autocomplete: 'username', required: true, autofocus: true, autocapitalize: 'none' });
  const pass = h('input', { type: 'password', autocomplete: 'current-password', required: true });
  const btn = h('button', { class: 'btn primary', type: 'submit' }, 'Sign in');
  const form = h('form', { class: 'form' },
    h('label', null, 'Username', user), h('label', null, 'Password', pass), err, btn);
  form.addEventListener('submit', async ev => {
    ev.preventDefault(); err.textContent = ''; btn.disabled = true;
    try {
      const d = await api('POST', API + '/login', { username: user.value, password: pass.value, rd });
      if (d.user.theme) applyTheme(d.user.theme);
      if (GATE) return location.reload();           // now authenticated: same URL is proxied to the app
      if (d.redirect) return location.replace(d.redirect);
      state.me = d.user; state.gateway = d.gateway; await renderDashboard();
    } catch (e) { err.textContent = e.message; pass.value = ''; pass.focus(); }
    finally { btn.disabled = false; }
  });
  root.replaceChildren(h('div', { class: 'login' },
    h('div', { class: 'corner' }, themeSwitch()),
    h('div', { class: 'card' },
      h('div', { class: 'logo' }, icon('logo'), 'Homelab Auth'),
      h('h1', null, 'Welcome back'),
      h('p', { class: 'muted' }, 'Sign in to continue'),
      form)));
}

/* ---------- dashboard ---------- */
async function renderDashboard() {
  const me = state.me;
  if (me.theme && me.theme !== document.documentElement.dataset.theme) applyTheme(me.theme);
  if (me.is_admin) await loadUsers();
  const top = h('header', { class: 'topbar' },
    h('div', { class: 'logo' }, icon('logo'), 'Homelab Auth'),
    h('div', { class: 'right' }, state.gateway ? h('a', { class: 'btn', href: '/' }, 'Open app') : null, themeSwitch(),
      h('div', { class: 'who' }, h('div', { class: 'avatar' }, initial(me)),
        h('div', { class: 'txt' }, h('div', { class: 'name' }, me.display_name || me.username), h('div', { class: 'sub' }, me.is_admin ? 'Administrator' : 'User'))),
      h('button', { class: 'btn', onclick: signOut }, icon('out'), 'Sign out')));

  const main = h('main');
  if (me.pw_default) {
    main.append(h('div', { class: 'banner' }, h('span', null, 'You are still using the default password. Please change it.'),
      h('button', { class: 'btn', onclick: ownPasswordDialog }, icon('key'), 'Change password')));
  }
  main.append(h('section', { class: 'card' },
    h('div', { class: 'card-head' }, h('h2', null, 'My account'),
      h('button', { class: 'btn', onclick: ownPasswordDialog }, icon('key'), 'Change password')),
    h('div', { class: 'card-body kv' },
      kv('Username', me.username), kv('Name', me.display_name || '—'), kv('Email', me.email || '—'),
      kv('Groups', me.groups.length ? me.groups.join(', ') : '—'), kv('Last sign-in', fmtDate(me.last_login)))));
  if (me.is_admin) main.append(usersCard());
  root.replaceChildren(top, main);
}
const kv = (k, v) => h('div', null, h('div', { class: 'k' }, k), h('div', { class: 'v' }, v));

async function loadUsers() { state.users = (await api('GET', API + '/users')).users; }

async function signOut() { try { await api('POST', API + '/logout'); } catch (e) {} location.replace('/_auth/'); }

function usersCard() {
  const body = h('div', { class: 'table-wrap' });
  const search = h('input', { type: 'search', placeholder: 'Search users…', value: state.q, 'aria-label': 'Search users' });
  search.addEventListener('input', () => { state.q = search.value; paint(); });
  function paint() {
    const q = state.q.toLowerCase();
    const list = state.users.filter(u => !q || [u.username, u.display_name, u.email, ...u.groups].join(' ').toLowerCase().includes(q));
    if (!list.length) return body.replaceChildren(h('div', { class: 'empty' }, 'No users found'));
    body.replaceChildren(h('table', null,
      h('thead', null, h('tr', null, ['User', 'Email', 'Groups', 'Role', 'Status', 'Last sign-in', ''].map(t => h('th', null, t)))),
      h('tbody', null, list.map(u => h('tr', null,
        h('td', null, h('div', { class: 'person' }, h('div', { class: 'avatar' }, initial(u)),
          h('div', null, h('div', { class: 'n' }, u.display_name || u.username), h('div', { class: 'muted' }, '@' + u.username)))),
        h('td', null, u.email || '—'),
        h('td', null, u.groups.length ? u.groups.map(g => h('span', { class: 'chip' }, g)) : '—'),
        h('td', null, h('span', { class: u.is_admin ? 'role-admin' : '' }, u.is_admin ? 'Admin' : 'User')),
        h('td', null, h('span', { class: 'badge' }, h('span', { class: 'dot' + (u.disabled ? ' off' : '') }), u.disabled ? 'Disabled' : 'Active')),
        h('td', { class: 'muted' }, fmtDate(u.last_login)),
        h('td', { class: 'actions' },
          h('button', { class: 'btn sm ghost', title: 'Edit', 'aria-label': 'Edit ' + u.username, onclick: () => userDialog(u) }, icon('edit')),
          u.id === state.me.id ? null : h('button', { class: 'btn sm ghost danger', title: 'Delete', 'aria-label': 'Delete ' + u.username, onclick: () => deleteDialog(u) }, icon('trash'))))))));
  }
  paint();
  return h('section', { class: 'card' },
    h('div', { class: 'card-head' }, h('h2', null, 'Users'),
      h('div', { class: 'toolbar' }, search, h('button', { class: 'btn primary', onclick: () => userDialog(null) }, icon('plus'), 'Add user'))),
    body);
}

async function refresh() { await loadUsers(); const old = document.querySelector('main section:last-child'); old.replaceWith(usersCard()); }

function userDialog(u) {
  const edit = !!u;
  const f = {
    username: h('input', { type: 'text', value: edit ? u.username : '', readOnly: edit, required: true, autocapitalize: 'none', autocomplete: 'off' }),
    name: h('input', { type: 'text', value: edit ? u.display_name : '', autocomplete: 'off' }),
    email: h('input', { type: 'email', value: edit ? u.email : '', autocomplete: 'off' }),
    groups: h('input', { type: 'text', value: edit ? u.groups.join(', ') : '', autocomplete: 'off', placeholder: 'media, admins' }),
    password: h('input', { type: 'password', required: !edit, autocomplete: 'new-password', minLength: 8 }),
    admin: h('input', { type: 'checkbox', checked: edit && u.is_admin, disabled: edit && u.id === state.me.id }),
    disabled: h('input', { type: 'checkbox', checked: edit && u.disabled, disabled: edit && u.id === state.me.id })
  };
  openDialog({
    title: edit ? 'Edit ' + u.username : 'Add user', submit: edit ? 'Save changes' : 'Create user',
    fields: [
      h('label', null, 'Username', f.username),
      h('label', null, 'Display name', f.name),
      h('label', null, 'Email', f.email),
      h('label', null, 'Groups', f.groups, h('span', { class: 'hint' }, 'Comma separated. Used for per-app access (e.g. ?group=media).')),
      h('label', null, edit ? 'New password' : 'Password', f.password, h('span', { class: 'hint' }, edit ? 'Leave blank to keep the current password. Minimum 8 characters.' : 'Minimum 8 characters.')),
      h('label', { class: 'check' }, f.admin, 'Administrator'),
      edit ? h('label', { class: 'check' }, f.disabled, 'Disabled (cannot sign in)') : null
    ],
    onSubmit: async () => {
      const payload = { display_name: f.name.value, email: f.email.value, groups: f.groups.value, is_admin: f.admin.checked };
      if (f.password.value) payload.password = f.password.value;
      if (edit) { payload.disabled = f.disabled.checked; await api('PATCH', API + '/users/' + u.id, payload); }
      else { payload.username = f.username.value; await api('POST', API + '/users', payload); }
      toast(edit ? 'User updated' : 'User created');
      await refresh();
    }
  });
}

function deleteDialog(u) {
  openDialog({
    title: 'Delete user?', submit: 'Delete', danger: true,
    fields: h('p', { class: 'muted' }, 'This permanently removes @' + u.username + ' and signs them out everywhere.'),
    onSubmit: async () => { await api('DELETE', API + '/users/' + u.id); toast('User deleted'); await refresh(); }
  });
}

function ownPasswordDialog() {
  const cur = h('input', { type: 'password', required: true, autocomplete: 'current-password' });
  const nw = h('input', { type: 'password', required: true, minLength: 8, autocomplete: 'new-password' });
  const again = h('input', { type: 'password', required: true, minLength: 8, autocomplete: 'new-password' });
  openDialog({
    title: 'Change password', submit: 'Update password',
    fields: [h('label', null, 'Current password', cur), h('label', null, 'New password', nw, h('span', { class: 'hint' }, 'Minimum 8 characters.')), h('label', null, 'Repeat new password', again)],
    onSubmit: async () => {
      if (nw.value !== again.value) throw new Error('New passwords do not match');
      await api('POST', API + '/me/password', { current: cur.value, new: nw.value });
      state.me.pw_default = false; toast('Password updated'); await renderDashboard();
    }
  });
}

/* ---------- boot ---------- */
(async function boot() {
  const rd = new URLSearchParams(location.search).get('rd') || '';
  if (GATE) return renderLogin('');
  try {
    const d = await api('GET', API + '/me' + (rd ? '?rd=' + encodeURIComponent(rd) : ''));
    if (d.redirect) return location.replace(d.redirect);
    state.me = d.user; state.gateway = d.gateway; await renderDashboard();
  } catch (e) {
    if (e.status === 401) renderLogin(rd);
    else root.replaceChildren(h('div', { class: 'login' }, h('div', { class: 'card' }, e.message)));
  }
})();
