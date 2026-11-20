const byId = id => document.getElementById(id);
const login = byId('login');
const connector = byId('connector');
const message = byId('message');
const statusNames = {
  connected: 'SentinelX connected',
  disconnected: 'SentinelX disconnected',
  unavailable: 'SentinelX unavailable',
  credentials_rejected: 'Credentials need updating',
  rate_limited: 'SentinelX rate limited',
  rejected: 'SentinelX rejected the event'
};

async function api(path, method = 'GET', body = {}) {
  const options = {method, cache: 'no-store'};
  if (method !== 'GET') {
    options.headers = {'Content-Type': 'application/json'};
    options.body = JSON.stringify(body);
  }
  const response = await fetch('/api/' + path, options);
  const result = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(result.detail || 'The portal could not complete the request.');
  return result;
}

function showStatus(status) {
  byId('connection').textContent = statusNames[status] || 'Connection status unavailable';
  byId('connection').dataset.status = status;
  if (connector) {
    byId('save').textContent = status === 'disconnected' ? 'Connect' : 'Update credentials';
    byId('test').disabled = status === 'disconnected';
    byId('disconnect').disabled = status === 'disconnected';
  }
}

async function refreshStatus() {
  try {
    showStatus((await api('status')).status);
  } catch {
    showStatus('unknown');
  }
}

async function perform(button, action) {
  button.disabled = true;
  message.textContent = '';
  try {
    await action();
  } catch (error) {
    message.dataset.error = 'true';
    message.textContent = error.message;
  } finally {
    button.disabled = false;
    await refreshStatus();
  }
}

function renderUser(user) {
  login.hidden = Boolean(user);
  byId('signed-in').hidden = !user;
  byId('settings').hidden = !user?.admin;
  byId('identity').textContent = user ? 'Signed in as ' + user.username : '';
}

if (login) {
  api('session').then(({user}) => renderUser(user)).catch(() => {
    message.textContent = 'Session status unavailable.';
  });
  byId('reveal').onclick = () => {
    const password = byId('password');
    const visible = password.type === 'password';
    password.type = visible ? 'text' : 'password';
    byId('reveal').textContent = visible ? 'Hide' : 'Show';
  };
  login.onsubmit = event => {
    event.preventDefault();
    const data = Object.fromEntries(new FormData(login));
    byId('password').value = '';
    void perform(event.submitter, async () => renderUser((await api('login-attempt', 'POST', data)).user));
  };
  byId('logout').onclick = event => void perform(event.currentTarget, async () => {
    await api('logout', 'POST');
    renderUser(null);
  });
}

if (connector) {
  connector.onsubmit = event => {
    event.preventDefault();
    const data = Object.fromEntries(new FormData(connector));
    byId('token').value = '';
    void perform(event.submitter, async () => {
      await api('integration', 'PUT', data);
      message.dataset.error = 'false';
      message.textContent = 'Connection tested and saved. In the SOC dashboard, select Verify for this connector.';
    });
  };
  byId('test').onclick = event => void perform(event.currentTarget, async () => {
    await api('integration/test', 'POST');
    message.dataset.error = 'false';
    message.textContent = 'SentinelX accepted the connection test.';
  });
  byId('disconnect').onclick = event => void perform(event.currentTarget, async () => {
    await api('integration/disconnect', 'POST');
    message.dataset.error = 'false';
    message.textContent = 'SentinelX integration disconnected.';
  });
}

void refreshStatus();
setInterval(refreshStatus, 15000);
