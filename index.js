// Minimal OAuth2 helper for Google APIs using refresh_token flow.
// Stores tokens in-memory for the duration of a workflow run.
// Depends on http.fetch provided by the host.

(function() {
  const httpx = require('http@latest');
  const json = require('json@latest');
  
  const TOKEN_URL_DEFAULT = 'https://oauth2.googleapis.com/token';

  const SCOPE_MAP = {
    'gmail': ['https://www.googleapis.com/auth/gmail.modify'],
    'gmail.readonly': ['https://www.googleapis.com/auth/gmail.readonly'],
    'drive': ['https://www.googleapis.com/auth/drive'],
    'drive.readonly': ['https://www.googleapis.com/auth/drive.readonly'],
    'calendar': ['https://www.googleapis.com/auth/calendar'],
    'calendar.readonly': ['https://www.googleapis.com/auth/calendar.readonly'],
    'contacts': ['https://www.googleapis.com/auth/contacts'],
    'contacts.readonly': ['https://www.googleapis.com/auth/contacts.readonly'],
    'directory.readonly': ['https://www.googleapis.com/auth/directory.readonly'],
    'tasks': ['https://www.googleapis.com/auth/tasks'],
    'tasks.readonly': ['https://www.googleapis.com/auth/tasks.readonly'],
    'sheets': ['https://www.googleapis.com/auth/spreadsheets'],
    'sheets.readonly': ['https://www.googleapis.com/auth/spreadsheets.readonly'],
    'docs': ['https://www.googleapis.com/auth/documents'],
    'docs.readonly': ['https://www.googleapis.com/auth/documents.readonly'],
    'slides': ['https://www.googleapis.com/auth/presentations'],
    'slides.readonly': ['https://www.googleapis.com/auth/presentations.readonly'],
    'userinfo.email': ['https://www.googleapis.com/auth/userinfo.email'],
    'userinfo.profile': ['https://www.googleapis.com/auth/userinfo.profile']
  };

  const state = {
    defaults: {
      clientId: null,
      clientSecret: null,
      refreshToken: null,
      tokenEndpoint: TOKEN_URL_DEFAULT
    },
    byScope: {}
  };
  let refreshPromise = null;

  function skewMs() {
    // 60s padding plus small jitter to avoid thundering herd on boundary.
    return 60000 + Math.floor(Math.random() * 5000);
  }

  function aliasScope(name) {
    if (!name) return name;
    return String(name).trim().replace(/:ro$/i, '.readonly');
  }

  function parseScopeInput(input) {
    if (Array.isArray(input)) return input.map(String);
    if (typeof input !== 'string') return [];
    const s = input.trim();
    if (!s) return [];
    try {
      if (s[0] === '[' && s[s.length - 1] === ']') {
        const arr = JSON.parse(s);
        if (Array.isArray(arr)) return arr.map(String);
      }
    } catch {}
    return s.split(/[,\s]+/).filter(Boolean);
  }

  function normalizeScope(input, fallback) {
    const raw = parseScopeInput(input);
    const picked = raw.length ? raw : parseScopeInput(fallback);
    const out = [];
    for (const entry of picked) {
      const key = aliasScope(entry);
      if (key === 'all' || key === '*') {
        for (const list of Object.values(SCOPE_MAP)) {
          for (const m of list) out.push(m);
        }
        continue;
      }
      const mapped = SCOPE_MAP[key];
      if (mapped && mapped.length) {
        for (const m of mapped) out.push(m);
      } else {
        out.push(entry);
      }
    }
    const uniq = Array.from(new Set(out.map((v) => String(v).trim()).filter(Boolean)));
    uniq.sort();
    const scopeString = uniq.join(' ');
    const scopeKey = scopeString || 'default';
    return { scopeList: uniq, scopeString, scopeKey };
  }

  function scopeFromEnv() {
    return sys.env.get('google.scope') || sys.env.get('gauth.scope') || '';
  }

  function getEntry(scopeKey) {
    const key = scopeKey || 'default';
    if (!state.byScope[key]) {
      state.byScope[key] = {
        clientId: state.defaults.clientId,
        clientSecret: state.defaults.clientSecret,
        refreshToken: state.defaults.refreshToken,
        tokenEndpoint: state.defaults.tokenEndpoint,
        accessToken: null,
        expiresAt: 0,
        obtainedAt: 0,
        scope: key === 'default' ? '' : key
      };
    }
    return state.byScope[key];
  }

  function applyConfig(entry, opts) {
    const src = opts || {};
    if (src.clientId) entry.clientId = String(src.clientId);
    if (src.clientSecret) entry.clientSecret = String(src.clientSecret);
    if (src.refreshToken) entry.refreshToken = String(src.refreshToken);
    if (src.tokenEndpoint) entry.tokenEndpoint = String(src.tokenEndpoint);
    if (!entry.clientId) entry.clientId = sys.env.get('gauth.clientId');
    if (!entry.clientSecret) entry.clientSecret = sys.env.get('gauth.clientSecret');
    if (!entry.refreshToken) entry.refreshToken = sys.env.get('gauth.refreshToken');
    if (!entry.tokenEndpoint) entry.tokenEndpoint = sys.env.get('gauth.tokenEndpoint') || TOKEN_URL_DEFAULT;
  }

  function configure(opts) {
    if (opts && typeof opts !== 'object') throw new Error('gauth.configure: options must be object');
    const src = opts || {};
    if (src.scope || src.scopes || src.services) {
      const scopeInfo = normalizeScope(src.scope || src.scopes || src.services, scopeFromEnv());
      const entry = getEntry(scopeInfo.scopeKey);
      applyConfig(entry, src);
      entry.accessToken = null;
      entry.expiresAt = 0;
      entry.obtainedAt = 0;
      entry.scope = scopeInfo.scopeString;
    } else {
      if (src.clientId) state.defaults.clientId = String(src.clientId);
      if (src.clientSecret) state.defaults.clientSecret = String(src.clientSecret);
      if (src.refreshToken) state.defaults.refreshToken = String(src.refreshToken);
      if (src.tokenEndpoint) state.defaults.tokenEndpoint = String(src.tokenEndpoint);
    }
  }

  function setTokens(tokens) {
    if (!tokens || typeof tokens !== 'object') throw new Error('gauth.setTokens: object required');
    const scopeInfo = normalizeScope(tokens.scope || tokens.scopes || tokens.services, scopeFromEnv());
    const entry = getEntry(scopeInfo.scopeKey);
    if (tokens.accessToken) entry.accessToken = String(tokens.accessToken);
    if (typeof tokens.expiresAt === 'number') entry.expiresAt = tokens.expiresAt;
    if (typeof tokens.obtainedAt === 'number') entry.obtainedAt = tokens.obtainedAt;
    if (tokens.refreshToken) entry.refreshToken = String(tokens.refreshToken);
  }

  function clear(opts) {
    if (opts && (opts.scope || opts.scopes || opts.services)) {
      const scopeInfo = normalizeScope(opts.scope || opts.scopes || opts.services, scopeFromEnv());
      const entry = getEntry(scopeInfo.scopeKey);
      entry.accessToken = null;
      entry.expiresAt = 0;
      entry.obtainedAt = 0;
      return;
    }
    Object.keys(state.byScope).forEach((k) => {
      if (state.byScope[k]) {
        state.byScope[k].accessToken = null;
        state.byScope[k].expiresAt = 0;
        state.byScope[k].obtainedAt = 0;
      }
    });
    refreshPromise = null;
  }

  function getAccessToken(opts) {
    const scopeInfo = normalizeScope(opts && (opts.scope || opts.scopes || opts.services), scopeFromEnv());
    const entry = getEntry(scopeInfo.scopeKey);
    applyConfig(entry, opts);
    const now = Date.now();
    if (entry.accessToken && now < entry.expiresAt - skewMs()) {
      return Promise.resolve(entry.accessToken);
    }
    if (!entry.clientId || !entry.clientSecret || !entry.refreshToken) {
      return Promise.reject(new Error('gauth: missing clientId/clientSecret/refreshToken; call configure()'));
    }
    if (refreshPromise) return refreshPromise;
    refreshPromise = httpx.form({ url: entry.tokenEndpoint, method: 'POST', fields: {
      client_id: entry.clientId,
      client_secret: entry.clientSecret,
      refresh_token: entry.refreshToken,
      grant_type: 'refresh_token'
    }}).then(r => {
      const j = r.json || json.parseSafe(r.raw, {});
      if (!j || !j.access_token) {
        const msg = (j && (j.error_description || j.error)) || 'token exchange failed';
        const err = new Error('gauth: ' + msg);
        err.status = r && r.status;
        err.body = j;
        throw err;
      }
      entry.accessToken = j.access_token;
      if (j.refresh_token) entry.refreshToken = j.refresh_token;
      const expiresIn = (typeof j.expires_in === 'number' ? j.expires_in : 3600);
      entry.expiresAt = Date.now() + expiresIn * 1000;
      entry.obtainedAt = Math.floor(Date.now() / 1000);
      entry.scope = scopeInfo.scopeString || entry.scope || '';
      return entry.accessToken;
    }).finally(() => { refreshPromise = null; });
    return refreshPromise;
  }

  function forceRefresh(opts) {
    const scopeInfo = normalizeScope(opts && (opts.scope || opts.scopes || opts.services), scopeFromEnv());
    const entry = getEntry(scopeInfo.scopeKey);
    entry.expiresAt = 0;
    return getAccessToken(opts);
  }

  function authorizationHeader() {
    return getAccessToken().then(tok => 'Authorization: Bearer ' + tok);
  }

  async function getToken(opts) {
    try {
      const scopeInfo = normalizeScope(opts && (opts.scope || opts.scopes || opts.services), scopeFromEnv());
      const tok = await getAccessToken(opts);
      const entry = getEntry(scopeInfo.scopeKey);
      const expiresIn = entry.expiresAt ? Math.max(0, Math.floor((entry.expiresAt - Date.now()) / 1000)) : 0;
      return {
        status: 'ok',
        tokens: {
          access_token: tok,
          expires_in: expiresIn,
          obtained_at: entry.obtainedAt || Math.floor(Date.now() / 1000),
          scope: entry.scope || scopeInfo.scopeString || ''
        }
      };
    } catch (e) {
      return { status: 'error', error: (e && (e.message || e)) || 'unknown' };
    }
  }

  async function auth(opts) {
    const res = await getToken(opts);
    if (res && res.status === 'ok' && res.tokens && res.tokens.access_token) return res.tokens.access_token;
    return '';
  }

  function toJSON() {
    return {
      configured: !!(state.defaults.clientId && state.defaults.clientSecret && state.defaults.refreshToken),
      scopes: Object.keys(state.byScope)
    };
  }

  module.exports = { configure, setTokens, clear, getAccessToken, forceRefresh, authorizationHeader, getToken, auth, toJSON };
})();
