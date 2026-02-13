/* ── toast helper ──────────────── */
export function toast(msg, type) {
  const t = document.createElement('div');
  t.className = 'toast' + (type ? ' ' + type : '');
  t.textContent = msg;
  document.getElementById('toasts').appendChild(t);
  setTimeout(() => t.remove(), 4000);
}

export function fmtSize(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / 1048576).toFixed(1) + ' MB';
}

function _normalizeBase(base) {
  const raw = String(base || '').trim();
  if (!raw || raw === '/') return '';
  return raw.replace(/\/+$/, '');
}

function _rootPathBase() {
  return _normalizeBase(window.__WELLSPRING_ROOT_PATH__ || '');
}

function _explicitApiBase() {
  return _normalizeBase(window.__WELLSPRING_API_BASE__ || '');
}

export function apiUrl(path) {
  const rawPath = String(path || '');
  if (/^https?:\/\//i.test(rawPath) || rawPath.startsWith('//')) return rawPath;
  const normalizedPath = rawPath.startsWith('/') ? rawPath : '/' + rawPath;
  const base = _explicitApiBase() || _rootPathBase();
  return `${base}${normalizedPath}`;
}

export function apiFetch(path, init) {
  return fetch(apiUrl(path), init);
}
