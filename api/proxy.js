// api/proxy.js — CommonJS, proxy de cabeceras HTTP sin restricciones CORS
const https = require('https');
const http  = require('http');

function fetchHeaders(targetUrl, timeoutMs = 12000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('Timeout')), timeoutMs);
    const lib = targetUrl.startsWith('https') ? https : http;
    const req = lib.get(targetUrl, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; WebScan/1.0)',
        'Accept': 'text/html,*/*',
      }
    }, (res) => {
      clearTimeout(timer);
      // Consumir body para liberar conexión (no nos hace falta)
      res.resume();
      const headers = {};
      Object.entries(res.headers).forEach(([k, v]) => {
        headers[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : v;
      });
      resolve({
        ok:       res.statusCode >= 200 && res.statusCode < 400,
        status:   res.statusCode,
        finalUrl: targetUrl,
        headers,
      });
    });
    req.on('error', e => { clearTimeout(timer); reject(e); });
  });
}

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Content-Type', 'application/json');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const target = req.query.url;
  if (!target) return res.status(400).json({ ok: false, error: 'Falta el parámetro url' });
  if (!/^https?:\/\//i.test(target)) return res.status(400).json({ ok: false, error: 'URL no válida' });

  try {
    const result = await fetchHeaders(target);
    return res.status(200).json(result);
  } catch (e) {
    return res.status(502).json({ ok: false, error: e.message || 'Error al contactar con el destino' });
  }
};
