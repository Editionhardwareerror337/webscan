// api/ssl.js — CommonJS, compatible con Vercel Serverless sin configuración extra
const https = require('https');

function fetchUrl(url, timeoutMs = 10000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('Timeout')), timeoutMs);
    const req = https.get(url, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; WebScan/1.0)',
        'Accept': 'application/json, text/html',
      }
    }, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        clearTimeout(timer);
        resolve({ status: res.statusCode, body: data, headers: res.headers });
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

  const host = (req.query.host || '')
    .trim()
    .replace(/^https?:\/\//, '')
    .replace(/[/?#].*/, '')
    .toLowerCase();

  if (!host) return res.status(400).json({ error: 'Falta el parámetro host' });

  let certs = null;
  let source = '';

  // Fuente 1: Certspotter
  try {
    const r = await fetchUrl(
      `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(host)}&include_subdomains=false&expand=dns_names&expand=cert`,
      8000
    );
    if (r.status === 200) {
      const data = JSON.parse(r.body);
      if (Array.isArray(data) && data.length) {
        certs = data.map(d => ({
          id:            d.id,
          not_before:    d.not_before,
          not_after:     d.not_after,
          name_value:    (d.dns_names || []).join('\n'),
          issuer_name:   (d.cert && d.cert.issuer && (d.cert.issuer.organization || [d.cert.issuer.common_name])[0]) || '',
          signature_alg: (d.cert && d.cert.key && d.cert.key.type) || '',
        }));
        source = 'certspotter';
      }
    }
  } catch (_) {}

  // Fuente 2: crt.sh
  if (!certs) {
    try {
      const r = await fetchUrl(
        `https://crt.sh/?q=${encodeURIComponent(host)}&output=json`,
        10000
      );
      if (r.status === 200) {
        const data = JSON.parse(r.body);
        if (Array.isArray(data) && data.length) {
          certs = data;
          source = 'crtsh';
        }
      }
    } catch (_) {}
  }

  // Fuente 3: Solo DNS
  if (!certs) {
    try {
      const r = await fetchUrl(`https://dns.google/resolve?name=${encodeURIComponent(host)}&type=A`, 5000);
      const d = JSON.parse(r.body);
      const hasA = Array.isArray(d.Answer) && d.Answer.length > 0;
      if (!hasA) return res.status(404).json({ error: `El dominio "${host}" no existe en DNS.` });
      const future = new Date();
      future.setFullYear(future.getFullYear() + 1);
      certs = [{
        id: 'dns-only',
        not_before: new Date().toISOString(),
        not_after: future.toISOString(),
        name_value: host,
        issuer_name: 'Desconocido',
        _dnsOnly: true,
      }];
      source = 'dns';
    } catch (e) {
      return res.status(502).json({ error: 'No se pudo contactar con ninguna fuente SSL: ' + e.message });
    }
  }

  return res.status(200).json({ certs, source, host });
};
