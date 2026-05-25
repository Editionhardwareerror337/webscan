// api/ssl.js — Proxy serverless para SSL (Certspotter + crt.sh)
// Se ejecuta en el servidor de Vercel, sin restricciones CORS

export default async function handler(req, res) {
  // Cabeceras CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const host = (req.query.host || '').trim()
    .replace(/^https?:\/\//, '')
    .replace(/[/?#].*/, '')
    .toLowerCase();

  if (!host) return res.status(400).json({ error: 'Falta el parámetro host' });

  let certs = null;
  let source = '';

  // ── Fuente 1: Certspotter ──────────────────────────────────────────
  try {
    const r = await fetch(
      `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(host)}&include_subdomains=false&expand=dns_names&expand=cert`,
      { signal: AbortSignal.timeout(8000) }
    );
    if (r.ok) {
      const data = await r.json();
      if (Array.isArray(data) && data.length) {
        certs = data.map(d => ({
          id:            d.id,
          not_before:    d.not_before,
          not_after:     d.not_after,
          name_value:    (d.dns_names || []).join('\n'),
          issuer_name:   d.cert?.issuer?.organization?.[0] || d.cert?.issuer?.common_name || '',
          signature_alg: d.cert?.key?.type || '',
        }));
        source = 'certspotter';
      }
    }
  } catch (_) {}

  // ── Fuente 2: crt.sh ──────────────────────────────────────────────
  if (!certs) {
    try {
      const r = await fetch(
        `https://crt.sh/?q=${encodeURIComponent(host)}&output=json`,
        { signal: AbortSignal.timeout(10000), headers: { 'User-Agent': 'WebScan/1.0' } }
      );
      if (r.ok) {
        const data = await r.json();
        if (Array.isArray(data) && data.length) {
          certs = data;
          source = 'crtsh';
        }
      }
    } catch (_) {}
  }

  // ── Fuente 3: Sin datos SSL — devolver info mínima de DNS ─────────
  if (!certs) {
    try {
      const r = await fetch(
        `https://dns.google/resolve?name=${encodeURIComponent(host)}&type=A`,
        { signal: AbortSignal.timeout(5000) }
      );
      const d = await r.json();
      const hasA = (d.Answer || []).length > 0;
      if (!hasA) return res.status(404).json({ error: `El dominio "${host}" no existe en DNS.` });

      const future = new Date();
      future.setFullYear(future.getFullYear() + 1);
      certs = [{
        id:          'dns-only',
        not_before:  new Date().toISOString(),
        not_after:   future.toISOString(),
        name_value:  host,
        issuer_name: 'CN=Desconocido',
        _dnsOnly:    true,
      }];
      source = 'dns';
    } catch (e) {
      return res.status(502).json({ error: 'No se pudo contactar con ninguna fuente SSL.' });
    }
  }

  return res.status(200).json({ certs, source, host });
}
