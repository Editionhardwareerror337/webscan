export const config = { runtime: 'edge' };

export default async function handler(req) {
  const { searchParams } = new URL(req.url);
  const host = (searchParams.get('host') || '')
    .replace(/^https?:\/\//, '').replace(/[/?#].*/, '').toLowerCase().trim();

  const cors = {
    'Access-Control-Allow-Origin': '*',
    'Content-Type': 'application/json',
  };

  if (!host) {
    return new Response(JSON.stringify({ error: 'Falta host' }), { status: 400, headers: cors });
  }

  let certs = null;
  let source = '';

  // Fuente 1: Certspotter
  try {
    const r = await fetch(
      `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(host)}&include_subdomains=false&expand=dns_names&expand=cert`,
      { headers: { 'User-Agent': 'WebScan/1.0' } }
    );
    if (r.ok) {
      const data = await r.json();
      if (Array.isArray(data) && data.length) {
        certs = data.map(d => ({
          id:           d.id,
          not_before:   d.not_before,
          not_after:    d.not_after,
          name_value:   (d.dns_names || []).join('\n'),
          issuer_name:  d.cert?.issuer?.organization?.[0] || d.cert?.issuer?.common_name || '',
          signature_alg: d.cert?.key?.type || '',
        }));
        source = 'certspotter';
      }
    }
  } catch (_) {}

  // Fuente 2: crt.sh
  if (!certs) {
    try {
      const r = await fetch(`https://crt.sh/?q=${encodeURIComponent(host)}&output=json`, {
        headers: { 'User-Agent': 'WebScan/1.0', 'Accept': 'application/json' }
      });
      if (r.ok) {
        const data = await r.json();
        if (Array.isArray(data) && data.length) { certs = data; source = 'crtsh'; }
      }
    } catch (_) {}
  }

  // Fuente 3: DNS fallback
  if (!certs) {
    try {
      const r = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(host)}&type=A`);
      const d = await r.json();
      if (!(d.Answer?.length)) {
        return new Response(JSON.stringify({ error: `Dominio "${host}" no encontrado en DNS` }), { status: 404, headers: cors });
      }
      const future = new Date();
      future.setFullYear(future.getFullYear() + 1);
      certs = [{ id: 'dns-only', not_before: new Date().toISOString(), not_after: future.toISOString(), name_value: host, issuer_name: 'Desconocido', _dnsOnly: true }];
      source = 'dns';
    } catch (e) {
      return new Response(JSON.stringify({ error: 'No se pudo verificar: ' + e.message }), { status: 502, headers: cors });
    }
  }

  return new Response(JSON.stringify({ certs, source, host }), { status: 200, headers: cors });
}
