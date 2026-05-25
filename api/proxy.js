// api/proxy.js — Proxy genérico serverless para cabeceras HTTP (auditoría de vulns)
// Recibe ?url=... y devuelve las response headers del destino sin restricciones CORS

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const target = req.query.url;
  if (!target) return res.status(400).json({ error: 'Falta el parámetro url' });

  // Seguridad básica: solo URLs HTTP/HTTPS
  if (!/^https?:\/\//i.test(target)) {
    return res.status(400).json({ error: 'URL no válida' });
  }

  try {
    const r = await fetch(target, {
      method:  'GET',
      redirect: 'follow',
      signal:  AbortSignal.timeout(12000),
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; WebScan/1.0)',
        'Accept':     'text/html,application/xhtml+xml,*/*',
      }
    });

    // Recopilar todas las cabeceras de respuesta
    const headers = {};
    r.headers.forEach((value, key) => { headers[key.toLowerCase()] = value; });

    // Detectar redirecciones
    const finalUrl = r.url || target;

    return res.status(200).json({
      ok:        true,
      status:    r.status,
      finalUrl,
      headers,
    });

  } catch (e) {
    return res.status(502).json({
      ok:    false,
      error: e.message || 'Error al contactar con el destino',
    });
  }
}
