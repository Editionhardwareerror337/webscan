export const config = { runtime: 'edge' };

export default async function handler(req) {
  const cors = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, x-apikey',
    'Content-Type': 'application/json',
  };

  if (req.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: cors });
  }

  const { searchParams } = new URL(req.url);
  const action = searchParams.get('action'); // 'scan' o 'analysis'
  const apiKey = req.headers.get('x-apikey') || searchParams.get('apikey') || '';

  if (!apiKey) {
    return new Response(JSON.stringify({ error: 'API key requerida' }), { status: 400, headers: cors });
  }

  try {
    let vtRes;

    if (action === 'scan') {
      // POST a VirusTotal para escanear una URL
      const body = await req.text();
      vtRes = await fetch('https://www.virustotal.com/api/v3/urls', {
        method: 'POST',
        headers: { 'x-apikey': apiKey, 'Content-Type': 'application/x-www-form-urlencoded' },
        body,
      });
    } else if (action === 'analysis') {
      // GET resultado del análisis
      const id = searchParams.get('id');
      if (!id) return new Response(JSON.stringify({ error: 'id requerido' }), { status: 400, headers: cors });
      vtRes = await fetch(`https://www.virustotal.com/api/v3/analyses/${encodeURIComponent(id)}`, {
        headers: { 'x-apikey': apiKey },
      });
    } else if (action === 'url_report') {
      // GET informe completo de una URL
      const id = searchParams.get('id');
      if (!id) return new Response(JSON.stringify({ error: 'id requerido' }), { status: 400, headers: cors });
      vtRes = await fetch(`https://www.virustotal.com/api/v3/urls/${encodeURIComponent(id)}`, {
        headers: { 'x-apikey': apiKey },
      });
    } else {
      return new Response(JSON.stringify({ error: 'action no válida' }), { status: 400, headers: cors });
    }

    const data = await vtRes.json();
    return new Response(JSON.stringify(data), {
      status: vtRes.status,
      headers: cors,
    });

  } catch (e) {
    return new Response(JSON.stringify({ error: e.message }), { status: 502, headers: cors });
  }
}
