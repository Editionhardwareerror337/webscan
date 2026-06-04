export const config = { runtime: 'edge' };

export default async function handler(req) {
  const { searchParams } = new URL(req.url);
  const target = searchParams.get('url') || '';

  const cors = {
    'Access-Control-Allow-Origin': '*',
    'Content-Type': 'application/json',
  };

  if (!target || !/^https?:\/\//i.test(target)) {
    return new Response(JSON.stringify({ ok: false, error: 'URL no válida' }), { status: 400, headers: cors });
  }

  try {
    const r = await fetch(target, {
      redirect: 'follow',
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; WebScan/1.0)' }
    });

    const headers = {};
    r.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });

    return new Response(JSON.stringify({ ok: true, status: r.status, finalUrl: r.url, headers }), { status: 200, headers: cors });
  } catch (e) {
    return new Response(JSON.stringify({ ok: false, error: e.message }), { status: 502, headers: cors });
  }
}
