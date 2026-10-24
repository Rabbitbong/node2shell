// Vulnerable fixture for CVE-2026-111497 ("node2shell").
//
// A normal-looking Express 5 app that exposes Node's bundled Brotli decoder to
// client-controlled bytes, via the two documented attack surfaces:
//   inbound  - Express 5 / body-parser 2.x decode `Content-Encoding: br`
//              request bodies, running the Brotli decoder on the client's bytes.
//   outbound - GET /fetch-brotli fetches a Brotli-compressed URL via built-in
//              fetch(); the decoder runs on the remote response.
//
// Run on node:24.22.0 (vulnerable) and node:24.22.1 (fixed) for an A/B pair.

const express = require('express');

const app = express();

app.use(express.json({ limit: '64mb' }));
app.use(express.urlencoded({ extended: false, limit: '64mb' }));
app.use(express.text({ limit: '64mb' }));

app.get('/health', (_req, res) => res.end('PONG\n'));

app.post('/echo', (req, res) => {
  const body = req.body == null ? null : JSON.stringify(req.body);
  res.json({
    ok: true,
    node: process.version,
    contentType: req.headers['content-type'] || null,
    bodyLen: body ? body.length : 0,
  });
});

// Surface the underlying zlib error code so the vuln/fixed divergence is
// observable remotely (24.22.0 continues; 24.22.1 rejects with BLOCK_SWITCH).
app.use((err, req, res, next) => {
  res.status(400).json({ error: String(err.message || err), code: err.code || null });
});

app.get('/fetch-brotli', async (req, res) => {
  const target = String(req.query.url || '');
  if (!/^https?:\/\//.test(target)) {
    return res.status(400).json({ error: 'url query param (http/https) required' });
  }
  try {
    const upstream = await fetch(target, { headers: { 'accept-encoding': 'br' } });
    const text = await upstream.text(); // Node decodes br here
    res.json({
      ok: true,
      node: process.version,
      upstreamStatus: upstream.status,
      bytes: text.length,
      head: text.slice(0, 200),
    });
  } catch (err) {
    res.status(502).json({ ok: false, error: String(err) });
  }
});

const port = Number(process.env.PORT || 3000);
app.listen(port, () => {
  console.log(`[vuln-app] node ${process.version} listening on :${port}`);
});
