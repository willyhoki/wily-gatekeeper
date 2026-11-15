// tunnel-lt.js — run localtunnel THROUGH the egress HTTP proxy.
//
// This VM has no direct outbound internet; all egress goes through an
// authenticated HTTP proxy (HTTPS_PROXY env var). localtunnel's client opens
// direct TCP connections which the egress firewall blocks, so it hangs
// forever. This wrapper monkey-patches net.connect / net.createConnection so
// that any connection to a NON-local host is routed through the proxy with an
// HTTP CONNECT handshake (Proxy-Authorization taken from the proxy URL in the
// env var — never hardcoded). Local connections (127.0.0.1/localhost) bypass
// the proxy so the tunnel can still reach the local agent on :3000.
//
// Both net.connect AND net.createConnection are patched (they are aliases,
// but Node's http/tls stack may reference either property).
//
// IMPORTANT: Node's built-in http client (NODE_USE_ENV_PROXY=1) ALSO tries to
// use the proxy for axios, but it sets Host: localtunnel.me while the request
// authority is the proxy, and Node rejects that mismatch. So this script
// disables Node's automatic proxy (NODE_USE_ENV_PROXY=0) and removes the
// proxy env vars AFTER reading the proxy URL — the patched net.connect is
// then the only proxy path, and the Host header matches the real target.
//
// Run:  node tunnel-lt.js [subdomain]
// Prints the public https://<name>.loca.lt URL. Keep this process running;
// the URL is only valid while it runs.
const net = require('net');

const PROXY_URL = process.env.TUNNEL_PROXY_URL || process.env.https_proxy || process.env.HTTPS_PROXY || '';
if (!PROXY_URL) {
  console.error('[tunnel] no proxy URL set (TUNNEL_PROXY_URL or https_proxy) — cannot route through the egress proxy');
  process.exit(1);
}
// Disable Node's automatic proxy so axios does not fight the patched connect.
process.env.NODE_USE_ENV_PROXY = '0';
delete process.env.http_proxy;
delete process.env.https_proxy;
delete process.env.HTTP_PROXY;
delete process.env.HTTPS_PROXY;
delete process.env.all_proxy;
delete process.env.ALL_PROXY;

const proxy = new URL(PROXY_URL);
const proxyAuth = proxy.username
  ? 'Basic ' + Buffer.from(decodeURIComponent(proxy.username) + ':' + decodeURIComponent(proxy.password)).toString('base64')
  : null;

function isLocal(host) {
  const h = String(host || '').toLowerCase();
  if (h === 'localhost' || h === '127.0.0.1' || h === '::1' || h === '[::1]' || h.endsWith('.local')) return true;
  // The proxy host itself must bypass the patch: a connection TO the proxy
  // must go direct — otherwise we CONNECT to the proxy through the proxy.
  if (proxy.hostname && h === proxy.hostname.toLowerCase()) return true;
  return false;
}

const DEBUG = process.env.TUNNEL_DEBUG === '1';
const origConnect = net.connect.bind(net);

function patchedConnect(options, ...rest) {
  const opts = typeof options === 'object' && options !== null ? options : { port: options, host: rest[0] };
  const cb = typeof rest[rest.length - 1] === 'function' ? rest[rest.length - 1] : (typeof options === 'function' ? options : null);
  const host = opts.host || 'localhost';
  const port = opts.port || 80;
  if (DEBUG) console.error(`[tunnel-dbg] net.connect ${host}:${port} (local=${isLocal(host)})`);
  if (isLocal(host)) return origConnect(options, ...rest);

  // Route through the egress proxy with HTTP CONNECT.
  const sock = origConnect({ host: proxy.hostname, port: Number(proxy.port) || 3128 });
  let buf = Buffer.alloc(0);
  let done = false;
  const fail = (err) => {
    if (done) return;
    done = true;
    sock.destroy();
    const e = err instanceof Error ? err : new Error(String(err));
    sock.emit('error', e);
    if (cb) cb(e);
  };
  sock.once('error', fail);
  sock.once('connect', () => {
    if (DEBUG) console.error(`[tunnel-dbg] connected to proxy, sending CONNECT ${host}:${port}`);
    sock.write([
      `CONNECT ${host}:${port} HTTP/1.1`,
      `Host: ${host}:${port}`,
      ...(proxyAuth ? [`Proxy-Authorization: ${proxyAuth}`] : []),
      'Proxy-Connection: Keep-Alive',
      '', '',
    ].join('\r\n'));
  });
  sock.on('data', (chunk) => {
    if (done) return;
    buf = Buffer.concat([buf, chunk]);
    const idx = buf.indexOf('\r\n\r\n');
    if (idx === -1) return;
    const head = buf.slice(0, idx).toString('utf8');
    const restBuf = buf.slice(idx + 4);
    const status = parseInt((head.split('\r\n')[0].match(/(\d{3})/) || [])[1] || '0', 10);
    if (DEBUG) console.error(`[tunnel-dbg] proxy CONNECT ${host}:${port} -> HTTP ${status}`);
    sock.removeAllListeners('data');
    if (status !== 200) {
      fail(new Error(`proxy CONNECT ${host}:${port} -> HTTP ${status}`));
      return;
    }
    done = true;
    sock.removeListener('error', fail);
    // The socket is now a tunnel to the target; hand it back as the connection.
    if (restBuf.length) sock.unshift(restBuf);
    sock.emit('connect');
    if (cb) cb();
  });
  return sock;
}

net.connect = patchedConnect;
net.createConnection = patchedConnect;

// Route axios (used by localtunnel for the initial tunnel request) through
// the proxy with a proper CONNECT agent. Node's automatic proxy handling
// (NODE_USE_ENV_PROXY) causes a Host/authority mismatch, so we disable it
// and set the agent explicitly on the shared axios instance BEFORE requiring
// localtunnel (it uses the same axios module, so the default applies).
const axios = require('axios');
const { HttpsProxyAgent } = require('https-proxy-agent');
axios.defaults.httpsAgent = new HttpsProxyAgent(PROXY_URL);
axios.defaults.httpAgent = new HttpsProxyAgent(PROXY_URL);

const localtunnel = require('localtunnel');

console.error('[tunnel] starting localtunnel client (port 3000)...');
(async () => {
  const subdomain = process.argv[2] || undefined;
  const tunnel = await localtunnel({ port: 3000, subdomain });
  console.log('[tunnel] public URL:', tunnel.url);
  console.log('[tunnel] local: http://127.0.0.1:3000  (health: GET /health)');
  tunnel.on('request', (info) => console.log('[tunnel] request:', info.method, info.path));
  tunnel.on('error', (e) => console.error('[tunnel] error:', e.message));
  tunnel.on('close', () => { console.error('[tunnel] closed'); process.exit(1); });
})().catch((e) => { console.error('[tunnel] FATAL', e.message); process.exit(1); });
