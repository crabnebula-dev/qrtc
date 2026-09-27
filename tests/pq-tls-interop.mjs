// Post-quantum TLS interop for TURN over TLS: the engine's rustls client with
// its X25519MLKEM768 group against an OpenSSL server (Node's TLS, needs
// OpenSSL 3.5 or later) that accepts only X25519MLKEM768.
// Usage: node tests/pq-tls-interop.mjs [cargo features, default pq-hybrid]
// Runs the ignored test post_quantum_against_openssl in src/native/turn_stream.rs.
import { execFileSync, spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import tls from 'node:tls';
import os from 'node:os';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const features = `turn-tls-rustcrypto,${process.argv[2] || 'pq-hybrid'}`;
const [maj, min] = process.versions.openssl.split('.').map(Number);
if (maj < 3 || (maj === 3 && min < 5)) { console.error(`OpenSSL ${process.versions.openssl}: need 3.5+`); process.exit(2); }

const dir = mkdtempSync(path.join(os.tmpdir(), 'pq-tls-'));
const ossl = (...a) => execFileSync('openssl', a, { cwd: dir, stdio: 'ignore' });
ossl('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-days', '2', '-subj', '/CN=pq-tls CA', '-keyout', 'ca.key', '-out', 'ca.pem');
ossl('req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-subj', '/CN=localhost', '-keyout', 'srv.key', '-out', 'srv.csr');
writeFileSync(path.join(dir, 'ext.cnf'), 'subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n');
ossl('x509', '-req', '-in', 'srv.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-days', '2', '-extfile', 'ext.cnf', '-out', 'srv.pem');

const seen = [];
const server = tls.createServer({
  key: readFileSync(path.join(dir, 'srv.key')), cert: readFileSync(path.join(dir, 'srv.pem')),
  minVersion: 'TLSv1.3', ecdhCurve: 'X25519MLKEM768',
}, (s) => { seen.push(s.getEphemeralKeyInfo?.() || {}); s.end(); });
server.on('tlsClientError', () => {});
await new Promise((r) => server.listen(0, '127.0.0.1', r));

// Asynchronous: the TLS server runs on this process's event loop.
const r = await new Promise((resolve) => {
  const c = spawn('cargo', ['test', '-q', '--no-default-features', '--features', features, '--lib',
    'post_quantum_against_openssl', '--', '--ignored', '--nocapture'], {
    cwd: root,
    env: { ...process.env, PQ_TLS_PORT: String(server.address().port), SSL_CERT_FILE: path.join(dir, 'ca.pem') },
  });
  let stdout = '', stderr = '';
  c.stdout.on('data', (d) => { stdout += d; });
  c.stderr.on('data', (d) => { stderr += d; });
  c.on('exit', (status) => resolve({ status, stdout, stderr }));
});
server.close();
process.stdout.write(r.stderr.split('\n').filter((l) => /Require|Prefer|Off|panicked|test result/.test(l)).join('\n') + '\n');
process.stdout.write(r.stdout.split('\n').filter((l) => /test result|FAILED/.test(l)).join('\n') + '\n');
console.log(JSON.stringify({ openssl: process.versions.openssl, features, ok: r.status === 0 }));
process.exit(r.status === 0 ? 0 : 1);
