// Checks that sbom/qrtc.cdx.json matches the dependency tree: regenerates the
// CycloneDX 1.5 SBOM with cargo-cyclonedx and compares everything except the
// serial number and timestamp.
//
//   node tests/sbom-check.mjs           compare, exit 1 on drift
//   node tests/sbom-check.mjs --update  write the regenerated SBOM
//
// Run on x86_64 Linux: the SBOM describes the default build for the host
// target, and target-specific dependencies differ between platforms.
//
// cargo-cyclonedx names path dependencies (qrtc itself and vendor/) by the
// absolute path of the checkout. Those bom-refs are rewritten to start at
// /qrtc, so the SBOM does not depend on, or reveal, where it was generated.
import { execFileSync } from 'node:child_process';
import { readFileSync, rmSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const committed = path.join(root, 'sbom/qrtc.cdx.json');
const generated = path.join(root, 'qrtc.cdx.json');

execFileSync('cargo', ['cyclonedx', '--format', 'json', '--spec-version', '1.5'], { cwd: root, stdio: 'inherit' });
const checkout = `path+file://${root}`;
// Cargo writes #qrtc@0.1.0 instead of #0.1.0 when the checkout directory is
// not named qrtc.
writeFileSync(generated, readFileSync(generated, 'utf8').split(`${checkout}#qrtc@`).join(`${checkout}#`).split(checkout).join('path+file:///qrtc'));

if (process.argv.includes('--update')) {
  writeFileSync(committed, readFileSync(generated, 'utf8'));
  rmSync(generated);
  console.log('sbom/qrtc.cdx.json updated');
  process.exit(0);
}

const load = (file) => {
  const bom = JSON.parse(readFileSync(file, 'utf8'));
  delete bom.serialNumber;
  delete bom.metadata.timestamp;
  return bom;
};
const want = load(committed);
const got = load(generated);
rmSync(generated);

if (JSON.stringify(want) === JSON.stringify(got)) {
  console.log(`SBOM up to date (${got.components.length} components)`);
  process.exit(0);
}

const key = (c) => `${c.purl} ${JSON.stringify(c.licenses ?? [])}`;
const before = new Set(want.components.map(key));
const after = new Set(got.components.map(key));
const added = [...after].filter((k) => !before.has(k));
const removed = [...before].filter((k) => !after.has(k));
console.error('sbom/qrtc.cdx.json is out of date. Run: node tests/sbom-check.mjs --update');
for (const k of added) console.error(`  + ${k}`);
for (const k of removed) console.error(`  - ${k}`);
if (!added.length && !removed.length) console.error('  (components equal; metadata or dependency graph differs)');
process.exit(1);
