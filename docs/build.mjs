// Builds the documentation site into a directory (default _site): each page
// in docs/pages is an HTML fragment wrapped in the shared layout. No
// dependencies. The Pages workflow adds the rustdoc API reference under api/.
//
//   node docs/build.mjs [out-dir]
import { copyFileSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const here = path.dirname(fileURLToPath(import.meta.url));
const out = path.resolve(process.argv[2] || path.join(here, '..', '_site'));
mkdirSync(out, { recursive: true });

// Each fragment starts with <!-- title: ... --> and <!-- order: n -->.
const pages = readdirSync(path.join(here, 'pages'))
  .filter((f) => f.endsWith('.html'))
  .map((file) => {
    const body = readFileSync(path.join(here, 'pages', file), 'utf8');
    const meta = (key) => body.match(new RegExp(`<!--\\s*${key}:\\s*(.*?)\\s*-->`))?.[1];
    return { file, body, title: meta('title') || file, nav: meta('nav') || meta('title'), order: Number(meta('order') || 99) };
  })
  .sort((a, b) => a.order - b.order);

const nav = (current) => pages
  .map((p) => `<a href="${p.file}"${p.file === current ? ' aria-current="page"' : ''}>${p.nav}</a>`)
  .concat('<a href="api/qrtc/index.html">API reference</a>')
  .join('\n        ');

for (const page of pages) {
  const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${page.title} · qrtc</title>
  <link rel="stylesheet" href="site.css">
</head>
<body>
  <header>
    <div class="bar">
      <a class="brand" href="index.html">qrtc</a>
      <span class="tag">quantum realtime communication</span>
      <a class="repo" href="https://github.com/crabnebula-dev/qrtc">GitHub</a>
    </div>
  </header>
  <div class="layout">
    <nav aria-label="Documentation">
        ${nav(page.file)}
    </nav>
    <main>
${page.body}
    </main>
  </div>
  <footer>
    qrtc is MIT OR Apache-2.0, stewarded by CrabNebula as free and open-source software.
  </footer>
</body>
</html>
`;
  writeFileSync(path.join(out, page.file), html);
}
copyFileSync(path.join(here, 'site.css'), path.join(out, 'site.css'));
console.log(`built ${pages.length} pages into ${out}`);
