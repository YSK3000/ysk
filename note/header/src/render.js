// Serve the scratchpad over localhost and screenshot each header design at 1280x670.
const http = require("http");
const fs = require("fs");
const path = require("path");
const { chromium } = require("playwright");

const root = path.resolve(__dirname, "..");
const outDir = process.argv[2];
const types = { ".html": "text/html; charset=utf-8", ".css": "text/css", ".woff2": "font/woff2", ".woff": "font/woff", ".js": "text/javascript" };

const server = http.createServer((req, res) => {
  const p = path.join(root, decodeURIComponent(req.url.split("?")[0]));
  if (!p.startsWith(root) || !fs.existsSync(p) || fs.statSync(p).isDirectory()) { res.writeHead(404); return res.end(); }
  res.writeHead(200, { "Content-Type": types[path.extname(p)] || "application/octet-stream" });
  fs.createReadStream(p).pipe(res);
});

server.listen(0, "127.0.0.1", async () => {
  const port = server.address().port;
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1280, height: 670 }, deviceScaleFactor: 1 });
  const jobs = [["a.html", "header-a-timeline.png"], ["b.html", "header-b-number.png"], ["c.html", "header-c-calendar.png"]];
  for (const [file, out] of jobs) {
    await page.goto(`http://127.0.0.1:${port}/headers/${file}`, { waitUntil: "networkidle" });
    await page.evaluate(() => document.fonts.ready);
    const ok = await page.evaluate(() => ({
      zen900: document.fonts.check('900 40px "Zen Kaku Gothic New"'),
      zen700: document.fonts.check('700 40px "Zen Kaku Gothic New"'),
      mincho: document.fonts.check('800 40px "Shippori Mincho"'),
      overflowX: document.documentElement.scrollWidth > 1280,
      overflowY: document.documentElement.scrollHeight > 670
    }));
    await page.screenshot({ path: path.join(outDir, out) });
    console.log(file, "->", out, JSON.stringify(ok));
  }
  await browser.close();
  server.close();
});
