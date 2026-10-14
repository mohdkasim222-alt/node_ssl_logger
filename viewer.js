const express = require('express');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '127.0.0.1'; // binds to localhost by default
const outputsDir = path.join(__dirname, 'outputs');
const metaPath = path.join(outputsDir, 'metadata.json');

// Optional Basic auth: set VIEWER_USER and VIEWER_PASS env vars to enable
const USER = process.env.VIEWER_USER;
const PASS = process.env.VIEWER_PASS;

app.use((req, res, next) => {
  if (!USER || !PASS) return next();
  const auth = req.headers.authorization;
  if (!auth) {
    res.setHeader('WWW-Authenticate', 'Basic realm="Outputs Viewer"');
    return res.status(401).send('Authentication required');
  }
  const parts = auth.split(' ');
  if (parts[0] !== 'Basic') return res.status(400).send('Bad authorization');
  const creds = Buffer.from(parts[1], 'base64').toString();
  const [u, p] = creds.split(':');
  if (u !== USER || p !== PASS) {
    res.setHeader('WWW-Authenticate', 'Basic realm="Outputs Viewer"');
    return res.status(401).send('Authentication failed');
  }
  next();
});

// static serve outputs (files saved by node_ssl_logger.js)
app.use('/outputs', express.static(outputsDir, { maxAge: '1h' }));

// static UI
app.use(express.static(path.join(__dirname, 'viewer_public')));

// metadata endpoint
app.get('/metadata', (req, res) => {
  fs.readFile(metaPath, 'utf8', (err, data) => {
    if (err) return res.json([]);
    try { return res.json(JSON.parse(data)); }
    catch (e) { return res.json([]); }
  });
});

app.listen(PORT, HOST, () => {
  console.log(`Outputs viewer available at http://${HOST}:${PORT}`);
  if (!fs.existsSync(outputsDir)) console.warn('Warning: outputs/ does not exist yet. Run the logger to create files.');
});
