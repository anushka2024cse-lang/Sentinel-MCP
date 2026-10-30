import 'dotenv/config';
import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function startServer() {
  const app = express();
  const PORT = Number(process.env.PORT || '3000');
  if (!Number.isInteger(PORT) || PORT < 1 || PORT > 65535) {
    throw new Error('PORT must be an integer between 1 and 65535.');
  }
  const isDev = process.env.NODE_ENV !== 'production';
  const host = process.env.HOST || (isDev ? '127.0.0.1' : '0.0.0.0');
  const { apiRouter } = await import('./src/server/routes.js');

  app.disable('x-powered-by');
  app.use((_req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    next();
  });
  app.use(express.json({ limit: '1mb', strict: true }));
  app.use(express.urlencoded({ extended: false, limit: '32kb', parameterLimit: 50 }));

  // Mount Sentinel REST API
  app.use('/api', apiRouter);

  // Development vs Production
  if (isDev) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true, host, port: PORT },
      appType: 'spa'
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.resolve(distPath, 'index.html'));
    });
  }

  app.use((error: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    const status = typeof error === 'object' && error !== null && 'status' in error &&
      typeof error.status === 'number' ? error.status : 500;
    if (status >= 500) {
      console.error('[SENTINEL-MCP] Request failed:', error);
    }

    const message = status === 413
      ? 'Request body exceeds the allowed size.'
      : status >= 500
        ? 'Internal server error.'
        : 'Invalid request.';
    res.status(status).json({ error: message });
  });

  app.listen(PORT, host, () => {
    console.log(`[SENTINEL-MCP] Gateway server running at http://${host}:${PORT}`);
  });
}

startServer().catch(err => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
