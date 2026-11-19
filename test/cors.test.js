import test from 'node:test';
import assert from 'node:assert/strict';

process.env.NODE_ENV = 'test';
process.env.CLIENT_URL = 'http://localhost:3000,https://library-management-system-clientsid-orcin.vercel.app';

const { default: app } = await import('../src/server.js');

test('credentialed CORS covers both origins on API 401 responses and OPTIONS preflight', async () => {
  const corsServer = app.listen(0, '127.0.0.1');
  await new Promise((resolve, reject) => { corsServer.once('listening', resolve); corsServer.once('error', reject); });
  const baseUrl = `http://127.0.0.1:${corsServer.address().port}`;
  try {
    for (const origin of ['http://localhost:3000', 'https://library-management-system-clientsid-orcin.vercel.app']) {
      const unauthorized = await fetch(`${baseUrl}/api/auth/me`, { headers: { Origin: origin } });
      assert.equal(unauthorized.status, 401);
      assert.equal(unauthorized.headers.get('access-control-allow-origin'), origin);
      assert.equal(unauthorized.headers.get('access-control-allow-credentials'), 'true');

      const preflight = await fetch(`${baseUrl}/api/auth/me`, {
        method: 'OPTIONS',
        headers: {
          Origin: origin,
          'Access-Control-Request-Method': 'GET',
          'Access-Control-Request-Headers': 'authorization,content-type',
        },
      });
      assert.equal(preflight.status, 204);
      assert.equal(preflight.headers.get('access-control-allow-origin'), origin);
      assert.equal(preflight.headers.get('access-control-allow-credentials'), 'true');
      assert.match(preflight.headers.get('access-control-allow-methods') || '', /GET/);
      assert.match(preflight.headers.get('access-control-allow-headers') || '', /authorization/i);
    }
    const denied = await fetch(`${baseUrl}/api/auth/me`, { headers: { Origin: 'https://untrusted.example' } });
    assert.equal(denied.headers.get('access-control-allow-origin'), null);
  } finally {
    await new Promise(resolve => corsServer.close(resolve));
  }
});
