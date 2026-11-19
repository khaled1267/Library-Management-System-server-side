import test from 'node:test';
import assert from 'node:assert/strict';

process.env.NODE_ENV = 'test';
process.env.CLIENT_URL = 'http://localhost:3000,https://library-management-system-clientsid-orcin.vercel.app';
process.env.JWT_SECRET = 'isolated-auth-cookie-test-secret-with-32-bytes';
delete process.env.SESSION_COOKIE_SAME_SITE;
delete process.env.VERCEL_ENV;

const [{ default: app }, { User }] = await Promise.all([
  import('../src/server.js'),
  import('../src/models.js'),
]);

test('login sets a usable session cookie in production and localhost modes', async () => {
  const originalFindOne = User.findOne;
  const originalFindById = User.findById;
  const originalNodeEnv = process.env.NODE_ENV;
  const originalSameSite = process.env.SESSION_COOKIE_SAME_SITE;
  const originalVercelEnv = process.env.VERCEL_ENV;
  const user = {
    _id: 'cookie-test-user-id',
    userId: 'LIB-2026-COOKIE1',
    name: 'Cookie Test User',
    email: 'cookie-user@example.test',
    role: 'student',
    phone: '',
    department: '',
    semester: '',
    studentNumber: '',
    createdAt: new Date('2026-01-01T00:00:00.000Z'),
    comparePassword: async password => password === 'CookieTestPassword123!',
  };
  User.findOne = () => ({ select: async () => user });
  User.findById = async id => id === user._id ? user : null;

  const server = app.listen(0, '127.0.0.1');
  await new Promise((resolve, reject) => { server.once('listening', resolve); server.once('error', reject); });
  const baseUrl = `http://127.0.0.1:${server.address().port}`;

  try {
    for (const scenario of [
      { nodeEnv: 'test', vercelEnv: 'production', origin: 'https://library-management-system-clientsid-orcin.vercel.app', sameSite: 'None', secure: true },
      { nodeEnv: 'development', vercelEnv: undefined, origin: 'http://localhost:3000', sameSite: 'Lax', secure: false },
    ]) {
      process.env.NODE_ENV = scenario.nodeEnv;
      if (scenario.vercelEnv === undefined) delete process.env.VERCEL_ENV;
      else process.env.VERCEL_ENV = scenario.vercelEnv;
      delete process.env.SESSION_COOKIE_SAME_SITE;

      const login = await fetch(`${baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { Origin: scenario.origin, 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: user.email, password: 'CookieTestPassword123!' }),
      });
      assert.equal(login.status, 200);
      assert.equal(login.headers.get('access-control-allow-origin'), scenario.origin);
      assert.equal(login.headers.get('access-control-allow-credentials'), 'true');
      const setCookie = login.headers.get('set-cookie') || '';
      assert.match(setCookie, /^library_session=/);
      assert.match(setCookie, /HttpOnly/i);
      assert.match(setCookie, /Path=\//i);
      assert.match(setCookie, new RegExp(`SameSite=${scenario.sameSite}`, 'i'));
      if (scenario.secure) assert.match(setCookie, /;\s*Secure/i);
      else assert.doesNotMatch(setCookie, /;\s*Secure/i);

      const cookiePair = setCookie.split(';', 1)[0];
      const currentUser = await fetch(`${baseUrl}/api/auth/me`, {
        headers: { Origin: scenario.origin, Cookie: cookiePair },
      });
      assert.equal(currentUser.status, 200);
      assert.equal(currentUser.headers.get('access-control-allow-origin'), scenario.origin);
      assert.equal(currentUser.headers.get('access-control-allow-credentials'), 'true');
      assert.equal((await currentUser.json()).user.email, user.email);
    }
  } finally {
    await new Promise(resolve => server.close(resolve));
    User.findOne = originalFindOne;
    User.findById = originalFindById;
    process.env.NODE_ENV = originalNodeEnv;
    if (originalSameSite === undefined) delete process.env.SESSION_COOKIE_SAME_SITE;
    else process.env.SESSION_COOKIE_SAME_SITE = originalSameSite;
    if (originalVercelEnv === undefined) delete process.env.VERCEL_ENV;
    else process.env.VERCEL_ENV = originalVercelEnv;
  }
});
