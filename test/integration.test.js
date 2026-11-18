import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import mongoose from 'mongoose';

process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'integration-test-only-secret-do-not-reuse';
process.env.JWT_EXPIRES_IN = '15m';
process.env.ADMIN_NAME = 'Integration Test Admin';
process.env.ADMIN_EMAIL = 'admin@library-integration.test';
process.env.ADMIN_PASSWORD = 'IntegrationOnlyAdmin123!';
process.env.SMTP_HOST = '';
process.env.SMTP_USER = '';
process.env.SMTP_PASSWORD = '';

const configuredUri = process.env.TEST_MONGODB_URI || 'mongodb://127.0.0.1:27017/library_management_test';
const testDatabaseUrl = new URL(configuredUri);
const databaseName = testDatabaseUrl.pathname.replace(/^\//, '').split('?')[0];
if (!['localhost', '127.0.0.1', '[::1]'].includes(testDatabaseUrl.hostname) || !databaseName.toLowerCase().endsWith('_test')) {
  throw new Error('Refusing integration tests: TEST_MONGODB_URI must point to localhost and use a database name ending in _test.');
}

const [{ default: app, initializeAdminAccount }, { User, Book, Category, Author, BookIssue }] = await Promise.all([
  import('../src/server.js'),
  import('../src/models.js'),
]);

test('Mongoose schemas declare required auth fields and linked records', () => {
  assert.equal(User.schema.path('password').options.select, false);
  assert.deepEqual(User.schema.path('role').enumValues, ['admin', 'student']);
  assert.equal(Book.schema.path('author').options.ref, 'Author');
  assert.equal(Book.schema.path('category').options.ref, 'Category');
  assert.equal(Book.schema.path('publishedDate').instance, 'String');
  assert.equal(BookIssue.schema.path('book').options.ref, 'Book');
  assert.equal(BookIssue.schema.path('student').options.ref, 'User');
  assert.ok(BookIssue.schema.indexes().some(([keys, options]) => keys.book === 1 && keys.student === 1 && options.unique && options.partialFilterExpression?.status === 'issued'));
});

let server;
let baseUrl;
let databaseError;
let adminToken;
let admin;
let student;
let secondStudent;
let category;
let author;
let book;
let activeIssueId;
let issuedStudent;

before(async () => {
  try {
    await mongoose.connect(configuredUri, { serverSelectionTimeoutMS: 2000 });
    await mongoose.connection.dropDatabase();
    await Promise.all([User.init(), Book.init(), Category.init(), Author.init(), BookIssue.init()]);
    server = app.listen(0, '127.0.0.1');
    await new Promise((resolve, reject) => { server.once('listening', resolve); server.once('error', reject); });
    baseUrl = `http://127.0.0.1:${server.address().port}/api`;
  } catch (error) {
    databaseError = error;
  }
});

after(async () => {
  if (server) await new Promise((resolve) => server.close(resolve));
  if (mongoose.connection.readyState === 1) {
    await mongoose.connection.dropDatabase();
    await mongoose.disconnect();
  }
});

const call = async (path, { method = 'GET', token, body, headers = {} } = {}) => {
  const response = await fetch(`${baseUrl}${path}`, {
    method,
    headers: { ...(body ? { 'Content-Type': 'application/json' } : {}), ...(token ? { Authorization: `Bearer ${token}` } : {}), ...headers },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  const data = await response.json();
  return { response, data };
};

const login = async (identity, password) => call('/auth/login', { method: 'POST', body: { email: identity, password } });

test('isolated MongoDB API integration workflows', async (t) => {
  if (databaseError) {
    t.skip('Local MongoDB test service unavailable. Start MongoDB and use TEST_MONGODB_URI ending in _test.');
    return;
  }

  await t.test('health, schema references, and frontend CORS origin', async () => {
    const { response, data } = await call('/health', { headers: { Origin: 'http://localhost:3000' } });
    assert.equal(response.status, 200);
    assert.equal(data.database, 'connected');
    assert.equal(response.headers.get('access-control-allow-origin'), 'http://localhost:3000');
    assert.equal(response.headers.get('access-control-allow-credentials'), 'true');
    assert.equal(Book.schema.path('author').options.ref, 'Author');
    assert.equal(Book.schema.path('category').options.ref, 'Category');
    assert.equal(BookIssue.schema.path('book').options.ref, 'Book');
    assert.equal(BookIssue.schema.path('student').options.ref, 'User');
  });

  await t.test('admin initialization is repeatable and never elevates an existing student', async () => {
    admin = await initializeAdminAccount();
    assert.equal(admin.role, 'admin');
    const existing = await initializeAdminAccount();
    assert.equal(String(existing._id), String(admin._id));
    assert.equal(await User.countDocuments({ role: 'admin' }), 1);
    const stored = await User.findById(admin._id).select('+password');
    assert.equal(await stored.comparePassword(process.env.ADMIN_PASSWORD), true);
    assert.notEqual(stored.password, process.env.ADMIN_PASSWORD);
  });

  await t.test('student registration generates unique IDs and blocks role injection', async () => {
    assert.equal((await call('/auth/register', { method: 'POST', body: { name: {}, email: 'not-an-email', password: 'StudentOne123!' } })).response.status, 400);
    assert.equal((await call('/auth/register', { method: 'POST', body: { name: 'Long Password', email: 'long@library-integration.test', password: 'a'.repeat(73) } })).response.status, 400);
    const first = await call('/auth/register', { method: 'POST', body: { name: 'Test Student One', email: 'student1@library-integration.test', password: 'StudentOne123!', department: 'Science', role: 'admin' } });
    assert.equal(first.response.status, 201);
    const registrationCookie = first.response.headers.get('set-cookie')?.split(';', 1)[0];
    assert.match(first.response.headers.get('set-cookie') || '', /httponly/i);
    assert.ok(registrationCookie?.startsWith('library_session='));
    assert.equal(first.data.user.role, 'student');
    assert.match(first.data.user.userId, /^LIB-\d{4}-[A-F0-9]{6}$/);
    student = first.data.user;
    const restoredRegistrationSession = await call('/auth/me', { headers: { Cookie: registrationCookie } });
    assert.equal(restoredRegistrationSession.response.status, 200);
    assert.equal(restoredRegistrationSession.data.user._id, student._id);
    const second = await call('/auth/register', { method: 'POST', body: { name: 'Test Student Two', email: 'student2@library-integration.test', password: 'StudentTwo123!', role: 'admin' } });
    assert.equal(second.response.status, 201);
    assert.notEqual(second.data.user.userId, student.userId);
    secondStudent = second.data.user;
    process.env.ADMIN_EMAIL = 'student1@library-integration.test';
    await initializeAdminAccount();
    assert.equal((await User.findById(student._id)).role, 'student');
    process.env.ADMIN_EMAIL = 'admin@library-integration.test';
  });

  await t.test('admin/student login, JWT validation, and role authorization', async () => {
    const adminLogin = await login(process.env.ADMIN_EMAIL, process.env.ADMIN_PASSWORD);
    assert.equal(adminLogin.response.status, 200);
    adminToken = adminLogin.data.token;
    assert.equal(adminLogin.data.user.role, 'admin');
    const studentLogin = await login(student.userId, 'StudentOne123!');
    assert.equal(studentLogin.response.status, 200);
    assert.equal(studentLogin.data.user._id, student._id);
    const loginCookie = studentLogin.response.headers.get('set-cookie')?.split(';', 1)[0];
    assert.match(studentLogin.response.headers.get('set-cookie') || '', /httponly/i);
    const refreshedSession = await call('/auth/me', { headers: { Cookie: loginCookie } });
    assert.equal(refreshedSession.response.status, 200);
    assert.equal(refreshedSession.data.user._id, student._id);
    const blockedLogout = await call('/auth/logout', { method: 'POST', headers: { Cookie: loginCookie, Origin: 'https://untrusted.example' } });
    assert.equal(blockedLogout.response.status, 403);
    const logout = await call('/auth/logout', { method: 'POST', headers: { Cookie: loginCookie, Origin: 'http://localhost:3000' } });
    assert.equal(logout.response.status, 200);
    assert.match(logout.response.headers.get('set-cookie') || '', /library_session=;/);
    assert.equal((await call('/auth/me')).response.status, 401);
    assert.equal((await call('/auth/me', { token: studentLogin.data.token })).response.status, 200);
    assert.equal((await call('/auth/me')).response.status, 401);
    assert.equal((await call('/auth/me', { token: 'invalid.jwt.token' })).response.status, 401);
    assert.equal((await call('/users', { token: studentLogin.data.token })).response.status, 403);
    assert.equal((await call('/categories', { method: 'POST', token: studentLogin.data.token, body: { name: 'Forbidden' } })).response.status, 403);
  });

  await t.test('Google Books search is admin-only and proxies normalized results from the backend', async () => {
    assert.equal((await call('/books/google-search?query=Test')).response.status, 401);
    assert.equal((await call('/books/google-search?query=Test', { token: (await login(student.userId, 'StudentOne123!')).data.token })).response.status, 403);
    const originalFetch = globalThis.fetch;
    const originalKey = process.env.GOOGLE_BOOKS_API_KEY;
    process.env.GOOGLE_BOOKS_API_KEY = 'integration-google-books-key';
    let requestedUrl;
    globalThis.fetch = async (input, options) => {
      const url = new URL(input);
      if (url.hostname !== 'www.googleapis.com') return originalFetch(input, options);
      requestedUrl = url;
      return new Response(JSON.stringify({ items: [{ id: 'google-id', volumeInfo: { title: 'Google Test Book', authors: ['Test Author'], description: 'A test description', industryIdentifiers: [{ type: 'ISBN_13', identifier: '9780000000001' }], publishedDate: '2025', imageLinks: { thumbnail: 'http://books.example/cover.jpg' } } }] }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    };
    try {
      const result = await call('/books/google-search?query=978-0-00-000000-1', { token: adminToken });
      assert.equal(result.response.status, 200);
      assert.equal(requestedUrl.searchParams.get('q'), 'isbn:9780000000001');
      assert.equal(requestedUrl.searchParams.get('key'), process.env.GOOGLE_BOOKS_API_KEY);
      assert.deepEqual(result.data.books[0], { id: 'google-id', title: 'Google Test Book', authors: ['Test Author'], description: 'A test description', isbn: '9780000000001', publishedDate: '2025', coverUrl: 'https://books.example/cover.jpg' });
      assert.equal(JSON.stringify(result.data).includes(process.env.GOOGLE_BOOKS_API_KEY), false);
    } finally {
      globalThis.fetch = originalFetch;
      if (originalKey === undefined) delete process.env.GOOGLE_BOOKS_API_KEY;
      else process.env.GOOGLE_BOOKS_API_KEY = originalKey;
    }
  });

  await t.test('category and author CRUD plus relationship protection', async () => {
    let result = await call('/categories', { method: 'POST', token: adminToken, body: { name: 'Integration Fiction', description: 'Test category' } });
    assert.equal(result.response.status, 201);
    category = result.data.category;
    result = await call(`/categories/${category._id}`, { method: 'PATCH', token: adminToken, body: { description: 'Updated category' } });
    assert.equal(result.response.status, 200);
    assert.equal(result.data.category.description, 'Updated category');
    result = await call('/authors', { method: 'POST', token: adminToken, body: { name: 'Integration Author', email: 'author@library-integration.test' } });
    assert.equal(result.response.status, 201);
    author = result.data.author;
    const authorList = await call('/authors');
    const categoryList = await call('/categories');
    assert.equal(authorList.response.status, 200);
    assert.equal(categoryList.response.status, 200);
    assert.ok(authorList.data.authors.some((item) => item._id === author._id));
    assert.ok(categoryList.data.categories.some((item) => item._id === category._id));
    result = await call(`/authors/${author._id}`, { method: 'PATCH', token: adminToken, body: { biography: 'Updated biography' } });
    assert.equal(result.response.status, 200);
    assert.equal(result.data.author.biography, 'Updated biography');
    assert.equal((await call('/categories')).response.status, 200);
    assert.equal((await call('/authors')).response.status, 200);
  });

  await t.test('book CRUD, search, populated references, and stock validation', async () => {
    let result = await call('/books', { method: 'POST', token: adminToken, body: { title: 'Invalid Reference Book', author: 'not-an-object-id', category: category._id } });
    assert.equal(result.response.status, 400);
    result = await call('/books', { method: 'POST', token: adminToken, body: { title: 'Missing Reference Book', author: new mongoose.Types.ObjectId().toString(), category: category._id } });
    assert.equal(result.response.status, 404);
    result = await call('/books', { method: 'POST', token: adminToken, body: { title: 'Integration Book', isbn: 'TEST-ISBN-1', author: author._id, category: category._id, totalCopies: 1, availableCopies: 1 } });
    assert.equal(result.response.status, 201);
    book = result.data.book;
    result = await call('/books', { method: 'POST', token: adminToken, body: { title: 'Duplicate ISBN', isbn: 'TEST-ISBN-1', author: author._id, category: category._id, totalCopies: 1, availableCopies: 1 } });
    assert.equal(result.response.status, 409);
    result = await call('/books', { method: 'POST', token: adminToken, body: { title: 'Imported Date Book', isbn: 'TEST-ISBN-DATE', publishedDate: '2024-02', author: author._id, category: category._id, totalCopies: 2, availableCopies: 1 } });
    assert.equal(result.response.status, 201);
    assert.equal((await Book.findById(result.data.book._id)).publishedDate, '2024-02');
    await Book.findByIdAndDelete(result.data.book._id);
    const storedBook = await Book.findById(book._id);
    assert.equal(String(storedBook.author), author._id);
    assert.equal(String(storedBook.category), category._id);
    assert.equal((await call(`/books/${book._id}`, { method: 'PATCH', token: adminToken, body: { author: 'invalid-author-id' } })).response.status, 400);
    assert.equal((await call(`/books/${book._id}`, { method: 'PATCH', token: adminToken, body: { category: new mongoose.Types.ObjectId().toString() } })).response.status, 404);
    result = await call('/books?search=Integration%20Book');
    assert.equal(result.response.status, 200);
    assert.equal(result.data.books.length, 1);
    assert.equal(result.data.books[0].author.name, 'Integration Author');
    assert.equal(result.data.books[0].category.name, 'Integration Fiction');
    assert.equal((await call('/books?search=%2E%2A')).data.books.length, 0);
    assert.equal((await call(`/books?search=${'a'.repeat(121)}`)).response.status, 400);
    result = await call(`/books/${book._id}`, { method: 'PATCH', token: adminToken, body: { title: 'Integration Book Revised' } });
    assert.equal(result.response.status, 200);
    assert.equal(result.data.book.title, 'Integration Book Revised');
    book = result.data.book;
  });

  await t.test('issue/return workflow protects stock under concurrent requests', async () => {
    const dueDate = new Date(Date.now() + 7 * 86400000).toISOString();
    const invalidDueDate = await call('/issues', { method: 'POST', token: adminToken, body: { bookId: book._id, userId: student.userId, dueDate: 'not-a-date' } });
    assert.equal(invalidDueDate.response.status, 400);
    assert.equal((await Book.findById(book._id)).availableCopies, 1);
    const requests = [student, secondStudent].map((s) => call('/issues', { method: 'POST', token: adminToken, body: { bookId: book._id, userId: s.userId, dueDate } }));
    const results = await Promise.all(requests);
    assert.deepEqual(results.map((r) => r.response.status).sort(), [201, 409]);
    const winner = results.find((r) => r.response.status === 201);
    activeIssueId = winner.data.issue._id;
    issuedStudent = winner.data.issue.student;
    assert.equal((await Book.findById(book._id)).availableCopies, 0);
    assert.equal(await BookIssue.countDocuments({ book: book._id, status: 'issued' }), 1);
    assert.equal((await call('/issues', { method: 'POST', token: (await login(student.email, 'StudentOne123!')).data.token, body: { bookId: book._id, userId: student.userId, dueDate } })).response.status, 403);
    assert.equal((await call('/issues', { method: 'POST', token: adminToken, body: { bookId: book._id, userId: issuedStudent.userId, dueDate } })).response.status, 409);

    const owner = issuedStudent.userId === student.userId ? student : secondStudent;
    const otherStudent = owner.userId === student.userId ? secondStudent : student;
    const studentToken = (await login(owner.userId, owner === student ? 'StudentOne123!' : 'StudentTwo123!')).data.token;
    const ownIssues = await call('/issues', { token: studentToken });
    assert.equal(ownIssues.response.status, 200);
    assert.equal(ownIssues.data.issues.length, 1);
    assert.equal(ownIssues.data.issues[0].student.userId, owner.userId);
    const otherToken = (await login(otherStudent.userId, otherStudent === student ? 'StudentOne123!' : 'StudentTwo123!')).data.token;
    assert.equal((await call('/issues', { token: otherToken })).data.issues.length, 0);
    const returned = await call(`/issues/${activeIssueId}/return`, { method: 'POST', token: adminToken, body: { note: 'Integration return' } });
    assert.equal(returned.response.status, 200);
    assert.ok(returned.data.issue.returnedAt);
    assert.ok(returned.data.issue.returnedBy);
    assert.equal((await Book.findById(book._id)).availableCopies, 1);
    assert.equal((await call(`/issues/${activeIssueId}/return`, { method: 'POST', token: adminToken })).response.status, 409);
  });

  await t.test('admin/student dashboards and student profile isolation', async () => {
    const adminDashboard = await call('/dashboard', { token: adminToken });
    assert.equal(adminDashboard.response.status, 200);
    assert.equal(adminDashboard.data.stats.students, 2);
    assert.equal(adminDashboard.data.stats.bookTitles, 1);
    assert.equal(adminDashboard.data.stats.availableBooks, 1);
    assert.equal(adminDashboard.data.recentIssues.length, 1);
    assert.equal(adminDashboard.data.recentStudents.length, 2);
    assert.equal(adminDashboard.data.stats.returned, 1);
    const studentToken = (await login(student.email, 'StudentOne123!')).data.token;
    const studentDashboard = await call('/dashboard', { token: studentToken });
    assert.equal(studentDashboard.response.status, 200);
    assert.equal(studentDashboard.data.stats.available, 1);
    assert.equal(studentDashboard.data.stats.issued, 0);
    assert.equal(studentDashboard.data.stats.overdue, 0);
    assert.equal(studentDashboard.data.stats.returned, issuedStudent.userId === student.userId ? 1 : 0);
    assert.equal(studentDashboard.data.recentIssues.length, 1);
    assert.ok(Array.isArray(studentDashboard.data.recommendedBooks));
    const profile = await call('/users/me', { method: 'PATCH', token: studentToken, body: { name: 'Student One Updated', department: 'Arts' } });
    assert.equal(profile.response.status, 200);
    assert.equal(profile.data.user.name, 'Student One Updated');
    assert.equal(profile.data.user.department, 'Arts');
    assert.equal((await call(`/users/${student.userId}`, { token: studentToken })).response.status, 403);
  });

  await t.test('student/admin password changes and single-use password recovery', async () => {
    const studentToken = (await login(student.email, 'StudentOne123!')).data.token;
    let result = await call('/users/me/password', { method: 'PATCH', token: studentToken, body: { currentPassword: 'StudentOne123!', newPassword: 'StudentChanged123!' } });
    assert.equal(result.response.status, 200);
    assert.equal((await login(student.email, 'StudentOne123!')).response.status, 401);
    assert.equal((await login(student.userId, 'StudentChanged123!')).response.status, 200);

    const rawToken = crypto.randomBytes(32).toString('hex');
    const record = await User.findById(student._id);
    record.resetTokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
    record.resetTokenExpires = new Date(Date.now() + 30 * 60 * 1000);
    await record.save();
    result = await call('/auth/reset-password', { method: 'POST', body: { token: rawToken, password: 'StudentReset123!' } });
    assert.equal(result.response.status, 200);
    assert.equal((await login(student.email, 'StudentReset123!')).response.status, 200);
    assert.equal((await call('/auth/reset-password', { method: 'POST', body: { token: rawToken, password: 'StudentReset456!' } })).response.status, 400);
    assert.equal((await call('/auth/reset-password', { method: 'POST', body: { token: 'expired-or-invalid', password: 'StudentReset789!' } })).response.status, 400);

    const adminTokenAgain = (await login(process.env.ADMIN_EMAIL, process.env.ADMIN_PASSWORD)).data.token;
    result = await call('/users/me/password', { method: 'PATCH', token: adminTokenAgain, body: { currentPassword: process.env.ADMIN_PASSWORD, newPassword: 'IntegrationAdminChanged123!' } });
    assert.equal(result.response.status, 200);
    assert.equal((await login(process.env.ADMIN_EMAIL, 'IntegrationAdminChanged123!')).response.status, 200);
    const knownEmail = await call('/auth/forgot-password', { method: 'POST', body: { email: student.email } });
    assert.equal(knownEmail.response.status, 503);
    const unknownEmail = await call('/auth/forgot-password', { method: 'POST', body: { email: 'missing@library-integration.test' } });
    assert.equal(unknownEmail.response.status, knownEmail.response.status);
  });

  await t.test('category, author, and book deletion after references are cleared', async () => {
    assert.equal((await call(`/categories/${category._id}`, { method: 'DELETE', token: adminToken })).response.status, 409);
    assert.equal((await call(`/authors/${author._id}`, { method: 'DELETE', token: adminToken })).response.status, 409);
    assert.equal((await call(`/books/${book._id}`, { method: 'DELETE', token: adminToken })).response.status, 200);
    assert.equal((await call(`/categories/${category._id}`, { method: 'DELETE', token: adminToken })).response.status, 200);
    assert.equal((await call(`/authors/${author._id}`, { method: 'DELETE', token: adminToken })).response.status, 200);
  });
});
