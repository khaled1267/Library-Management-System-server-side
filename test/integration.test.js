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

const [{ default: app, initializeAdminAccount, bookAvailabilityStatus }, { User, Book, Category, Author, BookIssue }] = await Promise.all([
  import('../src/server.js'),
  import('../src/models.js'),
]);

test('Mongoose schemas declare required auth fields and linked records', () => {
  assert.equal(User.schema.path('password').options.select, false);
  assert.deepEqual(User.schema.path('role').enumValues, ['admin', 'student']);
  assert.equal(User.schema.path('semester').options.default, '');
  assert.equal(Book.schema.path('author').options.ref, 'Author');
  assert.equal(Book.schema.path('category').options.ref, 'Category');
  assert.equal(Book.schema.path('publishedDate').instance, 'String');
  assert.equal(BookIssue.schema.path('book').options.ref, 'Book');
  assert.equal(BookIssue.schema.path('student').options.ref, 'User');
  assert.deepEqual(BookIssue.schema.path('returnRequestStatus').enumValues, ['none', 'pending', 'approved', 'rejected']);
  assert.equal(BookIssue.schema.path('returnRequestReason').options.maxlength, 500);
  assert.ok(BookIssue.schema.indexes().some(([keys, options]) => keys.book === 1 && keys.student === 1 && options.unique && options.partialFilterExpression?.status === 'issued'));
});

test('book availability status distinguishes available, busy, and unavailable inventory', () => {
  assert.equal(bookAvailabilityStatus(4, 2), 'Available');
  assert.equal(bookAvailabilityStatus(4, 0), 'Busy');
  assert.equal(bookAvailabilityStatus(0, 0), 'Unavailable');
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
let availabilityBook;
let selfServiceBook;
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
    const first = await call('/auth/register', { method: 'POST', body: { name: 'Test Student One', email: 'student1@library-integration.test', password: 'StudentOne123!', department: 'Science', semester: '3rd Semester', studentNumber: 'SCI-014', role: 'admin' } });
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
    const second = await call('/auth/register', { method: 'POST', body: { name: 'Test Student Two', email: 'student2@library-integration.test', password: 'StudentTwo123!', department: 'Arts', semester: '5th Semester', studentNumber: 'ART-022', role: 'admin' } });
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
    result = await call('/books', { method: 'POST', token: adminToken, body: { title: 'Availability Test Book', isbn: 'TEST-AVAILABILITY-1', author: author._id, category: category._id, totalCopies: 2, availableCopies: 2 } });
    assert.equal(result.response.status, 201);
    availabilityBook = result.data.book;
    result = await call('/books', { method: 'POST', token: adminToken, body: { title: 'Student Borrow Test Book', isbn: 'TEST-STUDENT-BORROW-1', author: author._id, category: category._id, totalCopies: 2, availableCopies: 2 } });
    assert.equal(result.response.status, 201);
    selfServiceBook = result.data.book;
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
    assert.equal((await call('/books?search=Integration%20Author')).data.books.length, 2);
    assert.equal((await call('/books?search=TEST-ISBN-1')).data.books.length, 1);
    assert.equal((await call('/books?search=No%20Such%20Title')).data.books.length, 0);
    assert.equal((await call(`/books?category=${category._id}`)).data.books.length, 2);
    assert.equal((await call(`/books?author=${author._id}`)).data.books.length, 2);
    const firstBookPage = await call(`/books?category=${category._id}&page=1&limit=1`);
    const secondBookPage = await call(`/books?category=${category._id}&page=2&limit=1`);
    assert.equal(firstBookPage.data.books.length, 1);
    assert.deepEqual(firstBookPage.data.pagination, { page: 1, limit: 1, total: 2, totalPages: 2 });
    assert.equal(secondBookPage.data.books.length, 1);
    assert.notEqual(firstBookPage.data.books[0]._id, secondBookPage.data.books[0]._id);
    assert.equal((await call('/books?search=%2E%2A')).data.books.length, 0);
    assert.equal((await call(`/books?search=${'a'.repeat(121)}`)).response.status, 400);
    assert.equal((await call('/books?category=invalid')).response.status, 400);
    assert.equal((await call('/books?author=invalid')).response.status, 400);
    assert.equal((await call('/books?limit=101')).response.status, 400);
    assert.equal((await call('/books?available=maybe')).response.status, 400);
    assert.equal((await call(`/books/${book._id}/availability`)).data.book.availabilityStatus, 'Available');
    assert.equal((await call('/books/not-an-object-id/availability')).response.status, 400);
    const missingBook = await call(`/books/${new mongoose.Types.ObjectId()}/availability`);
    assert.equal(missingBook.response.status, 404);
    assert.equal(missingBook.data.status, 'Unavailable');
    assert.equal((await call(`/books/${availabilityBook._id}/borrowers`)).response.status, 401);
    assert.equal((await call(`/books/${availabilityBook._id}/borrowers`, { token: (await login(student.userId, 'StudentOne123!')).data.token })).response.status, 403);
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
    assert.equal((await call(`/issues/${activeIssueId}/return-request`, { method: 'POST', body: {} })).response.status, 401);
    assert.equal((await call('/issues/not-an-object-id/return-request', { method: 'POST', token: studentToken, body: {} })).response.status, 400);
    assert.equal((await call(`/issues/${activeIssueId}/return-request`, { method: 'POST', token: otherToken, body: {} })).response.status, 404);
    assert.equal((await call('/return-requests', { token: studentToken })).response.status, 403);
    assert.equal((await call(`/issues/${activeIssueId}/return-request/review`, { method: 'POST', token: studentToken, body: { action: 'approve' } })).response.status, 403);
    assert.equal((await call(`/issues/${activeIssueId}/return-request/review`, { method: 'POST', token: adminToken, body: { action: 'complete' } })).response.status, 400);
    const returnRequests = await Promise.all([1, 2].map(() => call(`/issues/${activeIssueId}/return-request`, { method: 'POST', token: studentToken, body: { studentId: otherStudent._id, userId: otherStudent.userId } })));
    assert.deepEqual(returnRequests.map((result) => result.response.status).sort(), [201, 409]);
    const pendingIssue = returnRequests.find((result) => result.response.status === 201).data.issue;
    assert.equal(pendingIssue.student.toString?.() || pendingIssue.student._id, owner._id);
    assert.equal(pendingIssue.returnRequestStatus, 'pending');
    assert.equal((await Book.findById(book._id)).availableCopies, 0);
    let pendingQueue = await call('/return-requests', { token: adminToken });
    assert.equal(pendingQueue.response.status, 200);
    assert.equal(pendingQueue.data.requests.length, 1);
    assert.equal(pendingQueue.data.requests[0].student.userId, owner.userId);
    assert.equal(pendingQueue.data.requests[0].student.department, owner.department);
    assert.equal(pendingQueue.data.requests[0].student.studentNumber, owner.studentNumber);
    assert.equal(JSON.stringify(pendingQueue.data).includes(owner.email), false);

    const rejected = await call(`/issues/${activeIssueId}/return-request/review`, { method: 'POST', token: adminToken, body: { action: 'reject', reason: 'Please bring the book to the library desk.' } });
    assert.equal(rejected.response.status, 200);
    assert.equal(rejected.data.issue.returnRequestStatus, 'rejected');
    assert.equal(rejected.data.issue.returnRequestReason, 'Please bring the book to the library desk.');
    assert.equal(rejected.data.issue.status, 'issued');
    assert.equal((await Book.findById(book._id)).availableCopies, 0);
    assert.equal((await call('/issues', { token: studentToken })).data.issues[0].returnRequestReason, 'Please bring the book to the library desk.');

    const resubmitted = await call(`/issues/${activeIssueId}/return-request`, { method: 'POST', token: studentToken, body: {} });
    assert.equal(resubmitted.response.status, 201);
    assert.equal(resubmitted.data.issue.returnRequestStatus, 'pending');
    pendingQueue = await call('/return-requests', { token: adminToken });
    assert.equal(pendingQueue.data.requests.length, 1);

    const returned = await call(`/issues/${activeIssueId}/return-request/review`, { method: 'POST', token: adminToken, body: { action: 'approve' } });
    assert.equal(returned.response.status, 200);
    assert.equal(returned.data.issue.status, 'returned');
    assert.equal(returned.data.issue.returnRequestStatus, 'approved');
    assert.ok(returned.data.issue.returnedAt);
    assert.equal(String(returned.data.issue.returnedBy._id), String(admin._id));
    assert.equal((await Book.findById(book._id)).availableCopies, 1);
    assert.equal((await call(`/issues/${activeIssueId}/return-request/review`, { method: 'POST', token: adminToken, body: { action: 'approve' } })).response.status, 409);
    assert.equal((await call(`/issues/${activeIssueId}/return-request`, { method: 'POST', token: studentToken, body: {} })).response.status, 409);
    assert.equal((await Book.findById(book._id)).availableCopies, 1);
    assert.equal((await call(`/issues/${activeIssueId}/return`, { method: 'POST', token: adminToken })).response.status, 409);

    const secondBookLoan = async (user) => call('/issues', { method: 'POST', token: adminToken, body: { bookId: availabilityBook._id, userId: user.userId, dueDate } });
    const firstLoan = await secondBookLoan(student);
    assert.equal(firstLoan.response.status, 201);
    let detail = await call(`/books/${availabilityBook._id}/availability`);
    assert.deepEqual({ status: detail.data.book.availabilityStatus, total: detail.data.book.totalCopies, available: detail.data.book.availableCopies, issued: detail.data.book.issuedCopies }, { status: 'Available', total: 2, available: 1, issued: 1 });
    let borrowers = await call(`/books/${availabilityBook._id}/borrowers`, { token: adminToken });
    assert.equal(borrowers.response.status, 200);
    assert.equal(borrowers.data.borrowers.length, 1);
    assert.deepEqual(borrowers.data.borrowers[0].student, { name: student.name, userId: student.userId, semester: '3rd Semester', rollNumber: 'SCI-014', department: 'Science' });
    assert.ok(borrowers.data.borrowers[0].issueDate);
    assert.ok(borrowers.data.borrowers[0].dueDate);
    assert.equal(JSON.stringify(borrowers.data).includes(student.email), false);

    const secondLoan = await secondBookLoan(secondStudent);
    assert.equal(secondLoan.response.status, 201);
    detail = await call(`/books/${availabilityBook._id}/availability`);
    assert.deepEqual({ status: detail.data.book.availabilityStatus, total: detail.data.book.totalCopies, available: detail.data.book.availableCopies, issued: detail.data.book.issuedCopies }, { status: 'Busy', total: 2, available: 0, issued: 2 });
    borrowers = await call(`/books/${availabilityBook._id}/borrowers`, { token: adminToken });
    assert.equal(borrowers.data.borrowers.length, 2);

    const returnedLoan = await call(`/issues/${firstLoan.data.issue._id}/return`, { method: 'POST', token: adminToken });
    assert.equal(returnedLoan.response.status, 200);
    detail = await call(`/books/${availabilityBook._id}/availability`);
    assert.deepEqual({ status: detail.data.book.availabilityStatus, available: detail.data.book.availableCopies, issued: detail.data.book.issuedCopies }, { status: 'Available', available: 1, issued: 1 });
    borrowers = await call(`/books/${availabilityBook._id}/borrowers`, { token: adminToken });
    assert.equal(borrowers.data.borrowers.length, 1);
    assert.equal(borrowers.data.borrowers[0].student.userId, secondStudent.userId);
    assert.equal((await call(`/books/${availabilityBook._id}/borrowers`, { token: adminToken })).data.borrowers.some(borrower => borrower.student.userId === student.userId), false);
    const returnedSecondLoan = await call(`/issues/${secondLoan.data.issue._id}/return`, { method: 'POST', token: adminToken });
    assert.equal(returnedSecondLoan.response.status, 200);
    assert.equal((await call(`/books/${availabilityBook._id}/availability`)).data.book.availableCopies, 2);
  });

  await t.test('student self-service uses JWT identity and protects copy counts', async () => {
    const studentToken = (await login(student.userId, 'StudentOne123!')).data.token;
    assert.equal((await call('/issues', { method: 'POST', body: { bookId: selfServiceBook._id, selfService: true } })).response.status, 401);
    assert.equal((await call('/issues', { method: 'POST', token: adminToken, body: { bookId: selfServiceBook._id, selfService: true } })).response.status, 403);

    const requests = [1, 2].map(() => call('/issues', { method: 'POST', token: studentToken, body: { bookId: selfServiceBook._id, selfService: true, userId: secondStudent.userId, dueDate: '2000-01-01' } }));
    const results = await Promise.all(requests);
    assert.deepEqual(results.map((result) => result.response.status).sort(), [201, 409]);
    const successfulBorrow = results.find((result) => result.response.status === 201);
    assert.equal(successfulBorrow.data.issue.student._id, student._id);
    assert.ok(successfulBorrow.data.issue.issueDate);
    const loanDays = (new Date(successfulBorrow.data.issue.dueDate).getTime() - new Date(successfulBorrow.data.issue.issueDate).getTime()) / 86400000;
    assert.ok(loanDays >= 13.99 && loanDays <= 14.01);
    assert.equal((await Book.findById(selfServiceBook._id)).availableCopies, 1);
    assert.equal(await BookIssue.countDocuments({ book: selfServiceBook._id, status: 'issued' }), 1);

    const secondStudentToken = (await login(secondStudent.userId, 'StudentTwo123!')).data.token;
    const lastCopy = await call('/issues', { method: 'POST', token: secondStudentToken, body: { bookId: selfServiceBook._id, selfService: true } });
    assert.equal(lastCopy.response.status, 201);
    assert.equal((await Book.findById(selfServiceBook._id)).availableCopies, 0);
    assert.equal((await call('/issues', { method: 'POST', token: studentToken, body: { bookId: selfServiceBook._id, selfService: true } })).response.status, 409);
    assert.equal(await BookIssue.countDocuments({ book: selfServiceBook._id, status: 'issued' }), 2);

    const ownIssues = await call('/issues?status=issued', { token: studentToken });
    const ownIssue = ownIssues.data.issues.find((issue) => issue.book._id === selfServiceBook._id);
    assert.ok(ownIssue);
    assert.equal(ownIssue.student._id, student._id);
    assert.ok(ownIssue.issueDate);
    assert.ok(ownIssue.dueDate);

    for (const issue of [successfulBorrow.data.issue, lastCopy.data.issue]) {
      assert.equal((await call(`/issues/${issue._id}/return`, { method: 'POST', token: adminToken })).response.status, 200);
    }
    assert.equal((await Book.findById(selfServiceBook._id)).availableCopies, 2);
  });

  await t.test('admin/student dashboards and student profile isolation', async () => {
    const adminDashboard = await call('/dashboard', { token: adminToken });
    assert.equal(adminDashboard.response.status, 200);
    assert.equal(adminDashboard.data.stats.students, 2);
    assert.equal(adminDashboard.data.stats.bookTitles, 3);
    assert.equal(adminDashboard.data.stats.availableBooks, 5);
    assert.equal(adminDashboard.data.recentIssues.length, 5);
    assert.equal(adminDashboard.data.recentStudents.length, 2);
    assert.equal(adminDashboard.data.stats.returned, 5);
    const studentToken = (await login(student.email, 'StudentOne123!')).data.token;
    const studentDashboard = await call('/dashboard', { token: studentToken });
    assert.equal(studentDashboard.response.status, 200);
    assert.equal(studentDashboard.data.issues.find((issue) => issue._id === activeIssueId).returnRequestStatus, 'approved');
    assert.equal(studentDashboard.data.stats.available, 3);
    assert.equal(studentDashboard.data.stats.issued, 0);
    assert.equal(studentDashboard.data.stats.overdue, 0);
    assert.equal(studentDashboard.data.stats.returned, (issuedStudent.userId === student.userId ? 1 : 0) + 2);
    assert.equal(studentDashboard.data.recentIssues.length, (issuedStudent.userId === student.userId ? 2 : 1) + 1);
    assert.ok(Array.isArray(studentDashboard.data.recommendedBooks));
    const profile = await call('/users/me', { method: 'PATCH', token: studentToken, body: { name: 'Student One Updated', department: 'Arts' } });
    assert.equal(profile.response.status, 200);
    assert.equal(profile.data.user.name, 'Student One Updated');
    assert.equal(profile.data.user.department, 'Arts');
    const studentWithSemester = await call('/users/me', { method: 'PATCH', token: studentToken, body: { semester: '4th Semester', studentNumber: 'SCI-015' } });
    assert.equal(studentWithSemester.data.user.semester, '4th Semester');
    assert.equal(studentWithSemester.data.user.studentNumber, 'SCI-015');
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
    assert.equal((await call(`/books/${availabilityBook._id}`, { method: 'DELETE', token: adminToken })).response.status, 200);
    assert.equal((await call(`/categories/${category._id}`, { method: 'DELETE', token: adminToken })).response.status, 200);
    assert.equal((await call(`/authors/${author._id}`, { method: 'DELETE', token: adminToken })).response.status, 200);
  });
});
