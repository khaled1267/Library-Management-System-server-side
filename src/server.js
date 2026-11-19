import dotenv from 'dotenv';
import { fileURLToPath } from 'node:url';
import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import rateLimit from 'express-rate-limit';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'node:crypto';
import nodemailer from 'nodemailer';
import { User, Book, Author, Category, BookIssue } from './models.js';

dotenv.config({ path: fileURLToPath(new URL('../.env', import.meta.url)) });

const app = express();
app.use(helmet());
const configuredClientOrigins = (process.env.CLIENT_URL?.split(',') || []).map(origin => origin.trim()).filter(Boolean);
const allowedClientOrigins = new Set(configuredClientOrigins.length ? configuredClientOrigins : ['http://localhost:3000']);
const invalidClientOrigin = [...allowedClientOrigins].some(origin => {
  try {
    const parsed = new URL(origin);
    return !['http:', 'https:'].includes(parsed.protocol) || parsed.origin !== origin || origin === '*'
      || (process.env.NODE_ENV === 'production' && parsed.protocol !== 'https:' && origin !== 'http://localhost:3000');
  } catch { return true; }
});
if (invalidClientOrigin || (process.env.NODE_ENV === 'production' && !configuredClientOrigins.length)) {
  throw new Error('Set CLIENT_URL to exact frontend origins; production origins must use HTTPS except http://localhost:3000.');
}
app.use(cors({ origin: [...allowedClientOrigins], credentials: true }));
app.use('/api/auth', (req, res, next) => {
  res.set('Cache-Control', 'no-store');
  if (req.method === 'GET' || req.method === 'HEAD') {
    delete req.headers['if-none-match'];
    delete req.headers['if-modified-since'];
  }
  next();
});
app.use(express.json({ limit: '1mb' }));
app.use(morgan('tiny'));
app.use((req, res, next) => {
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
    if (req.body === undefined) req.body = {};
    if (req.body === null || typeof req.body !== 'object' || Array.isArray(req.body)) return res.status(400).json({ message: 'Request body must be a JSON object.' });
  }
  next();
});
app.use('/api/auth', rateLimit({ windowMs: 15 * 60 * 1000, limit: 40 }));
const fail = (res, status, message) => res.status(status).json({ message });
const safeUser = (u) => ({ _id: u._id, userId: u.userId, name: u.name, email: u.email, role: u.role, phone: u.phone, department: u.department, semester: u.semester, studentNumber: u.studentNumber, createdAt: u.createdAt });
const tokenFor = (u) => jwt.sign({ sub: u._id.toString(), role: u.role }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN || '7d', algorithm: 'HS256' });
const sessionCookieName = 'library_session';
const sessionCookieOptions = () => {
  const isProduction = process.env.NODE_ENV === 'production' || process.env.VERCEL_ENV === 'production';
  const configuredSameSite = process.env.SESSION_COOKIE_SAME_SITE?.toLowerCase();
  const sameSite = isProduction
    ? 'none'
    : ['strict', 'lax', 'none'].includes(configuredSameSite) ? configuredSameSite : 'lax';
  return { httpOnly: true, secure: isProduction || sameSite === 'none', sameSite, path: '/' };
};
const cookieToken = (req) => {
  const entry = req.headers.cookie?.split(';').map(part => part.trim()).find(part => part.startsWith(`${sessionCookieName}=`));
  if (!entry) return undefined;
  try { return decodeURIComponent(entry.slice(sessionCookieName.length + 1)); } catch { return undefined; }
};
app.use((req, res, next) => {
  const mutating = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method);
  const origin = req.headers.origin;
  if (mutating && origin && !allowedClientOrigins.has(origin)) return fail(res, 403, 'Request origin is not allowed.');
  if (mutating && cookieToken(req) && !allowedClientOrigins.has(origin)) return fail(res, 403, 'Request origin is not allowed.');
  next();
});
const auth = async (req, res, next) => {
  try { const bearerToken = req.headers.authorization?.replace(/^Bearer\s+/i, ''); const token = bearerToken || cookieToken(req); if (!token) return fail(res, 401, 'Sign in to continue.'); const payload = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] }); req.user = await User.findById(payload.sub); if (!req.user) return fail(res, 401, 'Account not found.'); if (bearerToken) req.sessionToken = bearerToken; next(); }
  catch { return fail(res, 401, 'Your session is invalid or has expired.'); }
};
const admin = (req, res, next) => req.user?.role === 'admin' ? next() : fail(res, 403, 'Administrator access is required.');
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const asyncAuth = [auth];
const cleanString = (v) => typeof v === 'string' ? v.trim() : v;
const isEmail = (value) => typeof value === 'string' && value.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(value);
const isPassword = (value) => typeof value === 'string' && value.length >= 8 && Buffer.byteLength(value, 'utf8') <= 72;
const escapeRegex = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
export const bookAvailabilityStatus = (totalCopies, availableCopies) => availableCopies > 0 ? 'Available' : totalCopies > 0 ? 'Busy' : 'Unavailable';
const logError = (label, error, details = {}) => console.error(label, {
  ...details,
  errorName: error?.name || 'Error',
  ...(error?.code !== undefined ? { errorCode: error.code } : {}),
});

mongoose.connection.on('connected', () => console.info('[mongodb] connected', { database: mongoose.connection.name }));
mongoose.connection.on('disconnected', () => console.warn('[mongodb] disconnected'));
mongoose.connection.on('error', (error) => logError('[mongodb] connection error', error));

export async function initializeAdminAccount() {
  const email = process.env.ADMIN_EMAIL?.trim().toLowerCase();
  const password = process.env.ADMIN_PASSWORD;
  if (!email || !password) return null;
  const existing = await User.findOne({ email });
  if (existing) return existing;
  return User.create({ name: process.env.ADMIN_NAME || 'Administrator', email, password, role: 'admin' });
}

app.get('/api/health', (req, res) => res.json({ status: 'ok', database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected' }));
app.post('/api/auth/register', wrap(async (req, res) => {
  const { name, email, password, phone = '', department = '', semester = '', studentNumber = '' } = req.body;
  if (typeof name !== 'string' || !name.trim() || name.trim().length > 100 || !isEmail(email) || !isPassword(password)) return fail(res, 400, 'Enter a name, a valid email, and a password of 8 to 72 UTF-8 bytes.');
  if ([phone, department, studentNumber].some(value => typeof value !== 'string' || value.length > 120) || typeof semester !== 'string' || semester.length > 50) return fail(res, 400, 'Optional profile fields are invalid or too long.');
  const normalizedEmail = email.trim().toLowerCase();
  if (await User.exists({ email: normalizedEmail })) return fail(res, 409, 'An account with this email already exists.');
  const userId = `LIB-${new Date().getFullYear()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
  let user;
  try {
    user = await User.create({ name: name.trim(), email: normalizedEmail, password, phone, department, semester, studentNumber, userId, role: 'student' });
  } catch (error) {
    logError('[registration] save failed', error);
    throw error;
  }
  const token = tokenFor(user);
  res.cookie(sessionCookieName, token, sessionCookieOptions());
  res.status(201).json({ user: safeUser(user), token });
}));
app.post('/api/auth/login', wrap(async (req, res) => {
  const rawIdentity = req.body.email || req.body.userId || '';
  const password = req.body.password;
  if (typeof rawIdentity !== 'string' || rawIdentity.length > 254 || typeof password !== 'string' || Buffer.byteLength(password, 'utf8') > 72) return fail(res, 401, 'Email/User ID or password is incorrect.');
  const identity = cleanString(rawIdentity).toLowerCase();
  const user = await User.findOne({ $or: [{ email: identity }, { userId: identity.toUpperCase() }] }).select('+password');
  if (!user || !(await user.comparePassword(password))) return fail(res, 401, 'Email/User ID or password is incorrect.');
  const token = tokenFor(user);
  res.cookie(sessionCookieName, token, sessionCookieOptions());
  res.json({ user: safeUser(user), token });
}));
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie(sessionCookieName, sessionCookieOptions());
  res.json({ message: 'Signed out.' });
});
app.post('/api/auth/forgot-password', wrap(async (req, res) => {
  const email = req.body.email;
  if (!isEmail(email)) return fail(res, 400, 'Enter a valid email address.');
  if (!process.env.SMTP_HOST || !process.env.SMTP_USER || !process.env.SMTP_PASSWORD) return fail(res, 503, 'Password recovery email is not configured. Ask your administrator to configure SMTP.');
  const user = await User.findOne({ email: cleanString(email).toLowerCase() });
  const generic = { message: 'If an account exists for that email, a recovery link will be sent.' };
  if (!user) return res.json(generic);
  const raw = crypto.randomBytes(32).toString('hex'); user.resetTokenHash = crypto.createHash('sha256').update(raw).digest('hex'); user.resetTokenExpires = Date.now() + 30 * 60 * 1000; await user.save();
  const transport = nodemailer.createTransport({ host: process.env.SMTP_HOST, port: Number(process.env.SMTP_PORT || 587), secure: process.env.SMTP_SECURE === 'true', auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASSWORD } });
  const link = `${process.env.CLIENT_URL?.split(',')[0] || 'http://localhost:3000'}/reset-password?token=${raw}`;
  try {
    void transport.sendMail({ from: process.env.SMTP_FROM || process.env.SMTP_USER, to: user.email, subject: 'Reset your library password', text: `Use this link within 30 minutes to reset your password: ${link}` }).catch(error => logError('[password-recovery] delivery failed', error));
  } catch (error) {
    logError('[password-recovery] delivery failed', error);
  }
  res.json(generic);
}));
app.post('/api/auth/reset-password', wrap(async (req, res) => {
  const { token, password } = req.body; if (typeof token !== 'string' || token.length > 256 || !isPassword(password)) return fail(res, 400, 'A valid recovery token and a password of 8 to 72 UTF-8 bytes are required.');
  const hash = crypto.createHash('sha256').update(token).digest('hex'); const u = await User.findOne({ resetTokenHash: hash, resetTokenExpires: { $gt: Date.now() } }).select('+resetTokenHash +resetTokenExpires');
  if (!u) return fail(res, 400, 'This recovery link is invalid or expired.'); u.password = password; u.resetTokenHash = undefined; u.resetTokenExpires = undefined; await u.save(); res.json({ message: 'Password updated. You can now sign in.' });
}));
app.get('/api/auth/me', auth, (req, res) => { if (req.sessionToken) res.cookie(sessionCookieName, req.sessionToken, sessionCookieOptions()); res.json({ user: safeUser(req.user) }); });
app.patch('/api/users/me', auth, wrap(async (req, res) => {
  const fields = ['name', 'phone', 'department', 'semester', 'studentNumber'];
  if (fields.some(field => req.body[field] !== undefined && typeof req.body[field] !== 'string')) return fail(res, 400, 'Profile fields must be text.');
  if (typeof req.body.name === 'string' && (!req.body.name.trim() || req.body.name.trim().length > 100)) return fail(res, 400, 'Name must be 1 to 100 characters.');
  if (typeof req.body.semester === 'string' && req.body.semester.length > 50) return fail(res, 400, 'Semester must be 50 characters or fewer.');
  if (['phone', 'department', 'studentNumber'].some(field => typeof req.body[field] === 'string' && req.body[field].length > 120)) return fail(res, 400, 'Profile fields must be 120 characters or fewer.');
  fields.forEach(field => { if (req.body[field] !== undefined) req.user[field] = cleanString(req.body[field]); });
  await req.user.save(); res.json({ user: safeUser(req.user) });
}));
app.patch('/api/users/me/password', auth, wrap(async (req, res) => { const u = await User.findById(req.user._id).select('+password'); if (typeof req.body.currentPassword !== 'string' || Buffer.byteLength(req.body.currentPassword, 'utf8') > 72 || !(await u.comparePassword(req.body.currentPassword))) return fail(res, 400, 'Current password is incorrect.'); if (!isPassword(req.body.newPassword)) return fail(res, 400, 'New password must be 8 to 72 UTF-8 bytes.'); u.password = req.body.newPassword; await u.save(); res.json({ message: 'Password updated.' }); }));

app.get('/api/books', wrap(async (req, res) => {
  if (req.query.search !== undefined && (typeof req.query.search !== 'string' || req.query.search.length > 120)) return fail(res, 400, 'Search text must be 120 characters or fewer.');
  if (req.query.available !== undefined && !['true', 'false'].includes(req.query.available)) return fail(res, 400, 'Availability filter must be true or false.');
  if (req.query.category !== undefined && (typeof req.query.category !== 'string' || !mongoose.isObjectIdOrHexString(req.query.category))) return fail(res, 400, 'Choose a valid category.');
  if (req.query.author !== undefined && (typeof req.query.author !== 'string' || !mongoose.isObjectIdOrHexString(req.query.author))) return fail(res, 400, 'Choose a valid author.');
  const page = req.query.page === undefined ? 1 : Number(req.query.page);
  const limit = req.query.limit === undefined ? 24 : Number(req.query.limit);
  if (!Number.isInteger(page) || page < 1 || !Number.isInteger(limit) || limit < 1 || limit > 100) return fail(res, 400, 'Page must be positive and page size must be between 1 and 100.');
  const filter = {};
  const searchTerm = typeof req.query.search === 'string' ? req.query.search.trim() : '';
  if (searchTerm) {
    const query = escapeRegex(searchTerm);
    const matchingAuthors = await Author.find({ name: { $regex: query, $options: 'i' } }).select('_id').lean();
    filter.$or = [
      { title: { $regex: query, $options: 'i' } },
      { isbn: { $regex: query, $options: 'i' } },
      { description: { $regex: query, $options: 'i' } },
      ...(matchingAuthors.length ? [{ author: { $in: matchingAuthors.map(author => author._id) } }] : []),
    ];
  }
  if (req.query.category) filter.category = req.query.category;
  if (req.query.author) filter.author = req.query.author;
  if (req.query.available === 'true') filter.availableCopies = { $gt: 0 };
  if (req.query.available === 'false') filter.availableCopies = 0;
  const total = await Book.countDocuments(filter);
  const books = await Book.find(filter).populate('author', 'name').populate('category', 'name').sort({ createdAt: -1 }).skip((page - 1) * limit).limit(limit);
  const activeCounts = books.length ? await BookIssue.aggregate([
    { $match: { status: 'issued', book: { $in: books.map(book => book._id) } } },
    { $group: { _id: '$book', count: { $sum: 1 } } },
  ]) : [];
  const issuedByBook = new Map(activeCounts.map(item => [String(item._id), item.count]));
  res.json({ books: books.map(book => ({
    ...book.toObject(),
    issuedCopies: issuedByBook.get(String(book._id)) || 0,
    availabilityStatus: bookAvailabilityStatus(book.totalCopies, book.availableCopies),
  })), pagination: { page, limit, total, totalPages: Math.ceil(total / limit) } });
}));
app.get('/api/books/:id/availability', wrap(async (req, res) => {
  if (!mongoose.isObjectIdOrHexString(req.params.id)) return fail(res, 400, 'Book ID is invalid.');
  const book = await Book.findById(req.params.id).populate('author', 'name').populate('category', 'name');
  if (!book) return res.status(404).json({ book: null, status: 'Unavailable', message: 'This title is not in the library catalog.' });
  const issuedCopies = await BookIssue.countDocuments({ book: book._id, status: 'issued' });
  res.json({ book: { ...book.toObject(), issuedCopies, availabilityStatus: bookAvailabilityStatus(book.totalCopies, book.availableCopies) } });
}));
app.get('/api/books/:id/borrowers', auth, admin, wrap(async (req, res) => {
  if (!mongoose.isObjectIdOrHexString(req.params.id)) return fail(res, 400, 'Book ID is invalid.');
  const exists = await Book.exists({ _id: req.params.id });
  if (!exists) return fail(res, 404, 'Book not found.');
  const issues = await BookIssue.find({ book: req.params.id, status: 'issued' })
    .select('student issueDate dueDate')
    .populate('student', 'name userId semester studentNumber department')
    .sort({ issueDate: -1 })
    .lean();
  res.json({ borrowers: issues.filter(issue => issue.student).map(issue => ({
    issueId: issue._id,
    student: {
      name: issue.student.name,
      userId: issue.student.userId,
      semester: issue.student.semester || '',
      rollNumber: issue.student.studentNumber || '',
      department: issue.student.department || '',
    },
    issueDate: issue.issueDate,
    dueDate: issue.dueDate,
  })) });
}));
app.get('/api/books/google-search', auth, admin, wrap(async (req, res) => {
  const query = cleanString(req.query.query || '');
  if (!query || query.length > 160) return fail(res, 400, 'Enter a title or ISBN (up to 160 characters).');
  if (!process.env.GOOGLE_BOOKS_API_KEY) return fail(res, 503, 'Google Books search is not configured on the server.');
  const isbn = /^[\d\s-]{10,17}x?$/i.test(query) && query.replace(/[\s-]/g, '').length >= 10;
  const googleQuery = isbn ? `isbn:${query.replace(/[\s-]/g, '')}` : query;
  const url = new URL('https://www.googleapis.com/books/v1/volumes');
  url.searchParams.set('q', googleQuery);
  url.searchParams.set('maxResults', '20');
  url.searchParams.set('key', process.env.GOOGLE_BOOKS_API_KEY);
  const response = await fetch(url, { signal: AbortSignal.timeout(10000) });
  if (!response.ok) {
    logError('[google-books] upstream request failed', new Error(`Google Books returned ${response.status}`), { status: response.status });
    return fail(res, 502, 'Google Books search is temporarily unavailable. Please try again.');
  }
  const payload = await response.json();
  const books = (payload.items || []).map(({ id, volumeInfo = {} }) => {
    const identifiers = volumeInfo.industryIdentifiers || [];
    const imageLinks = volumeInfo.imageLinks || {};
    return {
      id,
      title: volumeInfo.title || '',
      authors: Array.isArray(volumeInfo.authors) ? volumeInfo.authors : [],
      description: volumeInfo.description || '',
      isbn: identifiers.find(item => item.type === 'ISBN_13')?.identifier || identifiers.find(item => item.type === 'ISBN_10')?.identifier || '',
      publishedDate: volumeInfo.publishedDate || '',
      coverUrl: (imageLinks.thumbnail || imageLinks.smallThumbnail || '').replace(/^http:/, 'https:'),
    };
  });
  res.json({ books });
}));
const validateBookReferences = async ({ author, category }, { requireBoth = false } = {}) => {
  const selected = { author, category };
  for (const field of ['author', 'category']) {
    if (selected[field] === undefined && !requireBoth) continue;
    if (typeof selected[field] !== 'string' || !mongoose.isObjectIdOrHexString(selected[field])) return { status: 400, message: `Choose a valid ${field}.` };
  }
  const [authorExists, categoryExists] = await Promise.all([
    selected.author === undefined ? true : Author.exists({ _id: selected.author }),
    selected.category === undefined ? true : Category.exists({ _id: selected.category }),
  ]);
  if (!authorExists) return { status: 404, message: 'The selected author does not exist. Refresh the author list and choose another.' };
  if (!categoryExists) return { status: 404, message: 'The selected category does not exist. Refresh the category list and choose another.' };
  return null;
};
app.post('/api/books', auth, admin, wrap(async (req, res) => {
  const referenceError = await validateBookReferences(req.body, { requireBoth: true });
  if (referenceError) return fail(res, referenceError.status, referenceError.message);
  const data = { ...req.body }; data.totalCopies ??= 1; data.availableCopies ??= data.totalCopies;
  data.isbn = cleanString(data.isbn || '') || undefined;
  if (!cleanString(data.title || '') || !Number.isInteger(Number(data.totalCopies)) || !Number.isInteger(Number(data.availableCopies)) || Number(data.totalCopies) < 0 || Number(data.availableCopies) < 0 || Number(data.availableCopies) > Number(data.totalCopies)) return fail(res, 400, 'Enter a title and valid copy counts. Available copies cannot exceed total copies.');
  if (data.isbn && await Book.exists({ isbn: cleanString(data.isbn) })) return fail(res, 409, 'A book with this ISBN already exists in the collection.');
  try { res.status(201).json({ book: await Book.create(data) }); }
  catch (error) { if (error?.code === 11000 && error?.keyPattern?.isbn) return fail(res, 409, 'A book with this ISBN already exists in the collection.'); throw error; }
}));
app.patch('/api/books/:id', auth, admin, wrap(async (req, res) => {
  const book = await Book.findById(req.params.id);
  if (!book) return fail(res, 404, 'Book not found.');
  const referenceError = await validateBookReferences({
    ...(Object.hasOwn(req.body, 'author') ? { author: req.body.author } : {}),
    ...(Object.hasOwn(req.body, 'category') ? { category: req.body.category } : {}),
  });
  if (referenceError) return fail(res, referenceError.status, referenceError.message);
  const issued = book.totalCopies - book.availableCopies; Object.assign(book, req.body);
  if (book.totalCopies < issued) return fail(res, 400, 'Total copies cannot be less than copies currently issued.');
  book.availableCopies = book.totalCopies - issued; await book.save(); res.json({ book });
}));
app.delete('/api/books/:id', auth, admin, wrap(async (req, res) => { if (await BookIssue.exists({ book: req.params.id, status: 'issued' })) return fail(res, 409, 'Return active copies before deleting this book.'); const b = await Book.findByIdAndDelete(req.params.id); if (!b) return fail(res, 404, 'Book not found.'); res.json({ message: 'Book deleted.' }); }));

for (const [path, Model] of [['categories', Category], ['authors', Author]]) {
  app.get(`/api/${path}`, wrap(async (req, res) => res.json({ [path]: await Model.find().sort({ name: 1 }) })));
  const singular = path === 'categories' ? 'category' : 'author';
  app.post(`/api/${path}`, auth, admin, wrap(async (req, res) => res.status(201).json({ [singular]: await Model.create(req.body) })));
  app.patch(`/api/${path}/:id`, auth, admin, wrap(async (req, res) => { const doc = await Model.findByIdAndUpdate(req.params.id, req.body, { new: true, runValidators: true }); if (!doc) return fail(res, 404, 'Record not found.'); res.json({ [singular]: doc }); }));
  app.delete(`/api/${path}/:id`, auth, admin, wrap(async (req, res) => { const field = path === 'categories' ? 'category' : 'author'; if (await Book.exists({ [field]: req.params.id })) return fail(res, 409, 'Move or delete books that use this record first.'); const doc = await Model.findByIdAndDelete(req.params.id); if (!doc) return fail(res, 404, 'Record not found.'); res.json({ message: 'Record deleted.' }); }));
}
app.get('/api/users', auth, admin, wrap(async (req, res) => {
  if (req.query.search !== undefined && (typeof req.query.search !== 'string' || req.query.search.length > 120)) return fail(res, 400, 'Search text must be 120 characters or fewer.');
  const q = escapeRegex(cleanString(req.query.search || ''));
  const users = await User.find({ role: 'student', ...(q ? { $or: [{ userId: { $regex: q, $options: 'i' } }, { name: { $regex: q, $options: 'i' } }, { email: { $regex: q, $options: 'i' } }] } : {}) }).sort({ createdAt: -1 });
  res.json({ users: users.map(safeUser) });
}));
app.get('/api/users/:userId', auth, admin, wrap(async (req, res) => { const u = await User.findOne({ userId: req.params.userId.toUpperCase(), role: 'student' }); if (!u) return fail(res, 404, 'Student not found.'); const issues = await BookIssue.find({ student: u._id }).populate('book', 'title isbn').sort({ issueDate: -1 }); res.json({ user: safeUser(u), issues }); }));
app.get('/api/issues', auth, wrap(async (req, res) => { const filter = req.user.role === 'admin' ? {} : { student: req.user._id }; if (req.query.status) filter.status = req.query.status; const issues = await BookIssue.find(filter).populate('book').populate('student', 'name userId email').populate('issuedBy', 'name').populate('returnedBy', 'name').sort({ issueDate: -1 }); res.json({ issues }); }));
app.get('/api/return-requests', auth, admin, wrap(async (req, res) => {
  const requestedStatus = req.query.status || 'pending';
  if (typeof requestedStatus !== 'string' || !['pending', 'approved', 'rejected', 'all'].includes(requestedStatus)) return fail(res, 400, 'Choose a valid return request status.');
  const filter = { returnRequestStatus: requestedStatus === 'all' ? { $in: ['pending', 'approved', 'rejected'] } : requestedStatus };
  if (requestedStatus === 'pending') filter.status = 'issued';
  const requests = await BookIssue.find(filter)
    .populate('book', 'title coverUrl')
    .populate('student', 'name userId department semester studentNumber')
    .sort({ returnRequestDate: -1 });
  res.json({ requests });
}));
app.post('/api/issues/:id/return-request', auth, wrap(async (req, res) => {
  if (req.user.role !== 'student') return fail(res, 403, 'Only students can request returns.');
  if (!mongoose.isObjectIdOrHexString(req.params.id)) return fail(res, 400, 'Issue ID is invalid.');
  const issue = await BookIssue.findOneAndUpdate(
    {
      _id: req.params.id,
      student: req.user._id,
      status: 'issued',
      $or: [
        { returnRequestStatus: { $exists: false } },
        { returnRequestStatus: 'none' },
        { returnRequestStatus: 'rejected' },
      ],
    },
    {
      $set: { returnRequestStatus: 'pending', returnRequestDate: new Date(), returnRequestReason: '' },
      $unset: { returnRequestReviewedAt: 1, returnRequestReviewedBy: 1 },
    },
    { new: true, runValidators: true },
  );
  if (!issue) {
    const ownedIssue = await BookIssue.findOne({ _id: req.params.id, student: req.user._id });
    if (!ownedIssue) return fail(res, 404, 'Active book issue not found.');
    if (ownedIssue.status !== 'issued') return fail(res, 409, 'This book has already been returned.');
    if (ownedIssue.returnRequestStatus === 'pending') return fail(res, 409, 'A return request is already pending for this book.');
    return fail(res, 409, 'This book cannot be requested for return right now.');
  }
  res.status(201).json({ message: 'Return request submitted. Please hand the book to a librarian or administrator.', issue });
}));
app.post('/api/issues/:id/return-request/review', auth, admin, wrap(async (req, res) => {
  if (!mongoose.isObjectIdOrHexString(req.params.id)) return fail(res, 400, 'Issue ID is invalid.');
  const action = req.body.action;
  if (!['approve', 'reject'].includes(action)) return fail(res, 400, 'Choose approve or reject for this return request.');
  const reason = req.body.reason ?? '';
  if (action === 'reject' && (typeof reason !== 'string' || reason.trim().length > 500)) return fail(res, 400, 'Rejection reason must be 500 characters or fewer.');
  const requestFilter = { _id: req.params.id, status: 'issued', returnRequestStatus: 'pending' };
  const reviewedAt = new Date();

  if (action === 'reject') {
    const issue = await BookIssue.findOneAndUpdate(requestFilter, {
      $set: {
        returnRequestStatus: 'rejected',
        returnRequestReason: typeof reason === 'string' ? reason.trim() : '',
        returnRequestReviewedAt: reviewedAt,
        returnRequestReviewedBy: req.user._id,
      },
    }, { new: true, runValidators: true });
    if (!issue) {
      const exists = await BookIssue.exists({ _id: req.params.id });
      return fail(res, exists ? 409 : 404, exists ? 'This issue is no longer awaiting a return decision.' : 'Book issue not found.');
    }
    return res.json({ message: 'Return request rejected.', issue: await issue.populate(['book', 'student']) });
  }

  let issue = null;
  let session;
  try {
    session = await mongoose.startSession();
    await session.withTransaction(async () => {
      issue = await BookIssue.findOneAndUpdate(requestFilter, {
        $set: {
          status: 'returned',
          returnedAt: reviewedAt,
          returnedBy: req.user._id,
          returnNote: 'Student return request approved.',
          returnRequestStatus: 'approved',
          returnRequestReviewedAt: reviewedAt,
          returnRequestReviewedBy: req.user._id,
          returnRequestReason: '',
        },
      }, { new: true, session, runValidators: true });
      if (!issue) return;
      const stock = await Book.updateOne(
        { _id: issue.book, $expr: { $lt: ['$availableCopies', '$totalCopies'] } },
        { $inc: { availableCopies: 1 } },
        { session },
      );
      if (!stock.modifiedCount) {
        const stockConflict = new Error('Book stock cannot be incremented for this return.');
        stockConflict.code = 'RETURN_STOCK_CONFLICT';
        throw stockConflict;
      }
    });
  } catch (error) {
    if (error.code === 'RETURN_STOCK_CONFLICT') return fail(res, 409, error.message);
    logError('[return-request] approval transaction failed', error, { issueId: req.params.id });
    return fail(res, 503, 'Return approval could not be completed. No changes were committed; please retry.');
  } finally {
    await session?.endSession();
  }
  if (!issue) {
    const exists = await BookIssue.exists({ _id: req.params.id });
    return fail(res, exists ? 409 : 404, exists ? 'This issue is no longer awaiting a return decision.' : 'Book issue not found.');
  }
  res.json({ message: 'Return approved and book stock updated.', issue: await issue.populate(['book', 'student', 'returnedBy']) });
}));
app.post('/api/issues', auth, wrap(async (req, res) => {
  const { bookId, userId, dueDate } = req.body;
  if (req.body.selfService === true && req.user.role !== 'student') return fail(res, 403, 'Student borrowing is only available to student accounts.');
  if (!mongoose.isObjectIdOrHexString(bookId)) return fail(res, 400, 'Choose a valid book.');
  const isStudentBorrow = req.user.role === 'student';
  if (!isStudentBorrow && req.user.role !== 'admin') return fail(res, 403, 'Only students can borrow books and administrators can issue books.');
  const [book, student] = await Promise.all([
    Book.findById(bookId),
    isStudentBorrow ? User.findById(req.user._id) : User.findOne({ userId: typeof userId === 'string' ? userId.trim().toUpperCase() : '', role: 'student' }),
  ]);
  if (!book) return fail(res, 404, 'Book not found.'); if (!student) return fail(res, 404, isStudentBorrow ? 'Student account not found.' : 'Student not found.');
  const parsedDueDate = isStudentBorrow
    ? new Date(Date.now() + 14 * 24 * 60 * 60 * 1000)
    : typeof dueDate === 'string' || dueDate instanceof Date ? new Date(dueDate) : new Date(Number.NaN);
  if (Number.isNaN(parsedDueDate.getTime()) || parsedDueDate <= new Date()) return fail(res, 400, 'Choose a valid return date in the future.');
  if (book.availableCopies < 1) return fail(res, 409, 'No available copies remain.');
  if (await BookIssue.exists({ book: book._id, student: student._id, status: 'issued' })) return fail(res, 409, 'This student already has an active issue for this book.');
  const stock = await Book.updateOne({ _id: book._id, availableCopies: { $gt: 0 } }, { $inc: { availableCopies: -1 } });
  if (!stock.modifiedCount) return fail(res, 409, 'No available copies remain.');
  try { const issue = await BookIssue.create({ book: book._id, student: student._id, issuedBy: req.user._id, dueDate: parsedDueDate }); res.status(201).json({ issue: await issue.populate(['book', 'student']) }); }
  catch (error) {
    await Book.updateOne({ _id: book._id }, { $inc: { availableCopies: 1 } });
    if (error.code === 11000) return fail(res, 409, 'This student already has an active issue for this book.');
    throw error;
  }
}));
app.post('/api/issues/:id/return', auth, admin, wrap(async (req, res) => {
  const issue = await BookIssue.findOneAndUpdate(
    { _id: req.params.id, status: 'issued' },
    { $set: { status: 'returned', returnedAt: new Date(), returnedBy: req.user._id, returnNote: cleanString(req.body.note || '') } },
    { new: true },
  );
  if (!issue) {
    const exists = await BookIssue.exists({ _id: req.params.id });
    return fail(res, exists ? 409 : 404, exists ? 'This book has already been returned.' : 'Issue not found.');
  }
  const requestWasPending = issue.returnRequestStatus === 'pending';
  try {
    if (requestWasPending) {
      const approvedRequest = await BookIssue.updateOne(
        { _id: issue._id, status: 'returned', returnRequestStatus: 'pending', returnedAt: issue.returnedAt },
        { $set: { returnRequestStatus: 'approved', returnRequestReviewedAt: issue.returnedAt, returnRequestReviewedBy: req.user._id } },
      );
      if (!approvedRequest.modifiedCount) throw new Error('The pending return request could not be closed.');
    }
    const book = await Book.findById(issue.book);
    if (!book) throw new Error('The returned issue references a missing book.');
    const stock = await Book.updateOne({ _id: book._id }, [{ $set: { availableCopies: { $min: ['$totalCopies', { $add: ['$availableCopies', 1] }] } } }]);
    if (!stock.modifiedCount) throw new Error('Book stock could not be restored for this return.');
  } catch (error) {
    try {
      const restored = await BookIssue.updateOne(
        { _id: issue._id, status: 'returned', returnedBy: req.user._id, returnedAt: issue.returnedAt },
        {
          $set: { status: 'issued', returnNote: '', ...(requestWasPending ? { returnRequestStatus: 'pending' } : {}) },
          $unset: { returnedAt: 1, returnedBy: 1, ...(requestWasPending ? { returnRequestReviewedAt: 1, returnRequestReviewedBy: 1 } : {}) },
        },
      );
      if (!restored.modifiedCount) logError('[issue-return] unable to restore issue after stock update failure', error, { issueId: String(issue._id) });
    } catch (restoreError) {
      logError('[issue-return] issue restoration failed', restoreError, { issueId: String(issue._id) });
    }
    throw error;
  }
  res.json({ issue: await BookIssue.findById(issue._id).populate(['book', 'student', 'returnedBy']) });
}));
app.get('/api/dashboard', auth, wrap(async (req, res) => {
  if (req.user.role === 'admin') {
    const [bookTitles, totalCopies, availableCopies, students, issued, returned, recentIssues, recentStudents, byCategory] = await Promise.all([
      Book.countDocuments(),
      Book.aggregate([{ $group: { _id: null, n: { $sum: '$totalCopies' } } }]),
      Book.aggregate([{ $group: { _id: null, n: { $sum: '$availableCopies' } } }]),
      User.countDocuments({ role: 'student' }),
      BookIssue.countDocuments({ status: 'issued' }),
      BookIssue.countDocuments({ status: 'returned' }),
      BookIssue.find().populate('book', 'title coverUrl').populate('student', 'name userId').sort({ issueDate: -1 }).limit(6),
      User.find({ role: 'student' }).sort({ createdAt: -1 }).limit(5),
      Book.aggregate([{ $group: { _id: '$category', copies: { $sum: '$totalCopies' }, available: { $sum: '$availableCopies' } } }, { $lookup: { from: 'categories', localField: '_id', foreignField: '_id', as: 'category' } }, { $unwind: { path: '$category', preserveNullAndEmptyArrays: true } }, { $project: { name: '$category.name', copies: 1, available: 1 } }]),
    ]);
    return res.json({
      stats: { totalBooks: totalCopies[0]?.n || 0, bookTitles, availableBooks: availableCopies[0]?.n || 0, students, issued, returned },
      recentIssues,
      recentStudents: recentStudents.map(safeUser),
      byCategory,
    });
  }

  const [issues, available, availableCopies] = await Promise.all([
    BookIssue.find({ student: req.user._id }).populate('book').sort({ issueDate: -1 }),
    Book.countDocuments({ availableCopies: { $gt: 0 } }),
    Book.aggregate([{ $group: { _id: null, n: { $sum: '$availableCopies' } } }]),
  ]);
  const activeIssues = issues.filter(issue => issue.status === 'issued');
  const returnedIssues = issues.filter(issue => issue.status === 'returned');
  const borrowedBookIds = issues.map(issue => issue.book?._id).filter(Boolean);
  const recommendedBooks = await Book.find({ availableCopies: { $gt: 0 }, ...(borrowedBookIds.length ? { _id: { $nin: borrowedBookIds } } : {}) })
    .populate('author', 'name').populate('category', 'name').sort({ createdAt: -1 }).limit(4);
  res.json({
    stats: {
      available,
      availableBooks: availableCopies[0]?.n || 0,
      issued: activeIssues.length,
      overdue: activeIssues.filter(issue => issue.dueDate < new Date()).length,
      returned: returnedIssues.length,
    },
    issues,
    recentIssues: issues.slice(0, 5),
    recommendedBooks,
  });
}));

app.use((req, res) => fail(res, 404, 'API endpoint not found.'));
app.use((err, req, res, next) => {
  logError('[http] request failed', err, { method: req.method, path: req.path });
  if (err.code === 11000) return fail(res, 409, 'That value is already in use.');
  if (err.name === 'ValidationError' || err.name === 'CastError' || err.type === 'entity.parse.failed') return fail(res, 400, 'The request contains invalid data.');
  if (err.status === 413 || err.type === 'entity.too.large') return fail(res, 413, 'Request body is too large.');
  res.status(500).json({ message: 'Something went wrong. Please try again.' });
});

const start = async () => {
  if (!process.env.MONGODB_URI || !process.env.JWT_SECRET || Buffer.byteLength(process.env.JWT_SECRET, 'utf8') < 32) throw new Error('Set MONGODB_URI and a JWT_SECRET of at least 32 UTF-8 bytes in server/.env.');
  await mongoose.connect(process.env.MONGODB_URI, { dbName: process.env.MONGODB_DATABASE || 'library_management' });
  await initializeAdminAccount();
  const port = process.env.PORT || 5000; app.listen(port, '0.0.0.0', () => console.log(`Library API listening on port ${port}`));
};
if (process.env.NODE_ENV !== 'test') start().catch(err => { logError('[startup] failed', err); process.exit(1); });
export default app;
