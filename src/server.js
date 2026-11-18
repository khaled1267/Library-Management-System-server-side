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
if (process.env.NODE_ENV === 'production' && (!configuredClientOrigins.length || configuredClientOrigins.some(origin => {
  try { const parsed = new URL(origin); return parsed.protocol !== 'https:' || parsed.origin !== origin; } catch { return true; }
}))) {
  throw new Error('Set CLIENT_URL to one or more exact HTTPS frontend origins in production.');
}
const allowedClientOrigins = new Set(configuredClientOrigins.length ? configuredClientOrigins : ['http://localhost:3000']);
app.use(cors({ origin: [...allowedClientOrigins], credentials: true }));
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
const safeUser = (u) => ({ _id: u._id, userId: u.userId, name: u.name, email: u.email, role: u.role, phone: u.phone, department: u.department, studentNumber: u.studentNumber, createdAt: u.createdAt });
const tokenFor = (u) => jwt.sign({ sub: u._id.toString(), role: u.role }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN || '7d', algorithm: 'HS256' });
const sessionCookieName = 'library_session';
const sessionCookieOptions = () => {
  const configuredSameSite = process.env.SESSION_COOKIE_SAME_SITE?.toLowerCase();
  const sameSite = ['strict', 'lax', 'none'].includes(configuredSameSite) ? configuredSameSite : 'lax';
  return { httpOnly: true, secure: process.env.NODE_ENV === 'production' || sameSite === 'none', sameSite, path: '/' };
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
  const { name, email, password, phone = '', department = '', studentNumber = '' } = req.body;
  if (typeof name !== 'string' || !name.trim() || name.trim().length > 100 || !isEmail(email) || !isPassword(password)) return fail(res, 400, 'Enter a name, a valid email, and a password of 8 to 72 UTF-8 bytes.');
  if ([phone, department, studentNumber].some(value => typeof value !== 'string' || value.length > 120)) return fail(res, 400, 'Optional profile fields must be text no longer than 120 characters.');
  const normalizedEmail = email.trim().toLowerCase();
  if (await User.exists({ email: normalizedEmail })) return fail(res, 409, 'An account with this email already exists.');
  const userId = `LIB-${new Date().getFullYear()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
  let user;
  try {
    user = await User.create({ name: name.trim(), email: normalizedEmail, password, phone, department, studentNumber, userId, role: 'student' });
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
app.patch('/api/users/me', auth, wrap(async (req, res) => { const fields = ['name', 'phone', 'department', 'studentNumber']; fields.forEach(k => { if (req.body[k] !== undefined) req.user[k] = cleanString(req.body[k]); }); await req.user.save(); res.json({ user: safeUser(req.user) }); }));
app.patch('/api/users/me/password', auth, wrap(async (req, res) => { const u = await User.findById(req.user._id).select('+password'); if (typeof req.body.currentPassword !== 'string' || Buffer.byteLength(req.body.currentPassword, 'utf8') > 72 || !(await u.comparePassword(req.body.currentPassword))) return fail(res, 400, 'Current password is incorrect.'); if (!isPassword(req.body.newPassword)) return fail(res, 400, 'New password must be 8 to 72 UTF-8 bytes.'); u.password = req.body.newPassword; await u.save(); res.json({ message: 'Password updated.' }); }));

app.get('/api/books', wrap(async (req, res) => {
  if (req.query.search !== undefined && (typeof req.query.search !== 'string' || req.query.search.length > 120)) return fail(res, 400, 'Search text must be 120 characters or fewer.');
  const filter = {}; if (req.query.search) { const query = escapeRegex(req.query.search); filter.$or = ['title', 'isbn', 'description'].map(k => ({ [k]: { $regex: query, $options: 'i' } })); }
  if (req.query.category) filter.category = req.query.category; if (req.query.available === 'true') filter.availableCopies = { $gt: 0 };
  const books = await Book.find(filter).populate('author', 'name').populate('category', 'name').sort({ createdAt: -1 }); res.json({ books });
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
app.post('/api/issues', auth, admin, wrap(async (req, res) => {
  const { bookId, userId, dueDate } = req.body; const [book, student] = await Promise.all([Book.findById(bookId), User.findOne({ userId: String(userId).toUpperCase(), role: 'student' })]);
  if (!book) return fail(res, 404, 'Book not found.'); if (!student) return fail(res, 404, 'Student not found.');
  const parsedDueDate = typeof dueDate === 'string' || dueDate instanceof Date ? new Date(dueDate) : new Date(Number.NaN);
  if (Number.isNaN(parsedDueDate.getTime()) || parsedDueDate <= new Date()) return fail(res, 400, 'Choose a valid return date in the future.');
  if (book.availableCopies < 1) return fail(res, 409, 'No available copies remain.');
  if (await BookIssue.exists({ book: book._id, student: student._id, status: 'issued' })) return fail(res, 409, 'This student already has an active issue for this book.');
  const stock = await Book.updateOne({ _id: book._id, availableCopies: { $gt: 0 } }, { $inc: { availableCopies: -1 } });
  if (!stock.modifiedCount) return fail(res, 409, 'No available copies remain.');
  try { const issue = await BookIssue.create({ book: book._id, student: student._id, issuedBy: req.user._id, dueDate: parsedDueDate }); res.status(201).json({ issue: await issue.populate(['book', 'student']) }); }
  catch (error) { await Book.updateOne({ _id: book._id }, { $inc: { availableCopies: 1 } }); throw error; }
}));
app.post('/api/issues/:id/return', auth, admin, wrap(async (req, res) => { const issue = await BookIssue.findOneAndUpdate({ _id: req.params.id, status: 'issued' }, { $set: { status: 'returned', returnedAt: new Date(), returnedBy: req.user._id, returnNote: cleanString(req.body.note || '') } }, { new: true }); if (!issue) { const exists = await BookIssue.exists({ _id: req.params.id }); return fail(res, exists ? 409 : 404, exists ? 'This book has already been returned.' : 'Issue not found.'); } const book = await Book.findById(issue.book); if (book) await Book.updateOne({ _id: book._id }, [{ $set: { availableCopies: { $min: ['$totalCopies', { $add: ['$availableCopies', 1] }] } } }]); res.json({ issue: await issue.populate(['book', 'student', 'returnedBy']) }); }));
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
