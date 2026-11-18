import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';

const userSchema = new mongoose.Schema({
  userId: { type: String, unique: true, sparse: true, index: true },
  name: { type: String, required: true, trim: true, maxlength: 100 },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true, select: false },
  role: { type: String, enum: ['admin', 'student'], default: 'student' },
  phone: { type: String, trim: true, default: '' },
  department: { type: String, trim: true, default: '' },
  studentNumber: { type: String, trim: true, default: '' },
  resetTokenHash: { type: String, select: false },
  resetTokenExpires: { type: Date, select: false }
}, { timestamps: true });
userSchema.pre('save', async function () { if (this.isModified('password')) this.password = await bcrypt.hash(this.password, 12); });
userSchema.methods.comparePassword = function (password) { return bcrypt.compare(password, this.password); };

const categorySchema = new mongoose.Schema({ name: { type: String, required: true, trim: true, unique: true }, description: { type: String, trim: true, default: '' } }, { timestamps: true });
const authorSchema = new mongoose.Schema({ name: { type: String, required: true, trim: true }, biography: { type: String, trim: true, default: '' }, email: { type: String, lowercase: true, trim: true, default: '' } }, { timestamps: true });
const bookSchema = new mongoose.Schema({
  title: { type: String, required: true, trim: true }, isbn: { type: String, trim: true, unique: true, sparse: true },
  author: { type: mongoose.Schema.Types.ObjectId, ref: 'Author', required: true },
  category: { type: mongoose.Schema.Types.ObjectId, ref: 'Category', required: true },
  description: { type: String, trim: true, default: '' }, coverUrl: { type: String, trim: true, default: '' },
  publishedDate: { type: String, trim: true, default: '' },
  publishedYear: { type: Number, min: 0 }, totalCopies: { type: Number, min: 0, required: true, default: 1 },
  availableCopies: { type: Number, min: 0, required: true, default: 1 }, shelf: { type: String, trim: true, default: '' }
}, { timestamps: true });
const issueSchema = new mongoose.Schema({
  book: { type: mongoose.Schema.Types.ObjectId, ref: 'Book', required: true },
  student: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  issuedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  issueDate: { type: Date, default: Date.now }, dueDate: { type: Date, required: true },
  returnedAt: { type: Date, default: null }, returnedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  returnNote: { type: String, trim: true, default: '' }, status: { type: String, enum: ['issued', 'returned'], default: 'issued' }
}, { timestamps: true });
issueSchema.index({ book: 1, student: 1 }, { unique: true, partialFilterExpression: { status: 'issued' } });

export const User = mongoose.model('User', userSchema);
export const Category = mongoose.model('Category', categorySchema);
export const Author = mongoose.model('Author', authorSchema);
export const Book = mongoose.model('Book', bookSchema);
export const BookIssue = mongoose.model('BookIssue', issueSchema);
// error handling for unique constraints