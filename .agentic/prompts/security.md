# Security Guidelines

## Your Role
You are responsible for writing secure code that protects user data, prevents vulnerabilities, and maintains system integrity. Security is not optional—it's a fundamental requirement.

## Security Mindset

### Core Principles
1. **Assume breach**: Write code expecting attackers will try everything
2. **Defense in depth**: Multiple layers of security, never rely on one
3. **Least privilege**: Grant minimum necessary permissions
4. **Fail securely**: Errors should not expose sensitive information
5. **Trust no input**: Validate and sanitize everything from outside

## Critical Security Rules

### 🚨 NEVER Do These Things

```typescript
// ❌ CRITICAL: Never store passwords in plain text
user.password = plainPassword;

// ❌ CRITICAL: Never log sensitive data
console.log('User password:', password);
logger.info('Credit card:', creditCardNumber);

// ❌ CRITICAL: Never hardcode secrets
const API_KEY = 'sk_live_abc123xyz';
const DB_PASSWORD = 'mypassword123';

// ❌ CRITICAL: Never use string concatenation for SQL
const query = `SELECT * FROM users WHERE id = ${userId}`;

// ❌ CRITICAL: Never trust user input in commands
exec(`process ${userInput}`);

// ❌ CRITICAL: Never return sensitive data in errors
catch (error) {
  res.json({ error: error.stack, dbPassword: process.env.DB_PASSWORD });
}

// ❌ CRITICAL: Never use weak cryptography
const hash = md5(password); // MD5 is broken
const encrypted = btoa(secret); // Base64 is not encryption

// ❌ CRITICAL: Never disable security features
app.disable('x-powered-by'); // Good
helmet({ contentSecurityPolicy: false }); // Bad!
```

## Input Validation

### Validate Everything
```typescript
// ✅ Validate all user input
function createUser(data: unknown) {
  const schema = z.object({
    email: z.string().email(),
    age: z.number().min(13).max(120),
    role: z.enum(['user', 'admin'])
  });
  
  const validated = schema.parse(data); // Throws if invalid
  return validated;
}

// ✅ Sanitize HTML input
import DOMPurify from 'dompurify';
const cleanHtml = DOMPurify.sanitize(userInput);

// ✅ Validate file uploads
function validateUpload(file: File) {
  const allowedTypes = ['image/jpeg', 'image/png'];
  const maxSize = 5 * 1024 * 1024; // 5MB
  
  if (!allowedTypes.includes(file.type)) {
    throw new ValidationError('Invalid file type');
  }
  
  if (file.size > maxSize) {
    throw new ValidationError('File too large');
  }
}

// ✅ Whitelist over blacklist
function isValidUsername(username: string): boolean {
  // Allow only alphanumeric and underscore
  return /^[a-zA-Z0-9_]+$/.test(username);
}
```

### SQL Injection Prevention
```typescript
// ✅ Use parameterized queries
const user = await db.query(
  'SELECT * FROM users WHERE id = ?',
  [userId]
);

// ✅ Use ORMs with proper escaping
const user = await User.findOne({ where: { id: userId } });

// ✅ Validate and sanitize even with parameterized queries
function getUser(userId: string) {
  if (!/^[0-9]+$/.test(userId)) {
    throw new ValidationError('Invalid user ID format');
  }
  return db.query('SELECT * FROM users WHERE id = ?', [userId]);
}
```

### XSS Prevention
```typescript
// ✅ Escape output in templates
// React does this automatically
<div>{userInput}</div>

// ✅ Use dangerouslySetInnerHTML only with sanitized content
<div dangerouslySetInnerHTML={{ 
  __html: DOMPurify.sanitize(userHtml) 
}} />

// ✅ Set Content Security Policy
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"],
    styleSrc: ["'self'", "'unsafe-inline'"],
  }
}));

// ✅ Sanitize before storing
function saveComment(comment: string) {
  const sanitized = DOMPurify.sanitize(comment, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a'],
    ALLOWED_ATTR: ['href']
  });
  return db.comments.create({ text: sanitized });
}
```

## Authentication & Authorization

### Password Security
```typescript
// ✅ Hash passwords with strong algorithm
import bcrypt from 'bcrypt';

async function hashPassword(password: string): Promise<string> {
  const saltRounds = 12; // Minimum 10, prefer 12+
  return bcrypt.hash(password, saltRounds);
}

async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}

// ✅ Enforce password requirements
function validatePassword(password: string): void {
  if (password.length < 12) {
    throw new ValidationError('Password must be at least 12 characters');
  }
  
  if (!/[A-Z]/.test(password)) {
    throw new ValidationError('Password must contain uppercase letter');
  }
  
  if (!/[a-z]/.test(password)) {
    throw new ValidationError('Password must contain lowercase letter');
  }
  
  if (!/[0-9]/.test(password)) {
    throw new ValidationError('Password must contain number');
  }
  
  if (!/[^A-Za-z0-9]/.test(password)) {
    throw new ValidationError('Password must contain special character');
  }
}

// ✅ Implement rate limiting for login attempts
import rateLimit from 'express-rate-limit';

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts
  message: 'Too many login attempts, please try again later'
});

app.post('/auth/login', loginLimiter, handleLogin);
```

### Token Security
```typescript
// ✅ Use secure token generation
import crypto from 'crypto';

function generateSecureToken(): string {
  return crypto.randomBytes(32).toString('hex');
}

// ✅ Set secure JWT options
import jwt from 'jsonwebtoken';

function createToken(userId: string): string {
  return jwt.sign(
    { userId },
    process.env.JWT_SECRET!,
    {
      expiresIn: '15m', // Short expiration
      issuer: 'your-app',
      audience: 'your-api'
    }
  );
}

// ✅ Implement token refresh
function createRefreshToken(userId: string): string {
  return jwt.sign(
    { userId, type: 'refresh' },
    process.env.REFRESH_SECRET!,
    { expiresIn: '7d' }
  );
}

// ✅ Validate tokens thoroughly
function validateToken(token: string): TokenPayload {
  try {
    return jwt.verify(token, process.env.JWT_SECRET!) as TokenPayload;
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      throw new UnauthorizedError('Token expired');
    }
    if (error instanceof jwt.JsonWebTokenError) {
      throw new UnauthorizedError('Invalid token');
    }
    throw error;
  }
}
```

### Authorization Checks
```typescript
// ✅ Check permissions for every protected action
async function deleteUser(actingUser: User, targetUserId: string) {
  // Check authentication
  if (!actingUser) {
    throw new UnauthorizedError('Not authenticated');
  }
  
  // Check authorization
  if (!actingUser.hasPermission('users:delete')) {
    throw new ForbiddenError('Insufficient permissions');
  }
  
  // Prevent privilege escalation
  const targetUser = await User.findById(targetUserId);
  if (targetUser.role === 'admin' && actingUser.role !== 'superadmin') {
    throw new ForbiddenError('Cannot delete admin users');
  }
  
  // Prevent self-deletion
  if (targetUserId === actingUser.id) {
    throw new ValidationError('Cannot delete your own account');
  }
  
  await User.delete(targetUserId);
}

// ✅ Implement resource ownership checks
async function updatePost(userId: string, postId: string, data: PostData) {
  const post = await Post.findById(postId);
  
  if (!post) {
    throw new NotFoundError('Post not found');
  }
  
  // Check ownership
  if (post.authorId !== userId) {
    throw new ForbiddenError('You can only edit your own posts');
  }
  
  return Post.update(postId, data);
}
```

## Data Protection

### Sensitive Data Handling
```typescript
// ✅ Encrypt sensitive data at rest
import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';

function encryptSensitiveData(data: string): string {
  const algorithm = 'aes-256-gcm';
  const key = Buffer.from(process.env.ENCRYPTION_KEY!, 'hex');
  const iv = randomBytes(16);
  
  const cipher = createCipheriv(algorithm, key, iv);
  const encrypted = Buffer.concat([
    cipher.update(data, 'utf8'),
    cipher.final()
  ]);
  
  const tag = cipher.getAuthTag();
  
  return JSON.stringify({
    iv: iv.toString('hex'),
    tag: tag.toString('hex'),
    data: encrypted.toString('hex')
  });
}

// ✅ Mask sensitive data in logs
function maskCreditCard(cardNumber: string): string {
  return cardNumber.replace(/\d(?=\d{4})/g, '*');
}

function maskEmail(email: string): string {
  const [local, domain] = email.split('@');
  return `${local[0]}***@${domain}`;
}

// ✅ Strip sensitive fields from API responses
function sanitizeUser(user: User): PublicUser {
  const { password, passwordResetToken, ...publicData } = user;
  return publicData;
}
```

### Secure Configuration
```typescript
// ✅ Use environment variables for secrets
const config = {
  database: {
    host: process.env.DB_HOST,
    password: process.env.DB_PASSWORD, // Never hardcode
  },
  jwt: {
    secret: process.env.JWT_SECRET,
  }
};

// ✅ Validate environment variables on startup
function validateEnv() {
  const required = [
    'DB_HOST',
    'DB_PASSWORD',
    'JWT_SECRET',
    'ENCRYPTION_KEY'
  ];
  
  for (const key of required) {
    if (!process.env[key]) {
      throw new Error(`Missing required environment variable: ${key}`);
    }
  }
  
  // Validate format
  if (process.env.JWT_SECRET!.length < 32) {
    throw new Error('JWT_SECRET must be at least 32 characters');
  }
}

// ✅ Use different secrets for different environments
// .env.production
JWT_SECRET=random_64_character_production_secret
// .env.development
JWT_SECRET=random_64_character_development_secret
```

## API Security

### HTTPS & Transport Security
```typescript
// ✅ Enforce HTTPS in production
app.use((req, res, next) => {
  if (process.env.NODE_ENV === 'production' && !req.secure) {
    return res.redirect(301, `https://${req.headers.host}${req.url}`);
  }
  next();
});

// ✅ Set security headers
import helmet from 'helmet';
app.use(helmet());

// ✅ Configure CORS properly
import cors from 'cors';
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(','),
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
```

### Rate Limiting
```typescript
// ✅ Implement rate limiting on all endpoints
import rateLimit from 'express-rate-limit';

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 requests per window
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/api/', apiLimiter);

// ✅ Stricter limits for sensitive endpoints
const strictLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
});

app.post('/api/auth/login', strictLimiter, handleLogin);
app.post('/api/auth/reset-password', strictLimiter, handleReset);
```

### Request Validation
```typescript
// ✅ Validate request size
app.use(express.json({ limit: '10kb' }));

// ✅ Validate content type
app.use((req, res, next) => {
  if (req.method === 'POST' || req.method === 'PUT') {
    const contentType = req.get('Content-Type');
    if (!contentType || !contentType.includes('application/json')) {
      return res.status(415).json({ error: 'Content-Type must be application/json' });
    }
  }
  next();
});

// ✅ Validate request body structure
import { z } from 'zod';

const createUserSchema = z.object({
  email: z.string().email().max(255),
  name: z.string().min(1).max(100),
  age: z.number().int().min(13).max(120)
});

app.post('/api/users', (req, res) => {
  try {
    const data = createUserSchema.parse(req.body);
    // Process valid data
  } catch (error) {
    return res.status(400).json({ error: 'Invalid request data' });
  }
});
```

## Error Handling

### Secure Error Messages
```typescript
// ❌ Bad: Exposes internal details
catch (error) {
  res.json({ 
    error: error.message, // "ECONNREFUSED: Connection to db.internal:5432 failed"
    stack: error.stack 
  });
}

// ✅ Good: Generic message to client, detailed log
catch (error) {
  logger.error('Database connection failed', { 
    error: error.message,
    stack: error.stack,
    userId: req.user?.id 
  });
  
  res.status(500).json({ 
    error: 'An error occurred processing your request' 
  });
}

// ✅ Provide safe error details
class AppError extends Error {
  constructor(
    public message: string,
    public statusCode: number,
    public isOperational: boolean = true
  ) {
    super(message);
  }
  
  toJSON() {
    return {
      error: this.message,
      statusCode: this.statusCode
    };
  }
}

// Use specific, safe error types
throw new AppError('User not found', 404);
// Not: throw new Error('Database query failed: SELECT * FROM users WHERE...')
```

## File Upload Security

```typescript
// ✅ Validate file uploads
import multer from 'multer';
import path from 'path';

const storage = multer.diskStorage({
  destination: './uploads/',
  filename: (req, file, cb) => {
    // Generate safe filename
    const uniqueName = `${Date.now()}-${crypto.randomUUID()}`;
    const ext = path.extname(file.originalname);
    cb(null, uniqueName + ext);
  }
});

const upload = multer({
  storage,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB max
    files: 1
  },
  fileFilter: (req, file, cb) => {
    // Whitelist allowed types
    const allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
    
    if (!allowedTypes.includes(file.mimetype)) {
      cb(new Error('Invalid file type'));
      return;
    }
    
    cb(null, true);
  }
});

// ✅ Scan uploaded files
import { scanFile } from './virus-scanner';

app.post('/upload', upload.single('file'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }
  
  // Scan for malware
  const isSafe = await scanFile(req.file.path);
  if (!isSafe) {
    fs.unlinkSync(req.file.path); // Delete unsafe file
    return res.status(400).json({ error: 'File failed security scan' });
  }
  
  // Process safe file
});

// ✅ Store files outside web root
// Store in: /var/app/uploads (not accessible via web)
// Not in: /var/app/public/uploads (publicly accessible)
```

## Dependency Security

```typescript
// ✅ Regularly audit dependencies
// npm audit
// npm audit fix

// ✅ Use dependency scanning in CI/CD
// .github/workflows/security.yml
name: Security Audit
on: [push, pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - run: npm audit --audit-level=moderate

// ✅ Lock dependency versions
// Use package-lock.json or yarn.lock
// Commit lockfiles to repository

// ✅ Review dependencies before adding
// Check: last update, maintainers, downloads, issues
// Prefer well-maintained, popular packages
// Avoid dependencies with few stars or abandoned projects
```

## Security Checklist

### For Every Feature
- [ ] All inputs validated and sanitized
- [ ] Authentication required if needed
- [ ] Authorization checks in place
- [ ] No secrets in code
- [ ] Sensitive data encrypted
- [ ] SQL injection prevented
- [ ] XSS prevented
- [ ] CSRF tokens used for state-changing operations
- [ ] Rate limiting configured
- [ ] Error messages don't leak information
- [ ] Logging doesn't expose sensitive data
- [ ] HTTPS enforced in production

### For Every Release
- [ ] Dependencies audited
- [ ] Security headers configured
- [ ] Secrets rotated if exposed
- [ ] Penetration testing complete
- [ ] Security review conducted
- [ ] Incident response plan updated

## Common Vulnerabilities

### OWASP Top 10
1. **Broken Access Control** - Always verify permissions
2. **Cryptographic Failures** - Use strong, modern crypto
3. **Injection** - Parameterize queries, validate input
4. **Insecure Design** - Security by design, not afterthought
5. **Security Misconfiguration** - Review all settings
6. **Vulnerable Components** - Keep dependencies updated
7. **Authentication Failures** - Strong passwords, MFA, rate limiting
8. **Data Integrity Failures** - Verify data hasn't been tampered
9. **Logging Failures** - Log security events properly
10. **Server-Side Request Forgery** - Validate and restrict URLs

## Security Resources

- OWASP Cheat Sheets: https://cheatsheetseries.owasp.org/
- Node.js Security Best Practices: https://nodejs.org/en/docs/guides/security/
- npm Security: https://docs.npmjs.com/auditing-package-dependencies-for-security-vulnerabilities

## Remember

- Security is everyone's responsibility
- Assume all input is malicious
- Defense in depth - multiple layers
- Keep secrets secret
- Update dependencies regularly
- Log security events
- Test security controls
- Stay informed about new threats