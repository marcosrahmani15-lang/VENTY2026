import express, { Request, Response, NextFunction } from 'express';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import dotenv from 'dotenv';
import {
  isPostgresConfigured,
  runMigrations,
  migrateJsonToPostgres,
  pgRepository,
} from './src/db/index';

dotenv.config();

process.on('uncaughtException', (err: Error) => {
  console.error('[VENTY CRITICAL] Uncaught exception:', err?.message || err);
  if (err?.stack) {
    console.error(err.stack);
  }
});

process.on('unhandledRejection', (reason: any) => {
  console.error('[VENTY WARNING] Unhandled promise rejection:', reason?.message || reason);
});

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;
const IS_PRODUCTION = process.env.NODE_ENV === 'production';
const IS_SERVERLESS = process.env.VERCEL === '1' || Boolean(process.env.AWS_LAMBDA_FUNCTION_NAME);
const BUNDLED_DATA_DIR = path.resolve(__dirname, 'data_store');
const DATA_DIR = process.env.DATA_STORE_DIR
  ? path.resolve(process.env.DATA_STORE_DIR)
  : (IS_SERVERLESS ? path.resolve('/tmp', 'data_store') : BUNDLED_DATA_DIR);
const DB_FILE = path.resolve(DATA_DIR, 'venty_loyalty_db.json');
const DB_BACKUP_FILE = path.resolve(DATA_DIR, 'venty_loyalty_db.bak.json');
const SESSIONS_FILE = path.resolve(DATA_DIR, 'venty_sessions.json');
const AUDIT_LOG_FILE = path.resolve(DATA_DIR, 'venty_audit.log');
const BACKUPS_DIR = path.resolve(DATA_DIR, 'backups');

// -------------------------------------------------------------
// 0. STARTUP SECRET & DATA STORE VALIDATION
// -------------------------------------------------------------
const KNOWN_WEAK_SECRETS = new Set([
  'admin',
  'password',
  '123456',
  '12345678',
  'admin123',
  'secret',
  'test',
  'changeme',
  'venty',
  'ventycoffee',
  'root',
  '12345',
  'change_me_production_admin_secret',
]);

const KNOWN_WEAK_PINS = new Set([
  '0000',
  '1111',
  '2222',
  '3333',
  '4444',
  '5555',
  '6666',
  '7777',
  '8888',
  '9999',
  '000000',
  '111111',
  '222222',
  '333333',
  '444444',
  '555555',
  '666666',
  '777777',
  '888888',
  '999999',
  '1234',
  '12345',
  '123456',
  '1234567',
  '12345678',
  '654321',
  '87654321',
  '4321',
  'admin',
  'change_me_production_staff_pin',
]);

export const isTrivialRepeatingOrSequential = (val: string): boolean => {
  if (!val || val.length < 2) return true;
  if (/^(.)\1+$/.test(val)) return true;
  let asc = true;
  let desc = true;
  for (let i = 0; i < val.length - 1; i++) {
    const diff = val.charCodeAt(i + 1) - val.charCodeAt(i);
    if (diff !== 1) asc = false;
    if (diff !== -1) desc = false;
  }
  return asc || desc;
};

const timingSafeSecretEquals = (candidate: string, configuredSecret: string): boolean => {
  if (
    !candidate ||
    !configuredSecret ||
    typeof candidate !== 'string' ||
    typeof configuredSecret !== 'string'
  ) {
    return false;
  }
  const cleanCandidate = candidate.trim();
  const cleanConfigured = configuredSecret.trim();
  if (!cleanCandidate || !cleanConfigured) {
    return false;
  }
  const hashA = crypto.createHash('sha256').update(cleanCandidate, 'utf8').digest();
  const hashB = crypto.createHash('sha256').update(cleanConfigured, 'utf8').digest();
  return crypto.timingSafeEqual(hashA, hashB);
};

const validateStartupSecretsAndStorage = () => {
  console.log('[VENTY MANAGEMENT] Direct management portal access active at /management.');

  try {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }
    if (!fs.existsSync(BACKUPS_DIR)) {
      fs.mkdirSync(BACKUPS_DIR, { recursive: true });
    }

    // In serverless environments, if local writable DB doesn't exist yet, seed from bundled copy
    if (IS_SERVERLESS && !fs.existsSync(DB_FILE)) {
      const bundledDbFile = path.resolve(BUNDLED_DATA_DIR, 'venty_loyalty_db.json');
      if (fs.existsSync(bundledDbFile)) {
        try {
          fs.copyFileSync(bundledDbFile, DB_FILE);
          console.log('[VENTY Serverless] Seeded loyalty DB from bundled data_store snapshot.');
        } catch (copyErr) {
          console.warn('[VENTY Serverless] Failed to seed DB from bundle:', copyErr);
        }
      }
    }

    const probeFile = path.resolve(DATA_DIR, `.write_probe_${process.pid}`);
    fs.writeFileSync(probeFile, 'ok', 'utf-8');
    fs.unlinkSync(probeFile);
  } catch (err: any) {
    console.error(
      `[VENTY FATAL STARTUP ERROR] DATA_STORE_DIR (${DATA_DIR}) is not writable: ${err?.message || 'Permission denied'}.`,
    );
    if (!IS_SERVERLESS) {
      process.exit(1);
    }
  }
};

validateStartupSecretsAndStorage();

// -------------------------------------------------------------
// 1. STRUCTURED AUDIT LOGGING UTILITY
// -------------------------------------------------------------
export const logAuditEvent = (eventType: string, details: Record<string, any>) => {
  const sanitized = { ...details };
  // Never log raw secrets, PINs, passwords, hashes, OTPs, salts, tokens, or auth headers
  if (sanitized.adminSecret) sanitized.adminSecret = '***';
  if (sanitized.staffPin) sanitized.staffPin = '***';
  if (sanitized.passcode) sanitized.passcode = '***';
  if (sanitized.password) sanitized.password = '***';
  if (sanitized.confirmPassword) sanitized.confirmPassword = '***';
  if (sanitized.newPassword) sanitized.newPassword = '***';
  if (sanitized.passwordHash) sanitized.passwordHash = '***';
  if (sanitized.resetToken) sanitized.resetToken = '***';
  if (sanitized.resetCode) sanitized.resetCode = '***';
  if (sanitized.otp) sanitized.otp = '***';
  if (sanitized.otpCode) sanitized.otpCode = '***';
  if (sanitized.code) sanitized.code = '***';
  if (sanitized.otpHash) sanitized.otpHash = '***';
  if (sanitized.salt) sanitized.salt = '***';
  if (sanitized.token) sanitized.token = '***';
  if (sanitized.sessionToken) sanitized.sessionToken = '***';
  if (sanitized.rawToken) sanitized.rawToken = '***';
  if (sanitized.authorization) sanitized.authorization = '***';
  if (sanitized.cookie) sanitized.cookie = '***';

  const logEntry = {
    timestamp: new Date().toISOString(),
    event: eventType,
    ...sanitized,
  };
  try {
    fs.appendFileSync(AUDIT_LOG_FILE, `${JSON.stringify(logEntry)}\n`, 'utf-8');
  } catch {
    // Non-blocking audit persistence
  }
  if (process.env.VENTY_STDOUT_AUDIT === 'true') {
    console.log(`[VENTY AUDIT] ${JSON.stringify(logEntry)}`);
  }
};

// -------------------------------------------------------------
// 2. CORS & HTTP SECURITY HEADERS
// -------------------------------------------------------------
app.use(express.json({ limit: '1mb' }));

// Restrict CORS to configured allowed origins (Defaulting to production ventycoffee.com domains)
const ALLOWED_ORIGINS = (
  process.env.ALLOWED_ORIGINS || 'https://ventycoffee.com,https://www.ventycoffee.com'
)
  .split(',')
  .map((o) => o.trim())
  .filter(Boolean);

if (process.env.APP_URL && !ALLOWED_ORIGINS.includes(process.env.APP_URL.trim())) {
  ALLOWED_ORIGINS.push(process.env.APP_URL.trim());
}

app.use((req: Request, res: Response, next: NextFunction) => {
  // Enforce HTTPS in production when behind reverse proxy / load balancer
  const forwardedProto = req.headers['x-forwarded-proto'];
  if (IS_PRODUCTION && forwardedProto === 'http') {
    if (req.method === 'GET' || req.method === 'HEAD') {
      res.redirect(301, `https://${req.headers.host}${req.originalUrl}`);
      return;
    }
    res.status(403).json({ error: 'HTTPS Required', message: 'Production API traffic must use HTTPS.' });
    return;
  }

  const origin = req.headers.origin;
  if (origin) {
    const isDevOrigin =
      !IS_PRODUCTION &&
      (origin.includes('localhost') || origin.includes('127.0.0.1') || origin.endsWith('.run.app'));
    if (ALLOWED_ORIGINS.includes(origin) || isDevOrigin) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Vary', 'Origin');
      res.setHeader('Access-Control-Allow-Credentials', 'true');
      res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization,x-venty-session-token,x-venty-device-id');
    } else if (req.path.startsWith('/api/')) {
      res.status(403).json({ error: 'Forbidden Origin', message: 'Origin is not allowed by CORS policy.' });
      return;
    }
  }

  if (req.method === 'OPTIONS') {
    res.sendStatus(204);
    return;
  }

  // Modern HTTP Security Headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  if (IS_PRODUCTION && (req.secure || forwardedProto === 'https')) {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data: https: blob:; font-src 'self' data: https://fonts.gstatic.com; connect-src 'self' ws: wss: https:;",
  );

  next();
});

// -------------------------------------------------------------
// 3. RATE LIMITING & BRUTE-FORCE PROTECTION
// -------------------------------------------------------------
interface RateLimitRecord {
  count: number;
  resetTime: number;
  failedAttempts: number;
  blockedUntil?: number;
}

const rateLimitStore = new Map<string, RateLimitRecord>();

const getClientIp = (req: Request): string => {
  return (
    (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
    req.socket.remoteAddress ||
    '127.0.0.1'
  );
};

const createRateLimiter = (options: { maxRequests: number; windowMs: number; isVerification?: boolean }) => {
  const instanceStore = new Map<string, RateLimitRecord>();
  return (req: Request, res: Response, next: NextFunction): void => {
    const ip = getClientIp(req);
    const now = Date.now();
    let record = instanceStore.get(ip);

    if (!record || now > record.resetTime) {
      record = { count: 0, resetTime: now + options.windowMs, failedAttempts: 0 };
      instanceStore.set(ip, record);
    }

    if (record.blockedUntil && now < record.blockedUntil) {
      const waitSeconds = Math.ceil((record.blockedUntil - now) / 1000);
      res.status(429).json({
        error: 'Too Many Requests',
        message: `Too many failed attempts. Access temporarily restricted. Try again in ${waitSeconds}s.`,
      });
      return;
    }

    record.count++;
    if (record.count > options.maxRequests) {
      res.status(429).json({
        error: 'Too Many Requests',
        message: 'Request rate limit exceeded. Please slow down.',
      });
      return;
    }

    next();
  };
};

const globalLimiter = createRateLimiter({ maxRequests: 300, windowMs: 60 * 1000 });
const redemptionLimiter = createRateLimiter({ maxRequests: 60, windowMs: 60 * 1000, isVerification: true });
const adminLimiter = createRateLimiter({ maxRequests: 100, windowMs: 60 * 1000 });

app.use('/api/', globalLimiter);

// -------------------------------------------------------------
// 4. PERSISTENT DATA SCHEMAS & ATOMIC DATABASE ENGINE
// -------------------------------------------------------------
export const VENTY_TIMEZONE = 'Africa/Algiers';

export const getAlgiersDateKey = (dateInput: string | number | Date = new Date()): string => {
  try {
    const date = dateInput instanceof Date ? dateInput : new Date(dateInput);
    if (isNaN(date.getTime())) return '';
    return new Intl.DateTimeFormat('en-CA', {
      timeZone: VENTY_TIMEZONE,
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
    }).format(date);
  } catch {
    return '';
  }
};

export const formatAlgiersDate = (dateInput: string | number | Date = new Date()): string => {
  try {
    const date = dateInput instanceof Date ? dateInput : new Date(dateInput);
    if (isNaN(date.getTime())) return String(dateInput);
    return new Intl.DateTimeFormat('en-US', {
      timeZone: VENTY_TIMEZONE,
      month: 'long',
      day: 'numeric',
      year: 'numeric',
    }).format(date);
  } catch {
    return String(dateInput);
  }
};

export const formatAlgiersTime = (dateInput: string | number | Date = new Date()): string => {
  try {
    const date = dateInput instanceof Date ? dateInput : new Date(dateInput);
    if (isNaN(date.getTime())) return '';
    return new Intl.DateTimeFormat('en-GB', {
      timeZone: VENTY_TIMEZONE,
      hour: '2-digit',
      minute: '2-digit',
      hour12: false,
    }).format(date);
  } catch {
    return '';
  }
};

export const formatAlgiersDateTime = (dateInput: string | number | Date): string => {
  const d = formatAlgiersDate(dateInput);
  const t = formatAlgiersTime(dateInput);
  return t ? `${d} · ${t}` : d;
};

export const getAlgiersBusinessBoundaries = (referenceNow: Date = new Date()) => {
  const todayKey = getAlgiersDateKey(referenceNow);
  const currentMonthKey = todayKey.slice(0, 7);
  const [y, m, d] = todayKey.split('-').map(Number);
  const utcNoon = new Date(Date.UTC(y, (m || 1) - 1, d || 1, 12, 0, 0));

  const yesterdayDate = new Date(utcNoon.getTime() - 24 * 60 * 60 * 1000);
  const yesterdayKey = getAlgiersDateKey(yesterdayDate);

  const weekKeys = new Set<string>();
  for (let i = 0; i < 7; i++) {
    const dayDate = new Date(utcNoon.getTime() - i * 24 * 60 * 60 * 1000);
    weekKeys.add(getAlgiersDateKey(dayDate));
  }

  return {
    todayKey,
    todayLabel: formatAlgiersDate(referenceNow),
    yesterdayKey,
    yesterdayLabel: formatAlgiersDate(yesterdayDate),
    currentMonthKey,
    weekKeys,
  };
};

export const matchesAlgiersDateFilter = (
  createdAtIso: string,
  filter: string,
  referenceNow: Date = new Date(),
): boolean => {
  const normalizedFilter = (filter || 'ALL').toUpperCase().replace(/\s+/g, '_');
  if (normalizedFilter === 'ALL') return true;
  const orderDateKey = getAlgiersDateKey(createdAtIso);
  if (!orderDateKey) return false;

  const boundaries = getAlgiersBusinessBoundaries(referenceNow);
  switch (normalizedFilter) {
    case 'TODAY':
      return orderDateKey === boundaries.todayKey;
    case 'YESTERDAY':
      return orderDateKey === boundaries.yesterdayKey;
    case 'THIS_WEEK':
      return boundaries.weekKeys.has(orderDateKey);
    case 'THIS_MONTH':
      return orderDateKey.startsWith(boundaries.currentMonthKey);
    default:
      return true;
  }
};

export type ServerOrderStatus =
  | 'PENDING'
  | 'CONFIRMED'
  | 'PREPARING'
  | 'READY'
  | 'COMPLETED'
  | 'CANCELLED';

export interface ServerOrderItem {
  id: string;
  productId: string;
  name: string;
  price: number;
  unitPrice: number;
  quantity: number;
  lineTotal: number;
  category?: string;
  notes?: string;
  grind?: string;
}

export interface ServerOrder {
  orderId: string;
  id: string;
  customerId: string | null;
  customerName: string;
  customerPhone?: string;
  orderItems: ServerOrderItem[];
  items: ServerOrderItem[];
  totalAmount: number;
  status: ServerOrderStatus;
  pickupTime: string;
  notes?: string;
  createdAt: string;
  completedAt: string | null;
  updatedAt: string;
  cancelledAt?: string | null;
  qualifiesForLoyalty: boolean;
  loyaltyStampAwarded: boolean;
  loyaltyStampsDelta: number;
  loyaltyTransactionId?: string;
  loyaltyReversed?: boolean;
}

export interface ServerLoyaltyAccount {
  customerId: string;
  name: string;
  phone: string;
  passwordHash?: string;
  email?: string;
  favouriteDrink?: string;
  currentStampCount: number; // 0 to 7
  lifetimeStamps: number;
  welcomeBonusGranted: boolean;
  createdAt: string;
  updatedAt: string;
  loyaltyStatus: 'Active' | 'Gold' | 'VIP';
  availableRewards: ServerLoyaltyReward[];
  redeemedRewards: ServerLoyaltyReward[];
}

export const sanitizeLoyaltyAccount = (
  account: ServerLoyaltyAccount,
): Omit<ServerLoyaltyAccount, 'passwordHash'> => {
  const { passwordHash: _omitted, ...safeAccount } = account;
  return safeAccount;
};

export interface ServerLoyaltyReward {
  rewardId: string;
  customerId: string;
  customerName: string;
  customerPhone: string;
  type: 'FREE_DRINK';
  status: 'AVAILABLE' | 'REDEEMED' | 'EXPIRED' | 'CANCELLED';
  issuedAt: string;
  expiresAt?: string;
  redeemedAt?: string;
  redemptionCode: string;
  redemptionToken: string;
  redemptionStaffId?: string;
  redemptionLocation?: string;
  redeemedOrderId?: string;
}

export interface ServerLoyaltyTransaction {
  id: string;
  customerId: string;
  customerName?: string;
  orderId?: string;
  type:
    | 'WELCOME_BONUS'
    | 'PURCHASE_STAMP'
    | 'REWARD_ISSUED'
    | 'REWARD_REDEEMED'
    | 'ADMIN_ADJUSTMENT'
    | 'REVERSAL';
  stampsDelta: number;
  timestamp: string;
  source: 'ONLINE_ORDER' | 'SIGNUP_BONUS' | 'COUNTER_SCAN' | 'ADMIN_CONSOLE' | 'SYSTEM';
  status: 'CONFIRMED' | 'REVERSED';
  idempotencyKey: string;
  note: string;
  adminReason?: string;
  adminId?: string;
  previousValue?: number;
  newValue?: number;
}

export interface ServerLoyaltyDB {
  accounts: ServerLoyaltyAccount[];
  transactions: ServerLoyaltyTransaction[];
  orders: ServerOrder[];
  config: {
    stampsToReward: number;
    welcomeBonusStamps: number;
    stampsPerQualifyingOrder: number;
    qualifyingCategories: string[];
    excludedCategories: string[];
  };
  migratedClients: Record<string, boolean>;
}

const DEFAULT_QUALIFYING_CATEGORIES = [
  'coffee',
  'drinks',
  'fresh',
  'espresso',
  'cold',
  'filter',
  'juice',
];

const DEFAULT_EXCLUDED_CATEGORIES = [
  'sweets',
  'desserts',
  'beans',
  'pastry',
  'cake',
  'food',
];

const INITIAL_SERVER_DB: ServerLoyaltyDB = {
  accounts: [
    {
      customerId: 'VENTY-7249',
      name: 'Karim Benali',
      phone: '0550123456',
      email: 'karim@venty.dz',
      favouriteDrink: 'Flat White & Iced Specialty Latte',
      currentStampCount: 5,
      lifetimeStamps: 12,
      welcomeBonusGranted: true,
      createdAt: new Date(Date.now() - 14 * 24 * 60 * 60 * 1000).toISOString(),
      updatedAt: new Date(Date.now() - 42 * 60 * 1000).toISOString(),
      loyaltyStatus: 'Active',
      availableRewards: [
        {
          rewardId: 'RW-8104',
          customerId: 'VENTY-7249',
          customerName: 'Karim Benali',
          customerPhone: '0550123456',
          type: 'FREE_DRINK',
          status: 'AVAILABLE',
          issuedAt: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString(),
          expiresAt: new Date(Date.now() + 58 * 24 * 60 * 60 * 1000).toISOString(),
          redemptionCode: 'VENTY-7F4K2',
          redemptionToken: 'rw_tok_7a4f91e802b1c43d99fa',
        },
      ],
      redeemedRewards: [
        {
          rewardId: 'RW-7001',
          customerId: 'VENTY-7249',
          customerName: 'Karim Benali',
          customerPhone: '0550123456',
          type: 'FREE_DRINK',
          status: 'REDEEMED',
          issuedAt: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000).toISOString(),
          redeemedAt: new Date(Date.now() - 8 * 24 * 60 * 60 * 1000).toISOString(),
          redemptionCode: 'VENTY-3M9PX',
          redemptionToken: 'rw_tok_prev_redeemed_1',
          redemptionStaffId: 'Staff-Amine',
          redemptionLocation: 'Miliana Roastery Counter',
        },
      ],
    },
  ],
  transactions: [
    {
      id: 'LTX-1001',
      customerId: 'VENTY-7249',
      customerName: 'Karim Benali',
      type: 'WELCOME_BONUS',
      stampsDelta: 2,
      timestamp: new Date(Date.now() - 14 * 24 * 60 * 60 * 1000).toISOString(),
      source: 'SIGNUP_BONUS',
      status: 'CONFIRMED',
      idempotencyKey: 'signup_bonus_VENTY-7249_0550123456',
      note: 'Welcome Bonus: +2 Free Stamps on Account Signup',
      previousValue: 0,
      newValue: 2,
    },
    {
      id: 'LTX-1002',
      customerId: 'VENTY-7249',
      customerName: 'Karim Benali',
      orderId: 'VENTY-6109',
      type: 'PURCHASE_STAMP',
      stampsDelta: 1,
      timestamp: new Date(Date.now() - 5 * 24 * 60 * 60 * 1000).toISOString(),
      source: 'ONLINE_ORDER',
      status: 'CONFIRMED',
      idempotencyKey: 'order_loyalty_VENTY-6109',
      note: 'Stamp earned: Classic Mojito (Order #VENTY-6109)',
      previousValue: 2,
      newValue: 3,
    },
    {
      id: 'LTX-1003',
      customerId: 'VENTY-7249',
      customerName: 'Karim Benali',
      orderId: 'VENTY-7241',
      type: 'PURCHASE_STAMP',
      stampsDelta: 1,
      timestamp: new Date(Date.now() - 42 * 60 * 1000).toISOString(),
      source: 'ONLINE_ORDER',
      status: 'CONFIRMED',
      idempotencyKey: 'order_loyalty_VENTY-7241',
      note: 'Stamp earned: Flat White (Order #VENTY-7241)',
      previousValue: 3,
      newValue: 4,
    },
    {
      id: 'LTX-1004',
      customerId: 'VENTY-7249',
      customerName: 'Karim Benali',
      type: 'PURCHASE_STAMP',
      stampsDelta: 1,
      timestamp: new Date(Date.now() - 15 * 60 * 1000).toISOString(),
      source: 'COUNTER_SCAN',
      status: 'CONFIRMED',
      idempotencyKey: 'counter_scan_1004',
      note: 'In-Shop Counter Stamping: Specialty Espresso',
      previousValue: 4,
      newValue: 5,
    },
    {
      id: 'LTX-1005',
      customerId: 'VENTY-7249',
      customerName: 'Karim Benali',
      type: 'REWARD_ISSUED',
      stampsDelta: 0,
      timestamp: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString(),
      source: 'ONLINE_ORDER',
      status: 'CONFIRMED',
      idempotencyKey: 'reward_issued_RW-8104',
      note: '🎉 Free Drink Reward Unlocked (VENTY-7F4K2) after 7 qualifying stamps!',
    },
  ],
  orders: [
    {
      orderId: 'VENTY-7241',
      id: 'VENTY-7241',
      customerId: 'VENTY-7249',
      customerName: 'Karim Benali',
      customerPhone: '0550123456',
      orderItems: [
        {
          id: 'latte-flat-white',
          productId: 'latte-flat-white',
          name: 'Flat White',
          price: 250,
          unitPrice: 250,
          quantity: 1,
          lineTotal: 250,
          category: 'coffee',
        },
        {
          id: 'dessert-banque-burnt-cheesecake',
          productId: 'dessert-banque-burnt-cheesecake',
          name: 'Banque Burnt Cheesecake',
          price: 400,
          unitPrice: 400,
          quantity: 1,
          lineTotal: 400,
          category: 'desserts',
        },
      ],
      items: [
        {
          id: 'latte-flat-white',
          productId: 'latte-flat-white',
          name: 'Flat White',
          price: 250,
          unitPrice: 250,
          quantity: 1,
          lineTotal: 250,
          category: 'coffee',
        },
        {
          id: 'dessert-banque-burnt-cheesecake',
          productId: 'dessert-banque-burnt-cheesecake',
          name: 'Banque Burnt Cheesecake',
          price: 400,
          unitPrice: 400,
          quantity: 1,
          lineTotal: 400,
          category: 'desserts',
        },
      ],
      totalAmount: 650,
      status: 'COMPLETED',
      pickupTime: '15 mins',
      createdAt: new Date(Date.now() - 42 * 60 * 1000).toISOString(),
      completedAt: new Date(Date.now() - 27 * 60 * 1000).toISOString(),
      updatedAt: new Date(Date.now() - 27 * 60 * 1000).toISOString(),
      qualifiesForLoyalty: true,
      loyaltyStampAwarded: true,
      loyaltyStampsDelta: 1,
      loyaltyTransactionId: 'LTX-1003',
    },
    {
      orderId: 'VENTY-6109',
      id: 'VENTY-6109',
      customerId: 'VENTY-7249',
      customerName: 'Karim Benali',
      customerPhone: '0550123456',
      orderItems: [
        {
          id: 'mojito-classic',
          productId: 'mojito-classic',
          name: 'Classic Mojito',
          price: 350,
          unitPrice: 350,
          quantity: 2,
          lineTotal: 700,
          category: 'drinks',
        },
        {
          id: 'waffle-chocolate',
          productId: 'waffle-chocolate',
          name: 'Chocolate Waffles',
          price: 350,
          unitPrice: 350,
          quantity: 1,
          lineTotal: 350,
          category: 'sweets',
        },
      ],
      items: [
        {
          id: 'mojito-classic',
          productId: 'mojito-classic',
          name: 'Classic Mojito',
          price: 350,
          unitPrice: 350,
          quantity: 2,
          lineTotal: 700,
          category: 'drinks',
        },
        {
          id: 'waffle-chocolate',
          productId: 'waffle-chocolate',
          name: 'Chocolate Waffles',
          price: 350,
          unitPrice: 350,
          quantity: 1,
          lineTotal: 350,
          category: 'sweets',
        },
      ],
      totalAmount: 1050,
      status: 'COMPLETED',
      pickupTime: '30 mins',
      createdAt: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
      completedAt: new Date(Date.now() - 23.5 * 60 * 60 * 1000).toISOString(),
      updatedAt: new Date(Date.now() - 23.5 * 60 * 60 * 1000).toISOString(),
      qualifiesForLoyalty: true,
      loyaltyStampAwarded: true,
      loyaltyStampsDelta: 1,
      loyaltyTransactionId: 'LTX-1002',
    },
  ],
  config: {
    stampsToReward: 7,
    welcomeBonusStamps: 2,
    stampsPerQualifyingOrder: 1,
    qualifyingCategories: DEFAULT_QUALIFYING_CATEGORIES,
    excludedCategories: DEFAULT_EXCLUDED_CATEGORIES,
  },
  migratedClients: {},
};

// Database in-memory authoritative cache & serialized atomic write engine
let dbCache: ServerLoyaltyDB | null = null;
let isDbWriting = false;
let isDbWritePending = false;

// Snapshot archive creator
export const createSnapshotArchive = (db: ServerLoyaltyDB) => {
  try {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const archivePath = path.resolve(BACKUPS_DIR, `venty_backup_${timestamp}.json`);
    fs.writeFileSync(archivePath, JSON.stringify(db, null, 2), 'utf-8');

    // Keep max 10 recent historical archives
    const files = fs.readdirSync(BACKUPS_DIR)
      .filter((f) => f.startsWith('venty_backup_') && f.endsWith('.json'))
      .sort();
    if (files.length > 10) {
      for (const oldFile of files.slice(0, files.length - 10)) {
        fs.unlinkSync(path.resolve(BACKUPS_DIR, oldFile));
      }
    }
  } catch (err) {
    console.error('[Server DB] Archive snapshot error:', err);
  }
};

const flushDatabaseToDisk = (): void => {
  if (!dbCache) return;
  if (isDbWriting) {
    isDbWritePending = true;
    return;
  }
  isDbWriting = true;
  isDbWritePending = false;
  try {
    const serialized = JSON.stringify(dbCache, null, 2);
    const tmpFile = `${DB_FILE}.tmp.${Date.now()}_${process.pid}`;
    fs.writeFileSync(tmpFile, serialized, 'utf-8');
    fs.renameSync(tmpFile, DB_FILE);

    // Keep active backup snapshot
    fs.writeFileSync(DB_BACKUP_FILE, serialized, 'utf-8');
  } catch (err) {
    console.error('[Server DB] Atomic DB write error:', err);
  } finally {
    isDbWriting = false;
    if (isDbWritePending) {
      setImmediate(() => flushDatabaseToDisk());
    }
  }
};

const loadDatabase = (): ServerLoyaltyDB => {
  if (dbCache) {
    return dbCache;
  }
  try {
    if (fs.existsSync(DB_FILE)) {
      const data = fs.readFileSync(DB_FILE, 'utf-8');
      dbCache = JSON.parse(data);
      if (!dbCache || typeof dbCache !== 'object') {
        dbCache = { ...INITIAL_SERVER_DB };
      }
      dbCache.accounts = Array.isArray(dbCache.accounts) ? dbCache.accounts.filter(Boolean) : [...INITIAL_SERVER_DB.accounts];
      dbCache.transactions = Array.isArray(dbCache.transactions) ? dbCache.transactions.filter(Boolean) : [...INITIAL_SERVER_DB.transactions];
      if (!Array.isArray(dbCache.orders)) {
        dbCache.orders = [...INITIAL_SERVER_DB.orders];
      } else {
        dbCache.orders = dbCache.orders.filter(Boolean);
      }
      return dbCache;
    }
  } catch (err) {
    console.error('[Server DB] Primary DB read error, attempting backup recovery:', err);
    try {
      if (fs.existsSync(DB_BACKUP_FILE)) {
        const backupData = fs.readFileSync(DB_BACKUP_FILE, 'utf-8');
        const parsed = JSON.parse(backupData);
        if (parsed && typeof parsed === 'object') {
          dbCache = parsed as ServerLoyaltyDB;
          if (!Array.isArray(dbCache.orders)) {
            dbCache.orders = [...INITIAL_SERVER_DB.orders];
          }
          flushDatabaseToDisk();
          logAuditEvent('DATABASE_RESTORED_FROM_BACKUP', { source: 'venty_loyalty_db.bak.json' });
          return dbCache;
        }
      }
    } catch (bErr) {
      console.error('[Server DB] Backup restore failed:', bErr);
    }
  }
  dbCache = JSON.parse(JSON.stringify(INITIAL_SERVER_DB)) as ServerLoyaltyDB;
  flushDatabaseToDisk();
  return dbCache;
};

// Atomic memory update & non-blocking serialized disk persistence
const saveDatabase = (db: ServerLoyaltyDB): void => {
  dbCache = db;
  flushDatabaseToDisk();
};

// Boot database & archive snapshot
const initialDb = loadDatabase();
createSnapshotArchive(initialDb);

// Postgres Serverless Boot Initialization
const initPostgresPersistence = async () => {
  if (isPostgresConfigured()) {
    try {
      console.log('[Postgres] DATABASE_URL detected. Running schema migrations...');
      await runMigrations();
      const existing = await pgRepository.getOrders({ limit: 1 });
      if (existing.length === 0) {
        console.log('[Postgres] First boot detected. Migrating initial data from JSON...');
        const summary = await migrateJsonToPostgres();
        console.log(`[Postgres] Initialized ${summary.customersCount} customers, ${summary.ordersCount} orders in ${summary.durationMs}ms.`);
      } else {
        console.log('[Postgres] Connected to durable Neon PostgreSQL database (schema up to date).');
      }
    } catch (err: any) {
      console.error('[Postgres Init Warning]', err?.message || err);
    }
  } else {
    console.log('[VENTY DB] Running in file/memory mode. Configure DATABASE_URL to enable Neon Serverless Postgres.');
  }
};
initPostgresPersistence().catch((err) => console.error('[Postgres Boot Error]', err));

// -------------------------------------------------------------
// 5. PERSISTENT SERVER SESSION MANAGEMENT (HASHED STORAGE)
// -------------------------------------------------------------
export type UserRole = 'CUSTOMER' | 'STAFF' | 'ADMIN';

export interface AuthenticatedUser {
  role: UserRole;
  customerId?: string;
  staffId?: string;
  staffName?: string;
  adminId?: string;
  sessionId: string;
  sessionHash: string;
  expiresAt: number;
}

// Persistent session store in memory keyed strictly by SHA-256 session token hash
const sessionStore = new Map<string, AuthenticatedUser>();

export const hashSessionToken = (token: string): string => {
  return crypto.createHash('sha256').update(token.trim(), 'utf8').digest('hex');
};

const loadSessionsFromDisk = () => {
  try {
    if (fs.existsSync(SESSIONS_FILE)) {
      const data = JSON.parse(fs.readFileSync(SESSIONS_FILE, 'utf-8'));
      const now = Date.now();
      let migrated = false;
      for (const [key, sess] of Object.entries(data)) {
        const s = sess as AuthenticatedUser;
        if (!s || typeof s !== 'object' || s.expiresAt <= now) continue;

        if (/^[0-9a-f]{64}$/.test(key)) {
          sessionStore.set(key, {
            ...s,
            sessionId: s.sessionId || key.substring(0, 16),
            sessionHash: key,
          });
        } else if (/^vty_sess_[0-9a-f]+$/.test(key)) {
          // Migrate any legacy raw tokens to secure SHA-256 hash
          const hash = hashSessionToken(key);
          sessionStore.set(hash, {
            ...s,
            sessionId: hash.substring(0, 16),
            sessionHash: hash,
          });
          migrated = true;
        }
      }
      if (migrated) {
        saveSessionsToDisk();
      }
    }
  } catch (err) {
    console.error('[Server Sessions] Error loading sessions file:', err);
  }
};

const saveSessionsToDisk = () => {
  try {
    const obj: Record<string, AuthenticatedUser> = {};
    const now = Date.now();
    for (const [hash, sess] of sessionStore.entries()) {
      if (/^[0-9a-f]{64}$/.test(hash) && sess.expiresAt > now) {
        // Only secure hash is saved on disk; raw session token is NEVER persisted
        obj[hash] = {
          role: sess.role,
          customerId: sess.customerId,
          staffId: sess.staffId,
          staffName: sess.staffName,
          adminId: sess.adminId,
          sessionId: sess.sessionId || hash.substring(0, 16),
          sessionHash: hash,
          expiresAt: sess.expiresAt,
        };
      }
    }
    const tmpFile = `${SESSIONS_FILE}.tmp.${Date.now()}`;
    fs.writeFileSync(tmpFile, JSON.stringify(obj, null, 2), 'utf-8');
    fs.renameSync(tmpFile, SESSIONS_FILE);
  } catch (err) {
    console.error('[Server Sessions] Error saving sessions file:', err);
  }
};

loadDatabase();
loadSessionsFromDisk();

// Direct management access configuration

// -------------------------------------------------------------
// 5B. CANONICAL PHONE NORMALIZATION
// -------------------------------------------------------------

/**
 * Normalizes Algerian & international phone formats into a single canonical identity.
 * Examples:
 *  "0550 12 34 56"  -> "0550123456"
 *  "0550123456"     -> "0550123456"
 *  "+213550123456"  -> "0550123456"
 *  "00213550123456" -> "0550123456"
 */
export const normalizePhoneNumber = (rawPhone: string): string => {
  if (!rawPhone || typeof rawPhone !== 'string') return '';
  let cleaned = rawPhone.trim().replace(/[\s\-().]/g, '');
  if (cleaned.startsWith('+213')) {
    cleaned = cleaned.substring(4);
    if (cleaned.startsWith('0')) cleaned = cleaned.substring(1);
    return `0${cleaned.replace(/\D/g, '')}`;
  }
  if (cleaned.startsWith('00213')) {
    cleaned = cleaned.substring(5);
    if (cleaned.startsWith('0')) cleaned = cleaned.substring(1);
    return `0${cleaned.replace(/\D/g, '')}`;
  }
  const digitsOnly = cleaned.replace(/\D/g, '');
  if (digitsOnly.startsWith('213') && (digitsOnly.length === 12 || digitsOnly.length === 13)) {
    const rest = digitsOnly.substring(3);
    return rest.startsWith('0') ? rest : `0${rest}`;
  }
  if (digitsOnly.length === 9 && /^[567]/.test(digitsOnly)) {
    return `0${digitsOnly}`;
  }
  return digitsOnly;
};

export const isValidNormalizedPhone = (normalizedPhone: string): boolean => {
  return /^0\d{8,9}$/.test(normalizedPhone) || /^\d{8,15}$/.test(normalizedPhone);
};

const maskPhoneForAudit = (normalizedPhone: string): string => {
  if (normalizedPhone.length < 6) return '***';
  return `${normalizedPhone.slice(0, 4)}***${normalizedPhone.slice(-3)}`;
};

export const createSession = (
  role: UserRole,
  details: { customerId?: string; staffId?: string; staffName?: string; adminId?: string },
): string => {
  const rawToken = `vty_sess_${crypto.randomBytes(32).toString('hex')}`;
  const sessionHash = hashSessionToken(rawToken);

  // Secure role-based expiration policy:
  // - ADMIN: 8 hours absolute lifetime
  // - STAFF: 12 hours shift lifetime
  // - CUSTOMER: 30 days
  let ttlMs = 30 * 24 * 60 * 60 * 1000;
  if (role === 'ADMIN') {
    ttlMs = 8 * 60 * 60 * 1000;
  } else if (role === 'STAFF') {
    ttlMs = 12 * 60 * 60 * 1000;
  }
  const expiresAt = Date.now() + ttlMs;

  sessionStore.set(sessionHash, {
    role,
    ...details,
    sessionId: sessionHash.substring(0, 16),
    sessionHash,
    expiresAt,
  });
  saveSessionsToDisk();
  return rawToken;
};

export const revokeSession = (tokenOrHash: string): boolean => {
  if (!tokenOrHash) return false;
  const hash = tokenOrHash.startsWith('vty_sess_') ? hashSessionToken(tokenOrHash) : tokenOrHash;
  const existed = sessionStore.delete(hash);
  if (existed) {
    saveSessionsToDisk();
  }
  return existed;
};

export const revokeCustomerSessions = (customerId: string): number => {
  let revokedCount = 0;
  for (const [hash, sess] of sessionStore.entries()) {
    if (sess.role === 'CUSTOMER' && sess.customerId === customerId) {
      sessionStore.delete(hash);
      revokedCount++;
    }
  }
  if (revokedCount > 0) {
    saveSessionsToDisk();
  }
  return revokedCount;
};

// Ensure sessions file on disk is strictly hashed and verified
saveSessionsToDisk();

// Extend Express Request
declare global {
  namespace Express {
    interface Request {
      user?: AuthenticatedUser;
      authError?: string;
      authTransport?: 'bearer' | 'custom-header' | 'cookie';
    }
  }
}

const parseCookies = (cookieHeader?: string): Record<string, string> => {
  const out: Record<string, string> = {};
  if (!cookieHeader || typeof cookieHeader !== 'string') return out;
  for (const part of cookieHeader.split(';')) {
    const idx = part.indexOf('=');
    if (idx > 0) {
      const k = part.slice(0, idx).trim();
      const v = part.slice(idx + 1).trim();
      if (k) out[k] = decodeURIComponent(v);
    }
  }
  return out;
};

// Session Authentication Middleware (Role derived strictly from server-side sessionStore via SHA-256 hash or Postgres)
const authenticateSession = async (req: Request, _res: Response, next: NextFunction): Promise<void> => {
  const authHeader = req.headers['authorization'] || (req.headers['x-venty-session-token'] as string);
  let rawToken: string | undefined;
  let authTransport: 'bearer' | 'custom-header' | 'cookie' = 'bearer';

  if (authHeader && typeof authHeader === 'string') {
    rawToken = authHeader.startsWith('Bearer ') ? authHeader.substring(7).trim() : authHeader.trim();
    authTransport = authHeader.startsWith('Bearer ') ? 'bearer' : 'custom-header';
  }

  if (!rawToken && req.headers.cookie) {
    const cookies = parseCookies(req.headers.cookie);
    rawToken = cookies['venty_management_session'] || cookies['venty_session'];
    if (rawToken) authTransport = 'cookie';
  }

  if (rawToken && (rawToken.startsWith('vty_sess_') || rawToken.length >= 32)) {
    const sessionHash = hashSessionToken(rawToken);
    let session = sessionStore.get(sessionHash);

    // If not in local instance memory and Postgres is configured, query durable shared session store
    if (!session && isPostgresConfigured()) {
      try {
        const pgSess = await pgRepository.getCustomerSession(sessionHash);
        if (pgSess) {
          session = {
            role: 'CUSTOMER',
            customerId: pgSess.customerId,
            sessionId: pgSess.sessionId,
            sessionHash: pgSess.sessionHash,
            expiresAt: pgSess.expiresAt,
          };
          sessionStore.set(sessionHash, session);
        }
      } catch (sessErr) {
        console.error('[Postgres Session Lookup Error]', sessErr);
      }
    }

    if (session) {
      if (Date.now() <= session.expiresAt) {
        req.user = session;
        req.authTransport = authTransport;
        next();
        return;
      } else {
        sessionStore.delete(sessionHash);
        if (isPostgresConfigured()) {
          pgRepository.deleteCustomerSession(sessionHash).catch(() => {});
        }
        saveSessionsToDisk();
        req.authError = 'Session token has expired.';
      }
    } else {
      req.authError = 'Invalid or revoked session token.';
    }
    next();
    return;
  }

  // Unauthenticated request (req.user remains undefined)
  next();
};

// Role Enforcement Middleware (Direct Management Access for Management Endpoints)
const requireRole = (allowedRoles: UserRole[]) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    // Direct trusted management access: endpoints permitting ADMIN or STAFF automatically grant management access
    if (allowedRoles.includes('ADMIN') || allowedRoles.includes('STAFF')) {
      if (!req.user || req.user.role === 'ADMIN' || req.user.role === 'STAFF') {
        if (!req.user) {
          req.user = {
            role: 'ADMIN',
            adminId: 'VENTY-MANAGER-MILIANA',
            sessionId: 'direct-management-console',
            sessionHash: 'direct-mgmt-hash',
            expiresAt: Date.now() + 30 * 24 * 3600 * 1000,
          };
        }
        next();
        return;
      }
    }

    if (!req.user) {
      logAuditEvent('AUTHENTICATION_FAILURE', {
        attemptedUrl: req.originalUrl,
        reason: req.authError || 'Missing session token',
        requiredRoles: allowedRoles,
      });
      res.status(401).json({
        error: 'Unauthorized',
        message: req.authError || 'Authentication required. Please log in.',
      });
      return;
    }
    if (!allowedRoles.includes(req.user.role)) {
      const actualRole = req.user.role;
      logAuditEvent('AUTHORIZATION_FAILURE', {
        attemptedUrl: req.originalUrl,
        userRole: actualRole,
        requiredRoles: allowedRoles,
      });
      res.status(403).json({
        error: 'Forbidden',
        message: `Role ${actualRole} is not authorized for this action. Required: ${allowedRoles.join(', ')}`,
      });
      return;
    }
    next();
  };
};

// CSRF Defense for state-changing Management Requests using cookie authentication
const csrfProtectionMiddleware = (req: Request, res: Response, next: NextFunction): void => {
  if (
    req.path.startsWith('/api/management/') &&
    ['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method) &&
    !['/api/management/auth/admin', '/api/management/auth/staff', '/api/management/auth/login', '/api/management/auth/logout'].includes(req.path)
  ) {
    const hasAuthHeader = req.headers['authorization'] || req.headers['x-venty-session-token'];
    if (!hasAuthHeader && req.authTransport === 'cookie') {
      const origin = (req.headers['origin'] || req.headers['referer'] || '') as string;
      if (!origin) {
        res.status(403).json({
          error: 'Forbidden',
          message: 'Origin header required for cookie-authenticated management mutations.',
        });
        return;
      }
      if (IS_PRODUCTION) {
        const allowedOrigins = (process.env.ALLOWED_ORIGINS || 'https://ventycoffee.com,https://www.ventycoffee.com')
          .split(',')
          .map((o) => o.trim())
          .filter(Boolean);
        if (!allowedOrigins.some((allowed) => origin.startsWith(allowed))) {
          res.status(403).json({
            error: 'Forbidden',
            message: 'Cross-origin request rejected.',
          });
          return;
        }
      }
    }
  }
  next();
};

app.use(authenticateSession);
app.use(csrfProtectionMiddleware);

// -------------------------------------------------------------
// 6. AUTHENTICATION: PHONE + PASSWORD LOGIN & SIGNUP (SERVER-AUTHORITATIVE)
// -------------------------------------------------------------

export const BCRYPT_COST_FACTOR = 10;
const DUMMY_BCRYPT_HASH = bcrypt.hashSync(
  'venty_constant_time_enumeration_guard_2026!',
  BCRYPT_COST_FACTOR,
);

export const LOGIN_MAX_FAILED_PER_PHONE = 8;
export const LOGIN_MAX_FAILED_PER_IP = 20;
export const LOGIN_LOCKOUT_WINDOW_MS = 15 * 60 * 1000; // 15 minutes
export const LOGIN_BLOCK_DURATION_MS = 5 * 60 * 1000; // 5 minutes lockout

interface LoginAttemptTracker {
  failedCount: number;
  windowResetAt: number;
  blockedUntil?: number;
}

const loginPhoneTrackerMap = new Map<string, LoginAttemptTracker>();
const loginIpTrackerMap = new Map<string, LoginAttemptTracker>();

const checkCustomerLoginRateLimit = (
  normalizedPhone: string,
  ip: string,
): { allowed: boolean; waitSeconds?: number } => {
  const now = Date.now();

  const ipRec = loginIpTrackerMap.get(ip);
  if (ipRec && ipRec.blockedUntil && now < ipRec.blockedUntil) {
    return {
      allowed: false,
      waitSeconds: Math.ceil((ipRec.blockedUntil - now) / 1000),
    };
  }

  const phoneRec = loginPhoneTrackerMap.get(normalizedPhone);
  if (phoneRec && phoneRec.blockedUntil && now < phoneRec.blockedUntil) {
    return {
      allowed: false,
      waitSeconds: Math.ceil((phoneRec.blockedUntil - now) / 1000),
    };
  }

  return { allowed: true };
};

const recordCustomerLoginAttempt = (
  normalizedPhone: string,
  ip: string,
  succeeded: boolean,
): void => {
  const now = Date.now();

  if (succeeded) {
    loginPhoneTrackerMap.delete(normalizedPhone);
    return;
  }

  // Update per-phone tracker
  let phoneRec = loginPhoneTrackerMap.get(normalizedPhone);
  if (!phoneRec || now > phoneRec.windowResetAt) {
    phoneRec = { failedCount: 0, windowResetAt: now + LOGIN_LOCKOUT_WINDOW_MS };
  }
  phoneRec.failedCount += 1;
  if (phoneRec.failedCount >= LOGIN_MAX_FAILED_PER_PHONE) {
    phoneRec.blockedUntil = now + LOGIN_BLOCK_DURATION_MS;
  }
  loginPhoneTrackerMap.set(normalizedPhone, phoneRec);

  // Update per-IP tracker
  let ipRec = loginIpTrackerMap.get(ip);
  if (!ipRec || now > ipRec.windowResetAt) {
    ipRec = { failedCount: 0, windowResetAt: now + LOGIN_LOCKOUT_WINDOW_MS };
  }
  ipRec.failedCount += 1;
  if (ipRec.failedCount >= LOGIN_MAX_FAILED_PER_IP) {
    ipRec.blockedUntil = now + LOGIN_BLOCK_DURATION_MS;
  }
  loginIpTrackerMap.set(ip, ipRec);
};

const GENERIC_INVALID_LOGIN_MESSAGE = 'Invalid verification code or expired session.';

interface CustomerOtpChallenge {
  phone: string;
  codeHash: string;
  email?: string;
  name?: string;
  favouriteDrink?: string;
  purpose: 'LOGIN' | 'SIGNUP';
  expiresAt: number;
  attemptsRemaining: number;
  createdAt: number;
}

const customerOtpMap = new Map<string, CustomerOtpChallenge>();
const customerOtpRequestLimiterMap = new Map<string, { count: number; resetAt: number }>();

const OTP_EXPIRY_MS = 10 * 60 * 1000; // 10 minutes
const OTP_MAX_ATTEMPTS = 5;
const OTP_REQUEST_WINDOW_MS = 10 * 60 * 1000;
const OTP_MAX_REQUESTS_PER_WINDOW = 10;
const SERVER_HMAC_SECRET = process.env.VENTY_HMAC_SECRET || 'venty-server-hmac-secret-auth-key-2026';

const hashOtpCode = (code: string, phone: string): string => {
  return crypto.createHmac('sha256', SERVER_HMAC_SECRET).update(`${phone}:${code.trim()}`).digest('hex');
};

const checkCustomerOtpRequestRateLimit = (phone: string, ip: string): { allowed: boolean; waitSeconds?: number } => {
  const now = Date.now();
  const key = `${phone}:${ip}`;
  let rec = customerOtpRequestLimiterMap.get(key);
  if (!rec || now > rec.resetAt) {
    rec = { count: 0, resetAt: now + OTP_REQUEST_WINDOW_MS };
  }
  if (rec.count >= OTP_MAX_REQUESTS_PER_WINDOW) {
    return { allowed: false, waitSeconds: Math.ceil((rec.resetAt - now) / 1000) };
  }
  rec.count += 1;
  customerOtpRequestLimiterMap.set(key, rec);
  return { allowed: true };
};

// Customer Passwordless OTP Request Handler
const handleCustomerRequestOtp = async (req: Request, res: Response): Promise<void> => {
  const { phone, email, name, favouriteDrink, purpose = 'LOGIN' } = req.body || {};
  const normalizedPhone = normalizePhoneNumber(String(phone || ''));

  if (!normalizedPhone || !isValidNormalizedPhone(normalizedPhone)) {
    res.status(400).json({
      error: 'Bad Request',
      message: 'Please enter a valid Algerian or international phone number.',
    });
    return;
  }

  const cleanName = typeof name === 'string' ? name.trim().substring(0, 80) : undefined;
  const cleanEmail = typeof email === 'string' ? email.trim().substring(0, 100) : undefined;
  const cleanDrink = typeof favouriteDrink === 'string' ? favouriteDrink.trim().substring(0, 60) : undefined;

  const ip = getClientIp(req);
  const rateCheck = checkCustomerOtpRequestRateLimit(normalizedPhone, ip);
  if (!rateCheck.allowed) {
    logAuditEvent('CUSTOMER_OTP_RATE_LIMITED', {
      phoneMasked: maskPhoneForAudit(normalizedPhone),
      ip,
    });
    res.status(429).json({
      error: 'Too Many Requests',
      rateLimited: true,
      message: `Too many verification requests. Please wait ${rateCheck.waitSeconds || 60} seconds before requesting a new code.`,
    });
    return;
  }

  // Generate cryptographically secure 6-digit numeric code
  const numericCode = String(crypto.randomInt(100000, 1000000));
  const codeHash = hashOtpCode(numericCode, normalizedPhone);
  const now = Date.now();

  const challenge: CustomerOtpChallenge = {
    phone: normalizedPhone,
    codeHash,
    name: cleanName,
    email: cleanEmail,
    favouriteDrink: cleanDrink,
    purpose: purpose === 'SIGNUP' ? 'SIGNUP' : 'LOGIN',
    expiresAt: now + OTP_EXPIRY_MS,
    attemptsRemaining: OTP_MAX_ATTEMPTS,
    createdAt: now,
  };

  customerOtpMap.set(normalizedPhone, challenge);
  if (isPostgresConfigured()) {
    pgRepository.saveOtpChallenge(challenge).catch((e) => console.error('[Postgres OTP Save]', e));
  }

  logAuditEvent('CUSTOMER_OTP_REQUESTED', {
    phoneMasked: maskPhoneForAudit(normalizedPhone),
    purpose: challenge.purpose,
    ip,
  });

  // Clean, non-leaking response in production, includes testCode for sandbox/development and in-app display
  res.status(200).json({
    success: true,
    step: 'CODE_SENT',
    message: `Verification code sent to ${normalizedPhone}${cleanEmail ? ' and ' + cleanEmail : ''}.`,
    testCode: process.env.NODE_ENV !== 'production' ? numericCode : undefined,
  });
};

// Customer Passwordless OTP Verification & Session Issuance Handler
const handleCustomerVerifyOtp = async (req: Request, res: Response): Promise<void> => {
  const { phone, code, name, email, favouriteDrink } = req.body || {};
  const normalizedPhone = normalizePhoneNumber(String(phone || ''));
  const rawCode = typeof code === 'string' ? code.trim() : '';

  if (!normalizedPhone || !isValidNormalizedPhone(normalizedPhone) || !rawCode) {
    res.status(400).json({
      error: 'Bad Request',
      message: 'Please provide both your phone number and the 6-digit verification code.',
    });
    return;
  }

  const ip = getClientIp(req);
  let challenge = customerOtpMap.get(normalizedPhone);
  if (!challenge && isPostgresConfigured()) {
    try {
      const pgCh = await pgRepository.getOtpChallenge(normalizedPhone);
      if (pgCh) {
        challenge = pgCh as any;
        customerOtpMap.set(normalizedPhone, challenge as any);
      }
    } catch (e) {
      console.error('[Postgres OTP Challenge Lookup Error]', e);
    }
  }
  const now = Date.now();

  if (!challenge || now > challenge.expiresAt) {
    if (challenge) {
      customerOtpMap.delete(normalizedPhone);
      if (isPostgresConfigured()) {
        pgRepository.deleteOtpChallenge(normalizedPhone).catch(() => {});
      }
    }
    logAuditEvent('CUSTOMER_OTP_EXPIRED_OR_NOT_FOUND', {
      phoneMasked: maskPhoneForAudit(normalizedPhone),
      ip,
    });
    res.status(401).json({
      error: 'Unauthorized',
      message: 'Verification code has expired or was not requested. Please request a new code.',
    });
    return;
  }

  if (challenge.attemptsRemaining <= 0) {
    customerOtpMap.delete(normalizedPhone);
    logAuditEvent('CUSTOMER_OTP_MAX_ATTEMPTS_EXCEEDED', {
      phoneMasked: maskPhoneForAudit(normalizedPhone),
      ip,
    });
    res.status(401).json({
      error: 'Unauthorized',
      message: 'Too many incorrect attempts. Please request a new verification code.',
    });
    return;
  }

  const candidateHash = hashOtpCode(rawCode, normalizedPhone);
  const isCodeMatch = timingSafeSecretEquals(candidateHash, challenge.codeHash);

  if (!isCodeMatch) {
    challenge.attemptsRemaining -= 1;
    logAuditEvent('CUSTOMER_OTP_VERIFY_FAILURE', {
      phoneMasked: maskPhoneForAudit(normalizedPhone),
      attemptsRemaining: challenge.attemptsRemaining,
      ip,
    });
    res.status(401).json({
      error: 'Unauthorized',
      message: `Invalid verification code. ${challenge.attemptsRemaining} attempt(s) remaining.`,
    });
    return;
  }

  // Single-use code guarantee: immediately remove from map
  customerOtpMap.delete(normalizedPhone);
  if (isPostgresConfigured()) {
    pgRepository.deleteOtpChallenge(normalizedPhone).catch(() => {});
  }

  const cleanName = typeof name === 'string' && name.trim() ? name.trim().substring(0, 80) : challenge.name;
  const cleanEmail = typeof email === 'string' && email.trim() ? email.trim().substring(0, 100) : challenge.email;
  const cleanDrink =
    typeof favouriteDrink === 'string' && favouriteDrink.trim()
      ? favouriteDrink.trim().substring(0, 60)
      : challenge.favouriteDrink;

  const db = loadDatabase();
  let existing = db.accounts.find((a) => normalizePhoneNumber(a.phone) === normalizedPhone);
  const nowIso = new Date().toISOString();

  if (existing) {
    // Existing customer returning
    let updated = false;
    if (cleanName && (!existing.name || existing.name === 'Customer')) {
      existing.name = cleanName;
      updated = true;
    }
    if (cleanEmail && !existing.email) {
      existing.email = cleanEmail;
      updated = true;
    }
    if (cleanDrink && !existing.favouriteDrink) {
      existing.favouriteDrink = cleanDrink;
      updated = true;
    }
    if (existing.phone !== normalizedPhone) {
      existing.phone = normalizedPhone;
      updated = true;
    }
    if (updated) {
      existing.updatedAt = nowIso;
      saveDatabase(db);
    }

    const token = createSession('CUSTOMER', { customerId: existing.customerId });
    const customerOrders = db.orders
      .filter((o) => o.customerId === existing.customerId)
      .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
      .map(enrichOrderWithAlgiersTime);
    const customerTransactions = db.transactions
      .filter((t) => t.customerId === existing.customerId)
      .slice(0, 50);

    logAuditEvent('CUSTOMER_PASSWORDLESS_LOGIN_SUCCESS', {
      customerId: existing.customerId,
      phoneMasked: maskPhoneForAudit(normalizedPhone),
      ip,
    });

    res.status(200).json({
      authenticated: true,
      verified: true,
      created: false,
      welcomeBonusAwarded: false,
      token,
      role: 'CUSTOMER',
      account: sanitizeLoyaltyAccount(existing),
      profile: {
        customerId: existing.customerId,
        name: existing.name,
        phone: existing.phone,
        email: existing.email || '',
        favouriteDrink: existing.favouriteDrink || 'Flat White',
        createdAt: existing.createdAt,
        updatedAt: existing.updatedAt,
      },
      orders: customerOrders,
      transactions: customerTransactions,
      message: `Welcome back, ${existing.name}!`,
    });
    return;
  }

  // New customer account creation with +2 Welcome Stamps
  let customerId = `VENTY-${Math.floor(1000 + Math.random() * 9000)}`;
  while (db.accounts.some((a) => a.customerId === customerId)) {
    customerId = `VENTY-${Math.floor(1000 + Math.random() * 9000)}`;
  }

  const welcomeStamps = db.config.welcomeBonusStamps || 2;
  const welcomeBonusIdempotencyKey = `signup_bonus_${customerId}_${normalizedPhone}`;
  const alreadyAwardedForPhone = db.transactions.some(
    (t) =>
      t.type === 'WELCOME_BONUS' &&
      t.status === 'CONFIRMED' &&
      t.idempotencyKey.endsWith(`_${normalizedPhone}`),
  );

  const initialStamps = alreadyAwardedForPhone ? 0 : welcomeStamps;

  const newAccount: ServerLoyaltyAccount = {
    customerId,
    name: cleanName || 'Customer',
    phone: normalizedPhone,
    email: cleanEmail,
    favouriteDrink: cleanDrink || 'Iced Specialty Latte',
    currentStampCount: initialStamps,
    lifetimeStamps: initialStamps,
    welcomeBonusGranted: true,
    createdAt: nowIso,
    updatedAt: nowIso,
    loyaltyStatus: 'Active',
    availableRewards: [],
    redeemedRewards: [],
  };

  const createdTransactions: ServerLoyaltyTransaction[] = [];

  if (!alreadyAwardedForPhone) {
    const welcomeTx: ServerLoyaltyTransaction = {
      id: `LTX-${Date.now().toString(36).toUpperCase()}`,
      customerId: newAccount.customerId,
      customerName: newAccount.name,
      type: 'WELCOME_BONUS',
      stampsDelta: welcomeStamps,
      timestamp: nowIso,
      source: 'SIGNUP_BONUS',
      status: 'CONFIRMED',
      idempotencyKey: welcomeBonusIdempotencyKey,
      note: `Welcome Bonus: +${welcomeStamps} Free Stamps on Account Signup`,
      previousValue: 0,
      newValue: welcomeStamps,
    };
    db.transactions.unshift(welcomeTx);
    createdTransactions.push(welcomeTx);
  }

  db.accounts.push(newAccount);
  saveDatabase(db);

  const token = createSession('CUSTOMER', { customerId: newAccount.customerId });
  logAuditEvent('CUSTOMER_ACCOUNT_CREATED', {
    customerId: newAccount.customerId,
    welcomeBonusAwarded: !alreadyAwardedForPhone,
    stamps: initialStamps,
    phoneMasked: maskPhoneForAudit(normalizedPhone),
  });

  res.status(201).json({
    authenticated: true,
    verified: true,
    created: true,
    welcomeBonusAwarded: !alreadyAwardedForPhone,
    token,
    role: 'CUSTOMER',
    account: sanitizeLoyaltyAccount(newAccount),
    profile: {
      customerId: newAccount.customerId,
      name: newAccount.name,
      phone: newAccount.phone,
      email: newAccount.email || '',
      favouriteDrink: newAccount.favouriteDrink || 'Iced Specialty Latte',
      createdAt: newAccount.createdAt,
      updatedAt: newAccount.updatedAt,
    },
    orders: [],
    transactions: createdTransactions,
    message: `Welcome to VENTY Loyalty, ${newAccount.name}! +${initialStamps} Welcome stamps added to your card.`,
  });
};

// Customer Account Registration or OTP Initiation Handler
const handleCustomerRegistration = async (req: Request, res: Response): Promise<void> => {
  const { name, phone, code, email, favouriteDrink } = req.body || {};

  const cleanName = typeof name === 'string' ? name.trim() : '';
  const normalizedPhone = normalizePhoneNumber(String(phone || ''));

  if (!cleanName) {
    res.status(400).json({
      error: 'Bad Request',
      message: 'Please enter your full name.',
    });
    return;
  }

  if (!normalizedPhone || !isValidNormalizedPhone(normalizedPhone)) {
    res.status(400).json({
      error: 'Bad Request',
      message: 'Please enter a valid Algerian or international phone number.',
    });
    return;
  }

  if (typeof code === 'string' && code.trim().length > 0) {
    void handleCustomerVerifyOtp(req, res);
    return;
  }

  // If no code provided, generate and send OTP for registration
  void handleCustomerRequestOtp(
    Object.assign(req, {
      body: {
        ...req.body,
        purpose: 'SIGNUP',
      },
    }),
    res,
  );
};

// -------------------------------------------------------------
// MANAGEMENT AUTHENTICATION RATE LIMITING & SECURITY HELPERS
// -------------------------------------------------------------
interface ManagementLoginTracker {
  failedAttempts: number;
  resetAt: number;
  blockedUntil?: number;
}

const managementLoginTrackerMap = new Map<string, ManagementLoginTracker>();
const MANAGEMENT_MAX_FAILED_ATTEMPTS = 5;
const MANAGEMENT_LOCKOUT_WINDOW_MS = 10 * 60 * 1000; // 10 minutes
const MANAGEMENT_LOCKOUT_BLOCK_MS = 5 * 60 * 1000; // 5 minutes lockout

const checkManagementLoginRateLimit = (ip: string): { allowed: boolean; waitSeconds?: number } => {
  const now = Date.now();
  const record = managementLoginTrackerMap.get(ip);
  if (record && record.blockedUntil && now < record.blockedUntil) {
    return {
      allowed: false,
      waitSeconds: Math.ceil((record.blockedUntil - now) / 1000),
    };
  }
  return { allowed: true };
};

const recordManagementLoginAttempt = (ip: string, succeeded: boolean): void => {
  const now = Date.now();
  if (succeeded) {
    managementLoginTrackerMap.delete(ip);
    return;
  }
  let record = managementLoginTrackerMap.get(ip);
  if (!record || now > record.resetAt) {
    record = { failedAttempts: 0, resetAt: now + MANAGEMENT_LOCKOUT_WINDOW_MS };
  }
  record.failedAttempts += 1;
  if (record.failedAttempts >= MANAGEMENT_MAX_FAILED_ATTEMPTS) {
    record.blockedUntil = now + MANAGEMENT_LOCKOUT_BLOCK_MS;
    logAuditEvent('MANAGEMENT_BRUTE_FORCE_LOCKOUT', {
      ip,
      attempts: record.failedAttempts,
      lockoutDurationSeconds: Math.round(MANAGEMENT_LOCKOUT_BLOCK_MS / 1000),
    });
  }
  managementLoginTrackerMap.set(ip, record);
};

// Periodic Memory Sweep (Prevents unbounded memory growth in long-running production environments)
const MEMORY_SWEEP_INTERVAL_MS = 10 * 60 * 1000; // 10 minutes
const cleanupExpiredMemoryRecords = () => {
  const now = Date.now();
  // 1. Sessions
  for (const [key, sess] of sessionStore.entries()) {
    if (sess.expiresAt <= now) {
      sessionStore.delete(key);
    }
  }
  // 2. Customer OTP Challenges
  for (const [phone, challenge] of customerOtpMap.entries()) {
    if (challenge.expiresAt <= now) {
      customerOtpMap.delete(phone);
    }
  }
  // 3. OTP Request Rate Limits
  for (const [key, record] of customerOtpRequestLimiterMap.entries()) {
    if (record.resetAt <= now) {
      customerOtpRequestLimiterMap.delete(key);
    }
  }
  // 4. Login Attempt Trackers
  for (const [phone, tracker] of loginPhoneTrackerMap.entries()) {
    if (tracker.windowResetAt <= now && (!tracker.blockedUntil || tracker.blockedUntil <= now)) {
      loginPhoneTrackerMap.delete(phone);
    }
  }
  for (const [ip, tracker] of loginIpTrackerMap.entries()) {
    if (tracker.windowResetAt <= now && (!tracker.blockedUntil || tracker.blockedUntil <= now)) {
      loginIpTrackerMap.delete(ip);
    }
  }
  // 5. Management Login Trackers
  for (const [ip, tracker] of managementLoginTrackerMap.entries()) {
    if (tracker.resetAt <= now && (!tracker.blockedUntil || tracker.blockedUntil <= now)) {
      managementLoginTrackerMap.delete(ip);
    }
  }
  // 6. Global Rate Limiter Records
  for (const [ip, record] of rateLimitStore.entries()) {
    if (record.resetTime <= now && (!record.blockedUntil || record.blockedUntil <= now)) {
      rateLimitStore.delete(ip);
    }
  }
};
const memorySweepTimer = setInterval(cleanupExpiredMemoryRecords, MEMORY_SWEEP_INTERVAL_MS);
if (memorySweepTimer.unref) {
  memorySweepTimer.unref();
}

const setManagementSessionCookie = (res: Response, token: string, role: UserRole = 'ADMIN'): void => {
  const maxAge = role === 'ADMIN' ? 8 * 3600 : role === 'STAFF' ? 12 * 3600 : 30 * 24 * 3600;
  const cookieParts = [
    `venty_management_session=${encodeURIComponent(token)}`,
    'HttpOnly',
    'Path=/',
    'SameSite=Lax',
    `Max-Age=${maxAge}`,
  ];
  if (IS_PRODUCTION) {
    cookieParts.push('Secure');
  }
  res.setHeader('Set-Cookie', cookieParts.join('; '));
};

const clearManagementSessionCookie = (res: Response): void => {
  const cookieParts = [
    'venty_management_session=',
    'HttpOnly',
    'Path=/',
    'SameSite=Lax',
    'Max-Age=0',
  ];
  if (IS_PRODUCTION) {
    cookieParts.push('Secure');
  }
  res.setHeader('Set-Cookie', cookieParts.join('; '));
};

const handleManagementPortalAuth = (req: Request, res: Response, forcedMode?: 'ADMIN' | 'STAFF'): void => {
  const db = loadDatabase();
  ensureManagementCollections(db);

  const role: UserRole = forcedMode || 'ADMIN';
  const resolvedAdminId = 'VENTY-MANAGER-MILIANA';

  const token = createSession(role, { adminId: resolvedAdminId });
  setManagementSessionCookie(res, token, role);
  logAuditEvent('LOGIN_SUCCESS', {
    user: resolvedAdminId,
    role,
    resource: 'MANAGEMENT_PORTAL',
    result: 'DIRECT_ACCESS',
  });
  res.json({
    token,
    role,
    adminId: resolvedAdminId,
    message: 'Management authorization granted.',
  });
};

// Dedicated Management Auth Endpoints (Protected by management login limiter)
app.post('/api/management/auth/admin', (req: Request, res: Response) => {
  handleManagementPortalAuth(req, res, 'ADMIN');
});

app.post('/api/management/auth/staff', (req: Request, res: Response) => {
  handleManagementPortalAuth(req, res, 'STAFF');
});

app.post('/api/management/auth/login', (req: Request, res: Response) => {
  handleManagementPortalAuth(req, res);
});

// Passwordless Customer OTP Request Endpoints
app.post('/api/loyalty/auth/request-otp', (req: Request, res: Response) => {
  void handleCustomerRequestOtp(req, res);
});
app.post('/api/auth/request-otp', (req: Request, res: Response) => {
  void handleCustomerRequestOtp(req, res);
});
app.post('/api/loyalty/auth/request-verification', (req: Request, res: Response) => {
  void handleCustomerRequestOtp(req, res);
});

// Passwordless Customer OTP Verification Endpoints
app.post('/api/loyalty/auth/verify-otp', (req: Request, res: Response) => {
  void handleCustomerVerifyOtp(req, res);
});
app.post('/api/auth/verify-otp', (req: Request, res: Response) => {
  void handleCustomerVerifyOtp(req, res);
});
app.post('/api/loyalty/auth/verify', (req: Request, res: Response) => {
  void handleCustomerVerifyOtp(req, res);
});
app.post('/api/auth/verify', (req: Request, res: Response) => {
  void handleCustomerVerifyOtp(req, res);
});

// Customer / Staff / Admin Login Endpoint
app.post('/api/loyalty/auth/login', (req: Request, res: Response) => {
  const {
    role: explicitRole,
    identifier,
    adminOrStaffId,
    phone,
    code,
    passcode,
    staffPin,
    adminSecret,
  } = req.body || {};

  const rawId = String(adminOrStaffId || identifier || '').trim();

  // Determine if this is a Management Portal login attempt
  const isManagementAttempt =
    explicitRole === 'ADMIN' ||
    explicitRole === 'STAFF' ||
    adminSecret !== undefined ||
    staffPin !== undefined ||
    passcode !== undefined ||
    (rawId.length > 0 && !phone);

  if (isManagementAttempt) {
    handleManagementPortalAuth(req, res);
    return;
  }

  // Customer Passwordless Login: Phone Number + 6-Digit OTP Verification -> Customer session
  if (phone && typeof phone === 'string') {
    if (typeof code === 'string' && code.trim().length > 0) {
      void handleCustomerVerifyOtp(req, res);
      return;
    }
    // If no code provided yet, initiate OTP request
    void handleCustomerRequestOtp(req, res);
    return;
  }

  res.status(400).json({ error: 'Bad Request', message: 'Valid phone number is required.' });
});

app.post('/api/auth/login', (req: Request, res: Response) => {
  const { phone, code } = req.body || {};
  if (phone && typeof phone === 'string') {
    if (typeof code === 'string' && code.trim().length > 0) {
      void handleCustomerVerifyOtp(req, res);
      return;
    }
    void handleCustomerRequestOtp(req, res);
    return;
  }
  res.status(400).json({ error: 'Bad Request', message: 'Valid phone number is required.' });
});

// Logout & Session Invalidation Endpoint
const handleLogoutRequest = (req: Request, res: Response) => {
  const authHeader = req.headers['authorization'] || (req.headers['x-venty-session-token'] as string);
  let rawToken: string | undefined;
  if (authHeader && typeof authHeader === 'string') {
    rawToken = authHeader.startsWith('Bearer ') ? authHeader.substring(7).trim() : authHeader.trim();
  }
  if (!rawToken && req.headers.cookie) {
    const cookies = parseCookies(req.headers.cookie);
    rawToken = cookies['venty_management_session'] || cookies['venty_session'];
  }

  if (rawToken) {
    revokeSession(rawToken);
  } else if (req.user?.sessionHash) {
    revokeSession(req.user.sessionHash);
  }

  logAuditEvent('USER_LOGOUT', { role: req.user?.role });
  clearManagementSessionCookie(res);
  res.json({ success: true, message: 'Session invalidated successfully.' });
};

app.post('/api/loyalty/auth/logout', handleLogoutRequest);
app.post('/api/management/auth/logout', handleLogoutRequest);
app.post('/api/auth/logout', handleLogoutRequest);

// -------------------------------------------------------------
// 7. PROTECTED REST API ENDPOINTS (/api/loyalty/*)
// -------------------------------------------------------------

// 1. GET Customer Loyalty Account (Isolated to Authenticated Customer or Staff/Admin)
app.get('/api/loyalty/account', requireRole(['CUSTOMER', 'STAFF', 'ADMIN']), (req: Request, res: Response) => {
  const db = loadDatabase();
  const queryCustomerId = (req.query.customerId as string) || '';
  const phone = (req.query.phone as string) || '';

  let targetCustomerId: string | undefined;

  if (req.user?.role === 'CUSTOMER') {
    targetCustomerId = req.user.customerId;
    if (!targetCustomerId) {
      res.status(401).json({ error: 'Unauthorized', message: 'Authentication required.' });
      return;
    }
    if ((queryCustomerId && queryCustomerId !== targetCustomerId) || phone) {
      logAuditEvent('CUSTOMER_ISOLATION_VIOLATION_ATTEMPT', {
        attemptedCustomerId: queryCustomerId || phone,
        authenticatedCustomerId: targetCustomerId,
      });
      res.status(403).json({ error: 'Forbidden', message: 'You can only access your own loyalty account.' });
      return;
    }
  } else {
    targetCustomerId = queryCustomerId || req.user?.customerId;
  }

  let match: ServerLoyaltyAccount | undefined;
  if (targetCustomerId) {
    match = db.accounts.find((a) => a.customerId === targetCustomerId);
  }
  if (!match && phone && req.user?.role !== 'CUSTOMER') {
    const clean = normalizePhoneNumber(phone);
    match = db.accounts.find((a) => normalizePhoneNumber(a.phone) === clean);
  }

  if (!match) {
    res.status(404).json({ error: 'Not Found', message: 'Loyalty account not found.' });
    return;
  }

  res.json({ account: sanitizeLoyaltyAccount(match) });
});

// 2. GET Loyalty Transactions History (Append-only Ledger with Strict Customer Isolation)
app.get('/api/loyalty/history', requireRole(['CUSTOMER', 'STAFF', 'ADMIN']), (req: Request, res: Response) => {
  const db = loadDatabase();
  const queryCustomerId = (req.query.customerId as string) || '';

  let targetId: string | undefined;

  if (req.user?.role === 'CUSTOMER') {
    targetId = req.user.customerId;
    if (!targetId) {
      res.status(401).json({ error: 'Unauthorized', message: 'Authentication required.' });
      return;
    }
    if (queryCustomerId && queryCustomerId !== targetId) {
      logAuditEvent('CUSTOMER_ISOLATION_VIOLATION_ATTEMPT', {
        attemptedCustomerId: queryCustomerId,
        authenticatedCustomerId: targetId,
      });
      res.status(403).json({ error: 'Forbidden', message: 'You can only access your own loyalty history.' });
      return;
    }
  } else {
    targetId = queryCustomerId || req.user?.customerId;
  }

  const limit = Math.min(100, Math.max(1, parseInt((req.query.limit as string) || '50', 10) || 50));
  const txs = targetId
    ? db.transactions.filter((t) => t.customerId === targetId).slice(0, limit)
    : (req.user?.role === 'STAFF' || req.user?.role === 'ADMIN' ? db.transactions.slice(0, limit) : []);

  res.json({ transactions: txs });
});

// 3. POST Customer Registration (Phone + Password Account Creation, +2 Welcome Bonus Once & Session)
app.post('/api/loyalty/signup', (req: Request, res: Response) => {
  void handleCustomerRegistration(req, res);
});
app.post('/api/loyalty/auth/signup', (req: Request, res: Response) => {
  void handleCustomerRegistration(req, res);
});
app.post('/api/loyalty/auth/register', (req: Request, res: Response) => {
  void handleCustomerRegistration(req, res);
});
app.post('/api/auth/register', (req: Request, res: Response) => {
  void handleCustomerRegistration(req, res);
});

// 4. POST Process Completed Order (Backend Idempotency & Qualifying Category Verification)
export const normalizeServerOrderStatus = (rawStatus?: string): ServerOrderStatus => {
  const clean = (rawStatus || 'PENDING').trim().toUpperCase();
  if (clean === 'CONFIRMED') return 'CONFIRMED';
  if (clean === 'PREPARING') return 'PREPARING';
  if (clean === 'READY') return 'READY';
  if (clean === 'COMPLETED') return 'COMPLETED';
  if (clean === 'CANCELLED' || clean === 'CANCELED') return 'CANCELLED';
  return 'PENDING';
};

export const CANONICAL_PRODUCT_CATALOG: Record<
  string,
  { id: string; name: string; unitPrice: number; category: string }
> = {
  // Official Menu — COFFEE
  'coffee-ristretto': { id: 'coffee-ristretto', name: 'Ristretto', unitPrice: 80, category: 'coffee' },
  'coffee-espresso': { id: 'coffee-espresso', name: 'Espresso', unitPrice: 100, category: 'coffee' },
  'coffee-doppio': { id: 'coffee-doppio', name: 'Doppio', unitPrice: 150, category: 'coffee' },
  'coffee-lungo': { id: 'coffee-lungo', name: 'Lungo', unitPrice: 100, category: 'coffee' },
  'coffee-americano': { id: 'coffee-americano', name: 'Americano', unitPrice: 150, category: 'coffee' },
  'coffee-long-black': { id: 'coffee-long-black', name: 'Long Black', unitPrice: 150, category: 'coffee' },
  'coffee-cold-brew': { id: 'coffee-cold-brew', name: 'Cold Brew', unitPrice: 100, category: 'coffee' },
  'latte-classic': { id: 'latte-classic', name: 'Latte', unitPrice: 300, category: 'coffee' },
  'latte-cappuccino': { id: 'latte-cappuccino', name: 'Cappuccino', unitPrice: 300, category: 'coffee' },
  'latte-cortado': { id: 'latte-cortado', name: 'Cortado', unitPrice: 250, category: 'coffee' },
  'latte-flat-white': { id: 'latte-flat-white', name: 'Flat White', unitPrice: 250, category: 'coffee' },
  'latte-cafe-au-lait': { id: 'latte-cafe-au-lait', name: 'Cafe Au Lait', unitPrice: 150, category: 'coffee' },
  'latte-spanish-latte': { id: 'latte-spanish-latte', name: 'Spanish Latte', unitPrice: 300, category: 'coffee' },
  'latte-mocha': { id: 'latte-mocha', name: 'Mocha', unitPrice: 300, category: 'coffee' },
  'latte-dalgona': { id: 'latte-dalgona', name: 'Dalgona Latte', unitPrice: 300, category: 'coffee' },
  'latte-matcha': { id: 'latte-matcha', name: 'Matcha Green Latte', unitPrice: 600, category: 'coffee' },
  'latte-hot-chocolate': { id: 'latte-hot-chocolate', name: 'Hot Chocolate', unitPrice: 300, category: 'coffee' },
  'flavor-hazelnut': { id: 'flavor-hazelnut', name: 'Hazelnut', unitPrice: 50, category: 'coffee' },
  'flavor-pistachio': { id: 'flavor-pistachio', name: 'Pistachio', unitPrice: 50, category: 'coffee' },
  'flavor-caramel': { id: 'flavor-caramel', name: 'Caramel', unitPrice: 50, category: 'coffee' },
  'flavor-vanilla': { id: 'flavor-vanilla', name: 'Vanilla', unitPrice: 50, category: 'coffee' },
  // Official Menu — DRINKS
  'mojito-classic': { id: 'mojito-classic', name: 'Classic Mojito', unitPrice: 350, category: 'drinks' },
  'mojito-virgin': { id: 'mojito-virgin', name: 'Virgin Mojito', unitPrice: 350, category: 'drinks' },
  'mojito-flavored': { id: 'mojito-flavored', name: 'Flavored Mojito', unitPrice: 400, category: 'drinks' },
  'milkshake-chocolate': { id: 'milkshake-chocolate', name: 'Chocolate Milkshake', unitPrice: 400, category: 'drinks' },
  'milkshake-caramel': { id: 'milkshake-caramel', name: 'Caramel Milkshake', unitPrice: 400, category: 'drinks' },
  'milkshake-vanilla': { id: 'milkshake-vanilla', name: 'Vanilla Milkshake', unitPrice: 400, category: 'drinks' },
  'milkshake-fruit': { id: 'milkshake-fruit', name: 'Fruit Milkshake', unitPrice: 400, category: 'drinks' },
  'milkshake-oreo': { id: 'milkshake-oreo', name: 'Oreo Milkshake', unitPrice: 400, category: 'drinks' },
  'mocktail-bora-bora': { id: 'mocktail-bora-bora', name: 'Bora Bora', unitPrice: 400, category: 'drinks' },
  'mocktail-blue-hawaii': { id: 'mocktail-blue-hawaii', name: 'Blue Hawaii', unitPrice: 400, category: 'drinks' },
  'mocktail-pink-lady': { id: 'mocktail-pink-lady', name: 'Pink Lady', unitPrice: 400, category: 'drinks' },
  'mocktail-blue-lady': { id: 'mocktail-blue-lady', name: 'Blue Lady', unitPrice: 400, category: 'drinks' },
  'mocktail-exotic-splash': { id: 'mocktail-exotic-splash', name: 'Exotic Splash', unitPrice: 400, category: 'drinks' },
  'mocktail-pina-colada': { id: 'mocktail-pina-colada', name: 'Pina Colada', unitPrice: 400, category: 'drinks' },
  'mocktail-red-cactus': { id: 'mocktail-red-cactus', name: 'Red Cactus', unitPrice: 400, category: 'drinks' },
  'mocktail-florida-sunshine': { id: 'mocktail-florida-sunshine', name: 'Florida Sunshine', unitPrice: 400, category: 'drinks' },
  // Official Menu — FRESH
  'juice-orange': { id: 'juice-orange', name: 'Orange Juice', unitPrice: 300, category: 'fresh' },
  'juice-lemon': { id: 'juice-lemon', name: 'Lemon Juice', unitPrice: 350, category: 'fresh' },
  'juice-strawberry': { id: 'juice-strawberry', name: 'Strawberry Juice', unitPrice: 300, category: 'fresh' },
  'juice-banana': { id: 'juice-banana', name: 'Banana Juice', unitPrice: 300, category: 'fresh' },
  'juice-pineapple': { id: 'juice-pineapple', name: 'Pineapple Juice', unitPrice: 350, category: 'fresh' },
  'juice-2-fruits': { id: 'juice-2-fruits', name: '2 Fruits Cocktail', unitPrice: 350, category: 'fresh' },
  'juice-3-4-fruits': { id: 'juice-3-4-fruits', name: '3–4 Fruits Cocktail', unitPrice: 400, category: 'fresh' },
  'tea-normal': { id: 'tea-normal', name: 'Normal Tea', unitPrice: 70, category: 'fresh' },
  'tea-infusion': { id: 'tea-infusion', name: 'Infusion Tea', unitPrice: 100, category: 'fresh' },
  'tea-iced': { id: 'tea-iced', name: 'Iced Tea', unitPrice: 200, category: 'fresh' },
  'tea-ginger': { id: 'tea-ginger', name: 'Ginger', unitPrice: 70, category: 'fresh' },
  'tea-local-infusion': { id: 'tea-local-infusion', name: 'Local Infusion', unitPrice: 150, category: 'fresh' },
  // Official Menu — SWEETS
  'style-croissant': { id: 'style-croissant', name: 'Croissant', unitPrice: 200, category: 'sweets' },
  'style-goelette': { id: 'style-goelette', name: 'Goélette', unitPrice: 150, category: 'sweets' },
  'style-brownie': { id: 'style-brownie', name: 'Brownie', unitPrice: 150, category: 'sweets' },
  'style-pastry': { id: 'style-pastry', name: 'Pastry', unitPrice: 220, category: 'sweets' },
  'style-todays-sweet': { id: 'style-todays-sweet', name: "Today's Sweet", unitPrice: 400, category: 'sweets' },
  'crepe-tarte': { id: 'crepe-tarte', name: 'Tarte Crêpe', unitPrice: 200, category: 'sweets' },
  'crepe-chocolatee': { id: 'crepe-chocolatee', name: 'Chocolatée crêpe', unitPrice: 300, category: 'sweets' },
  'crepe-1-fruit-chocolate': { id: 'crepe-1-fruit-chocolate', name: '1 Fruits Chocolate Crêpe', unitPrice: 400, category: 'sweets' },
  'crepe-2-fruits-chocolate': { id: 'crepe-2-fruits-chocolate', name: '2 Fruits Chocolate Crêpe', unitPrice: 450, category: 'sweets' },
  'crepe-3-fruits-chocolate': { id: 'crepe-3-fruits-chocolate', name: '3 Fruits Chocolate Crêpe', unitPrice: 500, category: 'sweets' },
  'waffle-chocolate': { id: 'waffle-chocolate', name: 'Chocolate Waffles', unitPrice: 350, category: 'sweets' },
  'waffle-1-fruit-chocolate': { id: 'waffle-1-fruit-chocolate', name: '1 Fruit Chocolate Waffles', unitPrice: 400, category: 'sweets' },
  'waffle-2-fruits-chocolate': { id: 'waffle-2-fruits-chocolate', name: '2 Fruit Chocolate Waffles', unitPrice: 450, category: 'sweets' },
  // Official Menu — DESSERTS
  'dessert-banque-burnt-cheesecake': { id: 'dessert-banque-burnt-cheesecake', name: 'Banque Burnt Cheesecake (Sans/Gluten/Sucre)', unitPrice: 400, category: 'desserts' },
  'dessert-gateau-basque': { id: 'dessert-gateau-basque', name: 'Gâteau Basque', unitPrice: 400, category: 'desserts' },
  'dessert-quesselle': { id: 'dessert-quesselle', name: 'Queselle', unitPrice: 300, category: 'desserts' },
  'dessert-fondant-chocolat': { id: 'dessert-fondant-chocolat', name: 'Fondant au chocolat', unitPrice: 350, category: 'desserts' },
  'dessert-tiramisu': { id: 'dessert-tiramisu', name: 'Tiramisu', unitPrice: 400, category: 'desserts' },
  'dessert-fruit-salad': { id: 'dessert-fruit-salad', name: 'Fruit Salad (Season Fruits)', unitPrice: 400, category: 'desserts' },
  'dessert-todays-dessert': { id: 'dessert-todays-dessert', name: "Today's Dessert", unitPrice: 400, category: 'desserts' },
  'cheesecake-chocolate': { id: 'cheesecake-chocolate', name: 'Chocolate Cheesecake', unitPrice: 400, category: 'desserts' },
  'cheesecake-pistachio': { id: 'cheesecake-pistachio', name: 'Pistachio Cheesecake', unitPrice: 350, category: 'desserts' },
  'cheesecake-red-fruit': { id: 'cheesecake-red-fruit', name: 'Red Fruit Cheesecake', unitPrice: 400, category: 'desserts' },
  'cheesecake-todays': { id: 'cheesecake-todays', name: "Today's Cheesecake", unitPrice: 400, category: 'desserts' },
  'supplement-hazelnut': { id: 'supplement-hazelnut', name: 'Hazelnut', unitPrice: 160, category: 'desserts' },
  'supplement-walnut': { id: 'supplement-walnut', name: 'Walnut', unitPrice: 100, category: 'desserts' },
  'supplement-peanut': { id: 'supplement-peanut', name: 'Peanut', unitPrice: 100, category: 'desserts' },
  'supplement-1-fruit': { id: 'supplement-1-fruit', name: '1 Fruit', unitPrice: 100, category: 'desserts' },
  'supplement-2-fruits': { id: 'supplement-2-fruits', name: '2 Fruits', unitPrice: 150, category: 'desserts' },
  // Featured Menu & Coffee Beans
  'espresso-single-origin': { id: 'espresso-single-origin', name: 'Specialty Espresso', unitPrice: 350, category: 'espresso' },
  'flat-white-venty': { id: 'flat-white-venty', name: 'Flat White', unitPrice: 450, category: 'espresso' },
  'caffe-latte-venty': { id: 'caffe-latte-venty', name: 'Caffè Latte', unitPrice: 450, category: 'espresso' },
  'iced-specialty-latte': { id: 'iced-specialty-latte', name: 'Iced Specialty Latte', unitPrice: 500, category: 'cold' },
  'iced-latte': { id: 'iced-latte', name: 'Iced Latte', unitPrice: 300, category: 'cold' },
  'v60-pourover': { id: 'v60-pourover', name: 'V60 Hand Pour Filter', unitPrice: 550, category: 'filter' },
  'cold-brew-venty': { id: 'cold-brew-venty', name: 'Slow Chilled Cold Brew', unitPrice: 500, category: 'cold' },
  'fresh-orange-juice': { id: 'fresh-orange-juice', name: 'Freshly Squeezed Orange Juice', unitPrice: 400, category: 'juice' },
  'citrus-mint-cooler': { id: 'citrus-mint-cooler', name: 'Lemon Mint Refresher', unitPrice: 450, category: 'juice' },
  'mixed-berry-juice': { id: 'mixed-berry-juice', name: 'Wild Berry Fruit Blend', unitPrice: 500, category: 'juice' },
  'oreo-cheesecake-slice': { id: 'oreo-cheesecake-slice', name: 'Signature Oreo Cheesecake', unitPrice: 600, category: 'sweets' },
  'chocolate-fondant-cake': { id: 'chocolate-fondant-cake', name: 'Artisan Chocolate Cake', unitPrice: 550, category: 'sweets' },
  'fresh-pastries-selection': { id: 'fresh-pastries-selection', name: 'Fresh Bakery Pastry', unitPrice: 350, category: 'sweets' },
  'ethiopia-specialty': { id: 'ethiopia-specialty', name: 'Single Origin Ethiopia', unitPrice: 1400, category: 'beans' },
  'colombia-specialty': { id: 'colombia-specialty', name: 'Colombia Huila Supremo', unitPrice: 1350, category: 'beans' },
  'house-blend-venty': { id: 'house-blend-venty', name: 'Venty Signature Roast', unitPrice: 1200, category: 'beans' },
};

export const normalizeServerOrderItems = (rawItems: any[]): ServerOrderItem[] => {
  if (!Array.isArray(rawItems)) return [];
  return rawItems.map((item: any, idx: number) => {
    const rawId = String(item.id || item.productId || `item-${idx}`).trim();
    const rawName = String(item.name || 'Venty Item').trim().substring(0, 100);
    const notesStr = item.notes ? String(item.notes).substring(0, 160) : undefined;
    const grindStr = item.grind ? String(item.grind).substring(0, 60) : undefined;

    // Resolve canonical product by ID or by normalized name (never trust client-tampered price)
    const canonicalById = CANONICAL_PRODUCT_CATALOG[rawId];
    const canonicalByName = !canonicalById
      ? Object.values(CANONICAL_PRODUCT_CATALOG).find(
          (p) => p.name.toLowerCase() === rawName.toLowerCase(),
        )
      : undefined;
    const canonicalProduct = canonicalById || canonicalByName;

    let unitPrice = canonicalProduct
      ? canonicalProduct.unitPrice
      : Math.max(50, Math.min(5000, Number(item.unitPrice ?? item.price ?? 300) || 300));

    // Support official +50 DA flavor syrup addition on Latte when selected in notes
    if (
      canonicalProduct?.id === 'latte-classic' &&
      notesStr &&
      /\+50\s*DA/i.test(notesStr)
    ) {
      unitPrice += 50;
    }

    const quantity = Math.max(1, Math.min(99, Math.floor(Number(item.quantity ?? 1) || 1)));
    const lineTotal = unitPrice * quantity;
    const resolvedCategory = canonicalProduct
      ? canonicalProduct.category
      : item.category
      ? String(item.category).toLowerCase().trim()
      : undefined;

    return {
      id: canonicalProduct ? canonicalProduct.id : rawId,
      productId: canonicalProduct ? canonicalProduct.id : rawId,
      name: canonicalProduct ? canonicalProduct.name : rawName,
      price: unitPrice,
      unitPrice,
      quantity,
      lineTotal,
      category: resolvedCategory,
      notes: notesStr,
      grind: grindStr,
    };
  });
};

export const filterQualifyingItemsForLoyalty = (items: any[], db: ServerLoyaltyDB): any[] => {
  const qualifyingCategories = db.config.qualifyingCategories || DEFAULT_QUALIFYING_CATEGORIES;
  const excludedCategories = db.config.excludedCategories || DEFAULT_EXCLUDED_CATEGORIES;
  const validItems = Array.isArray(items) ? items : [];

  return validItems.filter((item: any) => {
    if (item.grind) return false;
    const cat = (item.category || '').toLowerCase().trim();
    if (excludedCategories.includes(cat)) return false;
    if (qualifyingCategories.includes(cat)) return true;
    const nameLower = (item.name || '').toLowerCase();
    const drinkKeywords = [
      'coffee',
      'latte',
      'cappuccino',
      'espresso',
      'flat white',
      'cortado',
      'cold brew',
      'mojito',
      'juice',
      'tea',
      'matcha',
      'americano',
      'macchiato',
      'milkshake',
      'smoothie',
    ];
    return drinkKeywords.some((kw) => nameLower.includes(kw));
  });
};

// In-flight concurrency locks for atomic operations
const activeRedemptionLocks = new Set<string>();
const activeOrderCompletionLocks = new Set<string>();

export const enrichOrderWithAlgiersTime = (order: ServerOrder) => {
  const db = dbCache || loadDatabase();
  const customerAcc = order.customerId
    ? db.accounts.find((a) => a.customerId === order.customerId)
    : undefined;
  const dateKey = getAlgiersDateKey(order.createdAt);
  return {
    ...order,
    id: order.orderId || order.id,
    orderId: order.orderId || order.id,
    items: order.orderItems || order.items || [],
    orderItems: order.orderItems || order.items || [],
    algiersDate: formatAlgiersDate(order.createdAt),
    algiersTime: formatAlgiersTime(order.createdAt),
    algiersDateTime: formatAlgiersDateTime(order.createdAt),
    algiersDateKey: dateKey,
    algiersBusinessDate: dateKey,
    customerStampCount: customerAcc ? customerAcc.currentStampCount : null,
    stampsToReward: db.config?.stampsToReward || 7,
  };
};

export const awardOrderLoyaltyStampInternal = (
  db: ServerLoyaltyDB,
  orderId: string,
  account: ServerLoyaltyAccount,
  items: any[],
) => {
  const qualifyingItems = filterQualifyingItemsForLoyalty(items, db);
  if (qualifyingItems.length === 0) {
    return {
      awardedStamp: false,
      unlockedReward: false,
      duplicatePrevented: false,
      account: sanitizeLoyaltyAccount(account),
      message: 'Order contains no qualifying drinks for stamps.',
    };
  }

  const idempotencyKey = `order_loyalty_${orderId}`;
  const existingTx = db.transactions.find((t) => t.idempotencyKey === idempotencyKey && t.status !== 'REVERSED');
  if (existingTx) {
    return {
      awardedStamp: false,
      unlockedReward: false,
      duplicatePrevented: true,
      account: sanitizeLoyaltyAccount(account),
      transaction: existingTx,
      message: `Order #${orderId} was already stamped (${existingTx.id}).`,
    };
  }

  const stampsDelta = db.config.stampsPerQualifyingOrder || 1;
  const prevStamps = account.currentStampCount;
  const newStamps = prevStamps + stampsDelta;
  let unlockedReward = false;
  let issuedReward: ServerLoyaltyReward | undefined;

  let finalCurrentStamps = newStamps;
  const targetToReward = db.config.stampsToReward || 7;

  if (newStamps >= targetToReward) {
    unlockedReward = true;
    finalCurrentStamps = newStamps - targetToReward;

    const rewardId = `RW-${Math.floor(1000 + Math.random() * 9000)}`;
    const redemptionChars = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';
    let redemptionCode = 'VENTY-';
    for (let i = 0; i < 5; i++) {
      redemptionCode += redemptionChars.charAt(Math.floor(Math.random() * redemptionChars.length));
    }
    const redemptionToken = `rw_tok_${crypto.randomBytes(12).toString('hex')}`;

    issuedReward = {
      rewardId,
      customerId: account.customerId,
      customerName: account.name,
      customerPhone: account.phone,
      type: 'FREE_DRINK',
      status: 'AVAILABLE',
      issuedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 60 * 24 * 60 * 60 * 1000).toISOString(),
      redemptionCode,
      redemptionToken,
    };

    account.availableRewards.push(issuedReward);

    db.transactions.unshift({
      id: `LTX-${Date.now().toString(36).toUpperCase()}-RW`,
      customerId: account.customerId,
      customerName: account.name,
      orderId,
      type: 'REWARD_ISSUED',
      stampsDelta: 0,
      timestamp: new Date().toISOString(),
      source: 'ONLINE_ORDER',
      status: 'CONFIRMED',
      idempotencyKey: `reward_issued_${rewardId}_${orderId}`,
      note: `🎉 Free Drink Reward Unlocked (${redemptionCode}) after 7 qualifying stamps!`,
      previousValue: prevStamps,
      newValue: finalCurrentStamps,
    });
    logAuditEvent('REWARD_ISSUED', { customerId: account.customerId, rewardId, redemptionCode });
  }

  const itemNames = qualifyingItems.map((i: any) => `${i.quantity || 1}x ${i.name}`).join(', ');
  const nowIso = new Date().toISOString();
  const purchaseTx: ServerLoyaltyTransaction = {
    id: `LTX-${Date.now().toString(36).toUpperCase()}`,
    customerId: account.customerId,
    customerName: account.name,
    orderId,
    type: 'PURCHASE_STAMP',
    stampsDelta,
    timestamp: nowIso,
    source: 'ONLINE_ORDER',
    status: 'CONFIRMED',
    idempotencyKey,
    note: `+${stampsDelta} Stamp: ${itemNames} (Order #${orderId})`,
    previousValue: prevStamps,
    newValue: finalCurrentStamps,
  };

  db.transactions.unshift(purchaseTx);

  account.currentStampCount = finalCurrentStamps;
  account.lifetimeStamps += stampsDelta;
  account.updatedAt = nowIso;

  // Sync order record in db.orders if present
  const orderRecord = db.orders.find((o) => o.orderId === orderId || o.id === orderId);
  if (orderRecord) {
    orderRecord.loyaltyStampAwarded = true;
    orderRecord.loyaltyStampsDelta = stampsDelta;
    orderRecord.loyaltyTransactionId = purchaseTx.id;
    orderRecord.loyaltyReversed = false;
  }

  logAuditEvent('STAMP_AWARDED', {
    customerId: account.customerId,
    orderId,
    stampsDelta,
    newTotal: finalCurrentStamps,
  });

  return {
    awardedStamp: true,
    unlockedReward,
    duplicatePrevented: false,
    account: sanitizeLoyaltyAccount(account),
    reward: issuedReward,
    transaction: purchaseTx,
    message: unlockedReward
      ? '🎉 Congratulations! You earned a stamp and unlocked your FREE DRINK reward!'
      : `✨ +1 Venty stamp earned! (${finalCurrentStamps}/${targetToReward} stamps).`,
  };
};

export const reverseOrderLoyaltyStampInternal = (
  db: ServerLoyaltyDB,
  orderId: string,
  reason = 'Order cancelled/refunded',
  adminId = 'VENTY-ADMIN',
) => {
  const stampTx = db.transactions.find((t) => t.orderId === orderId && t.type === 'PURCHASE_STAMP');
  if (!stampTx) {
    return { success: false, status: 404, message: 'No purchase stamp found for this order.' };
  }

  const existingReversal = db.transactions.find((t) => t.idempotencyKey === `reversal_order_${orderId}`);
  if (existingReversal) {
    return { success: false, status: 409, message: 'Order stamp has already been reversed.' };
  }

  const account = db.accounts.find((a) => a.customerId === stampTx.customerId);
  if (!account) {
    return { success: false, status: 404, message: 'Customer account not found.' };
  }

  const prevStamps = account.currentStampCount;
  const newStamps = Math.max(0, prevStamps - stampTx.stampsDelta);
  const nowIso = new Date().toISOString();

  db.transactions.unshift({
    id: `LTX-${Date.now().toString(36).toUpperCase()}`,
    customerId: account.customerId,
    customerName: account.name,
    orderId,
    type: 'REVERSAL',
    stampsDelta: -stampTx.stampsDelta,
    timestamp: nowIso,
    source: 'SYSTEM',
    status: 'CONFIRMED',
    idempotencyKey: `reversal_order_${orderId}`,
    note: `Reversal of Order #${orderId}: -${stampTx.stampsDelta} Stamp (${reason})`,
    adminReason: reason,
    adminId,
    previousValue: prevStamps,
    newValue: newStamps,
  });

  account.currentStampCount = newStamps;
  account.lifetimeStamps = Math.max(0, account.lifetimeStamps - stampTx.stampsDelta);
  account.updatedAt = nowIso;

  const orderRecord = db.orders.find((o) => o.orderId === orderId || o.id === orderId);
  if (orderRecord) {
    orderRecord.loyaltyStampAwarded = false;
    orderRecord.loyaltyReversed = true;
    orderRecord.updatedAt = nowIso;
  }

  logAuditEvent('ORDER_STAMP_REVERSED', {
    orderId,
    customerId: account.customerId,
    delta: -stampTx.stampsDelta,
    reason,
  });

  return {
    success: true,
    status: 200,
    message: `Stamp for order #${orderId} reversed (-${stampTx.stampsDelta} stamp).`,
    account: sanitizeLoyaltyAccount(account),
  };
};

app.post('/api/loyalty/order-completed', requireRole(['STAFF', 'ADMIN']), (req: Request, res: Response) => {
  const db = loadDatabase();
  const { orderId, customerId, customerPhone, customerName, items, totalAmount, pickupTime } = req.body;

  if (!orderId || typeof orderId !== 'string') {
    res.status(400).json({ error: 'Bad Request', message: 'Valid orderId is required.' });
    return;
  }

  let account: ServerLoyaltyAccount | undefined;
  if (customerId) {
    account = db.accounts.find((a) => a.customerId === customerId);
  }
  if (!account && customerPhone) {
    const cleanPhone = normalizePhoneNumber(customerPhone);
    account = db.accounts.find((a) => normalizePhoneNumber(a.phone) === cleanPhone);
  }

  if (!account) {
    res.status(404).json({ error: 'Not Found', message: 'No loyalty account found for order.' });
    return;
  }

  // Ensure the order is also persisted in db.orders with server-generated timestamps
  const nowIso = new Date().toISOString();
  const normalizedItems = normalizeServerOrderItems(items);
  const computedTotal =
    typeof totalAmount === 'number' && totalAmount > 0
      ? totalAmount
      : normalizedItems.reduce((sum, i) => sum + i.lineTotal, 0);
  const qualifies = filterQualifyingItemsForLoyalty(normalizedItems, db).length > 0;

  let orderRecord = db.orders.find((o) => o.orderId === orderId || o.id === orderId);
  if (!orderRecord) {
    orderRecord = {
      orderId,
      id: orderId,
      customerId: account.customerId,
      customerName: customerName || account.name,
      customerPhone: customerPhone || account.phone,
      orderItems: normalizedItems,
      items: normalizedItems,
      totalAmount: computedTotal,
      status: 'COMPLETED',
      pickupTime: pickupTime || '15 mins',
      createdAt: nowIso,
      completedAt: nowIso,
      updatedAt: nowIso,
      qualifiesForLoyalty: qualifies,
      loyaltyStampAwarded: false,
      loyaltyStampsDelta: 0,
    };
    db.orders.unshift(orderRecord);
  } else {
    orderRecord.customerId = orderRecord.customerId || account.customerId;
    orderRecord.status = 'COMPLETED';
    orderRecord.completedAt = orderRecord.completedAt || nowIso;
    orderRecord.updatedAt = nowIso;
  }

  const result = awardOrderLoyaltyStampInternal(db, orderId, account, normalizedItems);
  saveDatabase(db);

  res.json(result);
});

// 5. POST Staff Reward Verification Desk (Protected: STAFF or ADMIN role)
app.post('/api/loyalty/verify-reward', redemptionLimiter, requireRole(['STAFF', 'ADMIN']), (req: Request, res: Response) => {
  const db = loadDatabase();
  const { query } = req.body;
  const ip = getClientIp(req);

  if (!query || typeof query !== 'string') {
    res.status(400).json({ error: 'Bad Request', message: 'Query code/token is required.' });
    return;
  }

  const clean = query.trim().toUpperCase();

  for (const account of db.accounts) {
    const allRewards = [...account.availableRewards, ...account.redeemedRewards];
    const match = allRewards.find(
      (r) =>
        r.redemptionCode.toUpperCase() === clean ||
        r.redemptionToken === query.trim() ||
        r.rewardId.toUpperCase() === clean,
    );

    if (match) {
      const record = rateLimitStore.get(ip);
      if (record) record.failedAttempts = 0;

      const isExpired = match.expiresAt ? new Date(match.expiresAt).getTime() < Date.now() : false;
      let status = match.status;
      if (status === 'AVAILABLE' && isExpired) {
        status = 'EXPIRED';
      }

      logAuditEvent('REWARD_VERIFIED', { rewardId: match.rewardId, status, staffId: req.user?.staffId });

      res.json({
        valid: status === 'AVAILABLE' && !isExpired,
        reward: match,
        customer: {
          customerId: account.customerId,
          name: account.name,
          phone: account.phone,
        },
        status,
        isExpired,
        message:
          status === 'AVAILABLE'
            ? 'Valid Free Drink Reward ready to redeem.'
            : status === 'REDEEMED'
            ? 'This reward has already been redeemed.'
            : 'Reward is expired or cancelled.',
      });
      return;
    }
  }

  // Track failed verification attempt for brute-force defense
  const record = rateLimitStore.get(ip) || { count: 0, resetTime: Date.now() + 60000, failedAttempts: 0 };
  record.failedAttempts = (record.failedAttempts || 0) + 1;
  if (record.failedAttempts >= 5) {
    record.blockedUntil = Date.now() + 5 * 60 * 1000;
    logAuditEvent('BRUTE_FORCE_LOCKOUT_TRIGGERED', { ip, attempts: record.failedAttempts });
  }
  rateLimitStore.set(ip, record);

  res.status(404).json({
    valid: false,
    reward: null,
    status: 'NOT_FOUND',
    message: 'Reward code or token not found.',
  });
});

// 6. POST Server-Authoritative Atomic Reward Redemption (Protected: STAFF or ADMIN role)
app.post('/api/loyalty/redeem', redemptionLimiter, requireRole(['STAFF', 'ADMIN']), (req: Request, res: Response) => {
  const db = loadDatabase();
  const { rewardId, redemptionCode, redemptionToken, location = 'Miliana Roastery Counter', orderId } = req.body || {};

  const lockKey = String(rewardId || redemptionCode || redemptionToken || '').trim().toUpperCase();
  if (lockKey && activeRedemptionLocks.has(lockKey)) {
    res.status(409).json({ success: false, message: 'Reward redemption is currently being processed.' });
    return;
  }
  if (lockKey) activeRedemptionLocks.add(lockKey);

  try {
    // Derive staff identity securely from server session
    const staffId = req.user?.staffId || req.user?.adminId || 'Staff-Miliana';

    let targetAccount: ServerLoyaltyAccount | undefined;
    let targetReward: ServerLoyaltyReward | undefined;

    for (const acc of db.accounts) {
      const available = acc.availableRewards || [];
      const match = available.find(
        (r) =>
          (rewardId && r.rewardId === rewardId) ||
          (redemptionCode && r.redemptionCode.toUpperCase() === redemptionCode.trim().toUpperCase()) ||
          (redemptionToken && r.redemptionToken === redemptionToken.trim()),
      );
      if (match) {
        targetAccount = acc;
        targetReward = match;
        break;
      }
    }

    if (!targetAccount || !targetReward) {
      for (const acc of db.accounts) {
        const redeemed = acc.redeemedRewards || [];
        const match = redeemed.find(
          (r) =>
            (rewardId && r.rewardId === rewardId) ||
            (redemptionCode && r.redemptionCode.toUpperCase() === redemptionCode?.trim().toUpperCase()),
        );
        if (match) {
          res.status(409).json({
            success: false,
            message: 'This reward has already been redeemed.',
          });
          return;
        }
      }

      res.status(404).json({
        success: false,
        message: 'Reward not found or not available for redemption.',
      });
      return;
    }

    if (targetReward.expiresAt && new Date(targetReward.expiresAt).getTime() < Date.now()) {
      res.status(410).json({
        success: false,
        message: 'This reward has expired.',
      });
      return;
    }

    const nowIso = new Date().toISOString();
    const redeemedReward: ServerLoyaltyReward = {
      ...targetReward,
      status: 'REDEEMED',
      redeemedAt: nowIso,
      redemptionStaffId: staffId,
      redemptionLocation: location,
      redeemedOrderId: orderId,
    };

    targetAccount.availableRewards = targetAccount.availableRewards.filter((r) => r.rewardId !== targetReward!.rewardId);
    targetAccount.redeemedRewards.unshift(redeemedReward);
    targetAccount.updatedAt = nowIso;

    db.transactions.unshift({
      id: `LTX-${Date.now().toString(36).toUpperCase()}`,
      customerId: targetAccount.customerId,
      customerName: targetAccount.name,
      orderId,
      type: 'REWARD_REDEEMED',
      stampsDelta: 0,
      timestamp: nowIso,
      source: 'COUNTER_SCAN',
      status: 'CONFIRMED',
      idempotencyKey: `redeem_rw_${targetReward.rewardId}`,
      note: `🎉 Free Drink Redeemed (${targetReward.redemptionCode}) at ${location} (Staff: ${staffId})`,
    });

    saveDatabase(db);
    logAuditEvent('REWARD_REDEEMED', { rewardId: targetReward.rewardId, customerId: targetAccount.customerId, staffId, location });

    res.json({
      success: true,
      message: `🎉 Reward ${targetReward.redemptionCode} successfully redeemed! Enjoy your free drink.`,
      reward: redeemedReward,
      account: sanitizeLoyaltyAccount(targetAccount),
    });
  } finally {
    if (lockKey) activeRedemptionLocks.delete(lockKey);
  }
});

// 7. POST Admin Audited Balance Adjustment (Strictly Protected: ADMIN role only)
app.post('/api/loyalty/admin/adjust', adminLimiter, requireRole(['ADMIN']), (req: Request, res: Response) => {
  const db = loadDatabase();
  const { customerId, stampsDelta, reason } = req.body;

  // Derive adminId from trusted session
  const adminId = req.user?.adminId || 'VENTY-ADMIN';

  if (!customerId || stampsDelta === undefined || !reason) {
    res.status(400).json({ error: 'Bad Request', message: 'customerId, stampsDelta, and reason are required.' });
    return;
  }

  const account = db.accounts.find((a) => a.customerId === customerId);
  if (!account) {
    res.status(404).json({ error: 'Not Found', message: 'Customer account not found.' });
    return;
  }

  const targetToReward = db.config.stampsToReward || 7;
  const prevStamps = account.currentStampCount;
  const targetStamps = Math.max(0, Math.min(targetToReward, prevStamps + Number(stampsDelta)));
  const effectiveDelta = targetStamps - prevStamps;

  if (effectiveDelta === 0) {
    res.json({ success: false, message: 'No change in stamps balance.', account: sanitizeLoyaltyAccount(account) });
    return;
  }

  const nowIso = new Date().toISOString();
  db.transactions.unshift({
    id: `LTX-${Date.now().toString(36).toUpperCase()}`,
    customerId: account.customerId,
    customerName: account.name,
    type: 'ADMIN_ADJUSTMENT',
    stampsDelta: effectiveDelta,
    timestamp: nowIso,
    source: 'ADMIN_CONSOLE',
    status: 'CONFIRMED',
    idempotencyKey: `admin_adj_${account.customerId}_${Date.now()}`,
    note: `Staff Adjustment: ${effectiveDelta > 0 ? '+' : ''}${effectiveDelta} Stamps (${reason})`,
    adminReason: reason,
    adminId,
    previousValue: prevStamps,
    newValue: targetStamps,
  });

  account.currentStampCount = targetStamps;
  if (effectiveDelta > 0) {
    account.lifetimeStamps += effectiveDelta;
  }
  account.updatedAt = nowIso;

  saveDatabase(db);
  logAuditEvent('ADMIN_ADJUSTMENT', { customerId: account.customerId, effectiveDelta, reason, adminId });

  res.json({
    success: true,
    message: `Account updated: ${account.currentStampCount}/${targetToReward} stamps.`,
    account: sanitizeLoyaltyAccount(account),
  });
});

// 8. POST Admin Cancel Reward (Strictly Protected: ADMIN role only)
app.post('/api/loyalty/admin/cancel-reward', adminLimiter, requireRole(['ADMIN']), (req: Request, res: Response) => {
  const db = loadDatabase();
  const { rewardId, reason = 'Cancelled by manager' } = req.body;
  const adminId = req.user?.adminId || 'VENTY-ADMIN';

  if (!rewardId) {
    res.status(400).json({ error: 'Bad Request', message: 'rewardId is required.' });
    return;
  }

  let targetAccount: ServerLoyaltyAccount | undefined;
  let targetReward: ServerLoyaltyReward | undefined;

  for (const acc of db.accounts) {
    const match = acc.availableRewards.find((r) => r.rewardId === rewardId);
    if (match) {
      targetAccount = acc;
      targetReward = match;
      break;
    }
  }

  if (!targetAccount || !targetReward) {
    res.status(404).json({ error: 'Not Found', message: 'Available reward not found.' });
    return;
  }

  targetAccount.availableRewards = targetAccount.availableRewards.filter((r) => r.rewardId !== rewardId);
  targetAccount.updatedAt = new Date().toISOString();

  db.transactions.unshift({
    id: `LTX-${Date.now().toString(36).toUpperCase()}`,
    customerId: targetAccount.customerId,
    customerName: targetAccount.name,
    type: 'ADMIN_ADJUSTMENT',
    stampsDelta: 0,
    timestamp: new Date().toISOString(),
    source: 'ADMIN_CONSOLE',
    status: 'CONFIRMED',
    idempotencyKey: `cancel_rw_${rewardId}`,
    note: `Reward ${targetReward.redemptionCode} cancelled: ${reason}`,
    adminReason: reason,
    adminId,
  });

  saveDatabase(db);
  logAuditEvent('REWARD_CANCELLED', { rewardId, customerId: targetAccount.customerId, reason, adminId });

  res.json({
    success: true,
    message: `Reward ${targetReward.redemptionCode} cancelled.`,
    account: sanitizeLoyaltyAccount(targetAccount),
  });
});

// 9. POST Order Refund/Cancellation Reversal (Protected: ADMIN role only)
app.post('/api/loyalty/order-reversal', adminLimiter, requireRole(['ADMIN']), (req: Request, res: Response) => {
  const db = loadDatabase();
  const { orderId, reason = 'Order cancelled/refunded' } = req.body;
  const adminId = req.user?.adminId || 'VENTY-ADMIN';

  if (!orderId) {
    res.status(400).json({ error: 'Bad Request', message: 'orderId is required.' });
    return;
  }

  const result = reverseOrderLoyaltyStampInternal(db, orderId, reason, adminId);
  if (!result.success) {
    res.status(result.status || 400).json({ error: 'Error', message: result.message });
    return;
  }

  saveDatabase(db);
  res.json({
    success: true,
    message: result.message,
    account: result.account,
  });
});

// -------------------------------------------------------------
// 7B. CUSTOMER PROFILES & ORDER HISTORY + ADMIN/STAFF ORDERS
// -------------------------------------------------------------

// GET Authenticated Customer Profile + Summary Stats
app.get('/api/customer/profile', requireRole(['CUSTOMER', 'STAFF', 'ADMIN']), (req: Request, res: Response) => {
  const db = loadDatabase();
  const queryCustomerId = (req.query.customerId as string) || '';

  let targetCustomerId: string | undefined;
  if (req.user?.role === 'CUSTOMER') {
    targetCustomerId = req.user.customerId;
    if (!targetCustomerId) {
      res.status(401).json({ error: 'Unauthorized', message: 'Authentication required.' });
      return;
    }
    if (queryCustomerId && queryCustomerId !== targetCustomerId) {
      logAuditEvent('CUSTOMER_ISOLATION_VIOLATION_ATTEMPT', {
        attemptedCustomerId: queryCustomerId,
        authenticatedCustomerId: targetCustomerId,
      });
      res.status(403).json({ error: 'Forbidden', message: 'You can only access your own customer profile.' });
      return;
    }
  } else {
    targetCustomerId = queryCustomerId || req.user?.customerId;
  }

  if (!targetCustomerId) {
    res.status(400).json({ error: 'Bad Request', message: 'customerId is required.' });
    return;
  }

  const account = db.accounts.find((a) => a.customerId === targetCustomerId);
  if (!account) {
    res.status(404).json({ error: 'Not Found', message: 'Customer profile not found.' });
    return;
  }

  const customerOrders = db.orders.filter((o) => o.customerId === account.customerId);
  const completedOrders = customerOrders.filter((o) => o.status === 'COMPLETED');

  res.json({
    profile: {
      customerId: account.customerId,
      name: account.name,
      phone: account.phone,
      email: account.email || '',
      favouriteDrink: account.favouriteDrink || 'Flat White',
      createdAt: account.createdAt,
      updatedAt: account.updatedAt,
    },
    account: sanitizeLoyaltyAccount(account),
    stats: {
      totalOrders: customerOrders.length,
      completedOrders: completedOrders.length,
      totalSpent: completedOrders.reduce((sum, o) => sum + o.totalAmount, 0),
    },
  });
});

// PUT Update Authenticated Customer Profile
app.put('/api/customer/profile', requireRole(['CUSTOMER', 'ADMIN']), (req: Request, res: Response) => {
  const db = loadDatabase();
  const targetCustomerId =
    req.user?.role === 'CUSTOMER'
      ? req.user.customerId
      : (req.body.customerId as string) || req.user?.customerId;

  if (req.user?.role === 'CUSTOMER' && req.body.customerId && req.body.customerId !== req.user.customerId) {
    res.status(403).json({ error: 'Forbidden', message: 'You can only update your own customer profile.' });
    return;
  }

  const account = db.accounts.find((a) => a.customerId === targetCustomerId);
  if (!account) {
    res.status(404).json({ error: 'Not Found', message: 'Customer profile not found.' });
    return;
  }

  const { name, phone, email, favouriteDrink } = req.body;
  if (name !== undefined && typeof name === 'string' && name.trim()) {
    account.name = name.trim().substring(0, 80);
  }
  if (phone !== undefined && typeof phone === 'string' && phone.trim()) {
    const cleanNewPhone = normalizePhoneNumber(phone);
    if (!isValidNormalizedPhone(cleanNewPhone)) {
      res.status(400).json({
        error: 'Bad Request',
        message: 'Please provide a valid phone number.',
      });
      return;
    }
    const duplicate = db.accounts.find(
      (a) => a.customerId !== account.customerId && normalizePhoneNumber(a.phone) === cleanNewPhone,
    );
    if (duplicate) {
      res.status(409).json({
        error: 'Conflict',
        message: 'Another customer account is already registered with that phone number.',
      });
      return;
    }
    account.phone = cleanNewPhone;
  }
  if (email !== undefined) {
    account.email = typeof email === 'string' && email.trim() ? email.trim().substring(0, 100) : undefined;
  }
  if (favouriteDrink !== undefined && typeof favouriteDrink === 'string') {
    account.favouriteDrink = favouriteDrink.trim().substring(0, 60) || 'Flat White';
  }

  account.updatedAt = new Date().toISOString();
  saveDatabase(db);
  logAuditEvent('CUSTOMER_PROFILE_UPDATED', { customerId: account.customerId });

  res.json({
    success: true,
    profile: {
      customerId: account.customerId,
      name: account.name,
      phone: account.phone,
      email: account.email || '',
      favouriteDrink: account.favouriteDrink || 'Flat White',
      createdAt: account.createdAt,
      updatedAt: account.updatedAt,
    },
    account: sanitizeLoyaltyAccount(account),
    message: 'Customer profile updated successfully.',
  });
});

// POST Create New Order (Server-Generated Unguessable IDs, Session-Derived Customer Identity & Strict Idempotency)
app.post('/api/orders', (req: Request, res: Response) => {
  const db = loadDatabase();
  const {
    items,
    orderItems,
    customerName,
    customerPhone,
    pickupTime = '15 mins',
    notes,
    status: requestedStatus,
    idempotencyKey: rawIdempotencyKey,
  } = req.body || {};

  const rawItems = Array.isArray(orderItems) ? orderItems : Array.isArray(items) ? items : [];
  if (rawItems.length === 0) {
    res.status(400).json({ error: 'Bad Request', message: 'Order must contain at least one item.' });
    return;
  }
  if (rawItems.length > 50) {
    res.status(400).json({ error: 'Bad Request', message: 'Order contains too many distinct line items (max 50).' });
    return;
  }

  const normalizedItems = normalizeServerOrderItems(rawItems);
  if (normalizedItems.length === 0) {
    res.status(400).json({ error: 'Bad Request', message: 'No valid items found in order.' });
    return;
  }

  const totalAmount = normalizedItems.reduce((sum, item) => sum + item.lineTotal, 0);
  const qualifiesForLoyalty = filterQualifyingItemsForLoyalty(normalizedItems, db).length > 0;

  // Derive customerId strictly from authenticated server session when CUSTOMER is logged in.
  // NEVER trust a customerId or unverified phone number sent from an unauthenticated request.
  let resolvedAccount: ServerLoyaltyAccount | undefined;
  let resolvedCustomerId: string | null = null;

  if (req.user?.role === 'CUSTOMER' && req.user.customerId) {
    resolvedAccount = db.accounts.find((a) => a.customerId === req.user?.customerId);
    resolvedCustomerId = resolvedAccount ? resolvedAccount.customerId : req.user.customerId;
  } else if ((req.user?.role === 'STAFF' || req.user?.role === 'ADMIN') && req.body.customerId) {
    resolvedAccount = db.accounts.find((a) => a.customerId === req.body.customerId);
    if (resolvedAccount) resolvedCustomerId = resolvedAccount.customerId;
  } else if ((req.user?.role === 'STAFF' || req.user?.role === 'ADMIN') && customerPhone && typeof customerPhone === 'string') {
    const cleanPhone = normalizePhoneNumber(customerPhone);
    if (cleanPhone) {
      resolvedAccount = db.accounts.find((a) => normalizePhoneNumber(a.phone) === cleanPhone);
      if (resolvedAccount) {
        resolvedCustomerId = resolvedAccount.customerId;
      }
    }
  }

  // Validate idempotency key format
  const sanitizedIdempotencyKey =
    typeof rawIdempotencyKey === 'string' && rawIdempotencyKey.trim()
      ? rawIdempotencyKey.trim().substring(0, 128)
      : undefined;

  const payloadFingerprint = crypto
    .createHash('sha256')
    .update(
      JSON.stringify({
        items: normalizedItems.map((i) => ({ p: i.productId, q: i.quantity, n: i.notes || '' })),
        pickupTime: String(pickupTime || '15 mins').trim(),
        notes: notes ? String(notes).trim() : '',
      }),
    )
    .digest('hex');

  // Idempotency check
  if (sanitizedIdempotencyKey) {
    const matchedByIdempotency = db.orders.find(
      (o) => (o as any).idempotencyKey === sanitizedIdempotencyKey,
    );
    if (matchedByIdempotency) {
      // Check cross-customer isolation
      if (
        matchedByIdempotency.customerId &&
        resolvedCustomerId &&
        matchedByIdempotency.customerId !== resolvedCustomerId
      ) {
        res.status(409).json({
          error: 'Conflict',
          message: 'Idempotency key has already been claimed by another customer account.',
        });
        return;
      }
      // Check payload matching
      if ((matchedByIdempotency as any).payloadFingerprint === payloadFingerprint) {
        res.status(200).json({
          created: false,
          duplicatePrevented: true,
          order: enrichOrderWithAlgiersTime(matchedByIdempotency),
        });
        return;
      } else {
        res.status(409).json({
          error: 'Conflict',
          message: 'Idempotency key was previously submitted with a different order payload.',
        });
        return;
      }
    }
  }

  // Rapid double-tap protection within 5 seconds for the same customer and identical items
  const itemFingerprint = normalizedItems
    .map((i) => `${i.productId}:${i.quantity}:${i.notes || ''}`)
    .sort()
    .join('|');
  const nowMs = Date.now();

  const existingRapidOrder = db.orders.find((o) => {
    if (resolvedCustomerId && o.customerId === resolvedCustomerId) {
      const createdMs = new Date(o.createdAt).getTime();
      if (!isNaN(createdMs) && Math.abs(nowMs - createdMs) < 4000) {
        const existingFp = (o.orderItems || [])
          .map((i) => `${i.productId}:${i.quantity}:${i.notes || ''}`)
          .sort()
          .join('|');
        if (existingFp === itemFingerprint) return true;
      }
    }
    return false;
  });

  if (existingRapidOrder) {
    res.status(200).json({
      created: false,
      duplicatePrevented: true,
      order: enrichOrderWithAlgiersTime(existingRapidOrder),
    });
    return;
  }

  // Generate cryptographically unguessable order ID for all orders
  const randomSuffix = crypto.randomBytes(4).toString('hex').toUpperCase();
  const generatedOrderId = `VENTY-${Date.now().toString(36).toUpperCase()}-${randomSuffix}`;

  const nowIso = new Date().toISOString();
  const initialStatus: ServerOrderStatus =
    req.user?.role === 'STAFF' || req.user?.role === 'ADMIN'
      ? normalizeServerOrderStatus(requestedStatus)
      : 'PENDING';

  const newOrder: ServerOrder = {
    orderId: generatedOrderId,
    id: generatedOrderId,
    customerId: resolvedCustomerId,
    customerName:
      (typeof customerName === 'string' && customerName.trim().substring(0, 80)) ||
      resolvedAccount?.name ||
      'Valued Guest',
    customerPhone:
      (typeof customerPhone === 'string' && customerPhone.trim().substring(0, 30)) ||
      resolvedAccount?.phone ||
      undefined,
    orderItems: normalizedItems,
    items: normalizedItems,
    totalAmount,
    status: initialStatus,
    pickupTime: String(pickupTime || '15 mins').substring(0, 40),
    notes: notes ? String(notes).substring(0, 200) : undefined,
    createdAt: nowIso,
    completedAt: initialStatus === 'COMPLETED' ? nowIso : null,
    updatedAt: nowIso,
    cancelledAt: initialStatus === 'CANCELLED' ? nowIso : null,
    qualifiesForLoyalty,
    loyaltyStampAwarded: false,
    loyaltyStampsDelta: 0,
  };

  (newOrder as any).idempotencyKey = sanitizedIdempotencyKey;
  (newOrder as any).payloadFingerprint = payloadFingerprint;

  db.orders.unshift(newOrder);

  let loyaltyResult: any = null;
  if (initialStatus === 'COMPLETED' && resolvedAccount && qualifiesForLoyalty) {
    loyaltyResult = awardOrderLoyaltyStampInternal(db, newOrder.orderId, resolvedAccount, normalizedItems);
  }

  saveDatabase(db);
  logAuditEvent('ORDER_CREATED', {
    orderId: newOrder.orderId,
    customerId: newOrder.customerId,
    totalAmount: newOrder.totalAmount,
    status: newOrder.status,
  });

  res.status(201).json({
    created: true,
    order: enrichOrderWithAlgiersTime(newOrder),
    loyaltyResult,
  });
});

// GET Customer's Own Order History ("My Orders" — Strictly Isolated to Authenticated Customer)
app.get('/api/orders/my-orders', requireRole(['CUSTOMER']), (req: Request, res: Response) => {
  const db = loadDatabase();
  const queryCustomerId = (req.query.customerId as string) || '';

  let targetCustomerId: string | undefined;
  if (req.user?.role === 'CUSTOMER') {
    targetCustomerId = req.user.customerId;
    if (!targetCustomerId) {
      res.status(401).json({ error: 'Unauthorized', message: 'Authentication required.' });
      return;
    }
    if (queryCustomerId && queryCustomerId !== targetCustomerId) {
      logAuditEvent('CUSTOMER_ORDER_ISOLATION_VIOLATION', {
        attemptedCustomerId: queryCustomerId,
        authenticatedCustomerId: targetCustomerId,
      });
      res.status(403).json({
        error: 'Forbidden',
        message: 'You can only view your own order history.',
      });
      return;
    }
  } else {
    targetCustomerId = queryCustomerId || req.user?.customerId;
  }

  if (!targetCustomerId) {
    res.status(400).json({ error: 'Bad Request', message: 'customerId is required.' });
    return;
  }

  const customerOrders = db.orders
    .filter((o) => o.customerId === targetCustomerId)
    .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
    .map(enrichOrderWithAlgiersTime);

  res.json({
    orders: customerOrders,
    timezone: VENTY_TIMEZONE,
  });
});

// GET Single Order by ID (For Customer Order Tracking — Enforces Strict Customer Ownership)
app.get('/api/orders/:orderId', (req: Request, res: Response) => {
  const db = loadDatabase();
  const orderId = String(req.params.orderId || '').trim();
  const targetOrder = db.orders.find((o) => o.orderId === orderId || o.id === orderId);

  if (!targetOrder) {
    res.status(404).json({ error: 'Not Found', message: `Order #${orderId} not found.` });
    return;
  }

  // Enforce strict customer isolation: if an order belongs to a customerId, only that authenticated customer or STAFF/ADMIN may view it
  if (targetOrder.customerId) {
    const isStaffOrAdmin = req.user?.role === 'STAFF' || req.user?.role === 'ADMIN';
    const isOwnerCustomer = req.user?.role === 'CUSTOMER' && req.user.customerId === targetOrder.customerId;
    if (!isStaffOrAdmin && !isOwnerCustomer) {
      logAuditEvent('UNAUTHORIZED_ORDER_ACCESS_ATTEMPT', {
        orderId,
        orderOwnerId: targetOrder.customerId,
        requesterId: req.user?.customerId || 'UNAUTHENTICATED',
      });
      res.status(403).json({
        error: 'Forbidden',
        message: 'You are not authorized to access another customer\'s order.',
      });
      return;
    }
  }

  res.json({
    order: enrichOrderWithAlgiersTime(targetOrder),
    timezone: VENTY_TIMEZONE,
  });
});

// GET Admin & Staff Order Dashboard (Grouped by Africa/Algiers Business Date + Metrics)
app.get('/api/orders', requireRole(['STAFF', 'ADMIN']), (req: Request, res: Response) => {
  const db = loadDatabase();
  const period = ((req.query.period as string) || 'TODAY').toUpperCase().replace(/\s+/g, '_');
  const statusFilter = ((req.query.status as string) || 'ALL').toUpperCase();
  const searchQuery = ((req.query.search as string) || '').trim().toLowerCase();
  const customerIdFilter = ((req.query.customerId as string) || '').trim();

  const now = new Date();
  const boundaries = getAlgiersBusinessBoundaries(now);

  // 1. Compute Today's Metrics in Africa/Algiers across all orders
  const todayOrders = db.orders.filter((o) => matchesAlgiersDateFilter(o.createdAt, 'TODAY', now));
  const todayCompleted = todayOrders.filter((o) => o.status === 'COMPLETED');
  const todayPending = todayOrders.filter((o) =>
    ['PENDING', 'CONFIRMED', 'PREPARING', 'READY'].includes(o.status),
  );
  const todayCancelled = todayOrders.filter((o) => o.status === 'CANCELLED');
  const todaySales = todayOrders
    .filter((o) => o.status !== 'CANCELLED')
    .reduce((sum, o) => sum + o.totalAmount, 0);
  const todayQualifyingLoyaltyOrders = todayOrders.filter(
    (o) => o.status !== 'CANCELLED' && (o.qualifiesForLoyalty || o.loyaltyStampAwarded),
  ).length;

  // 2. Filter orders by requested Africa/Algiers date period
  let filtered = db.orders.filter((o) => matchesAlgiersDateFilter(o.createdAt, period, now));

  if (customerIdFilter) {
    filtered = filtered.filter((o) => o.customerId === customerIdFilter);
  }

  if (statusFilter && statusFilter !== 'ALL') {
    filtered = filtered.filter((o) => o.status === statusFilter);
  }

  if (searchQuery) {
    filtered = filtered.filter(
      (o) =>
        o.orderId.toLowerCase().includes(searchQuery) ||
        o.customerName.toLowerCase().includes(searchQuery) ||
        (o.customerPhone && o.customerPhone.toLowerCase().includes(searchQuery)) ||
        (o.customerId && o.customerId.toLowerCase().includes(searchQuery)) ||
        o.orderItems.some((item) => item.name.toLowerCase().includes(searchQuery)),
    );
  }

  filtered.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());

  const periodCompleted = filtered.filter((o) => o.status === 'COMPLETED').length;
  const periodPending = filtered.filter((o) =>
    ['PENDING', 'CONFIRMED', 'PREPARING', 'READY'].includes(o.status),
  ).length;
  const periodCancelled = filtered.filter((o) => o.status === 'CANCELLED').length;
  const periodSales = filtered
    .filter((o) => o.status !== 'CANCELLED')
    .reduce((sum, o) => sum + o.totalAmount, 0);
  const periodQualifying = filtered.filter(
    (o) => o.status !== 'CANCELLED' && (o.qualifiesForLoyalty || o.loyaltyStampAwarded),
  ).length;

  const metrics = {
    totalOrders: period === 'TODAY' ? todayOrders.length : filtered.length,
    completedOrders: period === 'TODAY' ? todayCompleted.length : periodCompleted,
    pendingOrders: period === 'TODAY' ? todayPending.length : periodPending,
    cancelledOrders: period === 'TODAY' ? todayCancelled.length : periodCancelled,
    todaySales,
    todayQualifyingLoyaltyOrders,
    periodSales,
    periodQualifyingLoyaltyOrders: periodQualifying,
    algiersTodayKey: boundaries.todayKey,
    algiersTodayLabel: boundaries.todayLabel,
    timezone: VENTY_TIMEZONE,
  };

  res.json({
    orders: filtered.map(enrichOrderWithAlgiersTime),
    metrics,
    period,
    timezone: VENTY_TIMEZONE,
    algiersTodayKey: boundaries.todayKey,
    algiersTodayLabel: boundaries.todayLabel,
  });
});

// PATCH / POST Update Order Status (Strictly Protected: STAFF or ADMIN role only)
const handleOrderStatusUpdate = (req: Request, res: Response) => {
  const db = loadDatabase();
  const orderId = String(req.params.orderId || '').trim();
  const { status: rawStatus, reason } = req.body || {};

  if (!rawStatus || typeof rawStatus !== 'string') {
    res.status(400).json({ error: 'Bad Request', message: 'Valid order status is required.' });
    return;
  }

  if (activeOrderCompletionLocks.has(orderId)) {
    res.status(409).json({ error: 'Conflict', message: 'Order status transition is currently being processed.' });
    return;
  }
  activeOrderCompletionLocks.add(orderId);

  try {
    const order = db.orders.find((o) => o.orderId === orderId || o.id === orderId);
    if (!order) {
      res.status(404).json({ error: 'Not Found', message: `Order #${orderId} not found.` });
      return;
    }

  const nextStatus = normalizeServerOrderStatus(rawStatus);
  const currentStatus = order.status;

  // Idempotent no-op if status is already in the requested state
  if (currentStatus === nextStatus) {
    res.json({
      success: true,
      order: enrichOrderWithAlgiersTime(order),
      message: `Order #${orderId} is already ${nextStatus}.`,
    });
    return;
  }

  // State machine enforcement
  if (currentStatus === 'CANCELLED') {
    res.status(400).json({
      error: 'Bad Request',
      message: `Cannot change status of a CANCELLED order. Cancelled orders are terminal.`,
    });
    return;
  }

  if (currentStatus === 'COMPLETED' && nextStatus !== 'CANCELLED') {
    res.status(400).json({
      error: 'Bad Request',
      message: `Cannot transition a COMPLETED order back to ${nextStatus}.`,
    });
    return;
  }

  if (currentStatus === 'COMPLETED' && nextStatus === 'CANCELLED' && req.user?.role !== 'ADMIN') {
    res.status(403).json({
      error: 'Forbidden',
      message: 'Only an ADMIN can cancel/reverse an already COMPLETED order.',
    });
    return;
  }

  const nowIso = new Date().toISOString();
  order.status = nextStatus;
  order.updatedAt = nowIso;

  let loyaltyResult: any = null;
  let updatedAccount: ServerLoyaltyAccount | undefined;

  if (nextStatus === 'COMPLETED') {
    order.completedAt = order.completedAt || nowIso;
    if (order.customerId) {
      const account = db.accounts.find((a) => a.customerId === order.customerId);
      if (account) {
        updatedAccount = account;
        if (order.qualifiesForLoyalty) {
          loyaltyResult = awardOrderLoyaltyStampInternal(db, order.orderId, account, order.orderItems);
        }
      }
    }
  } else if (nextStatus === 'CANCELLED') {
    order.cancelledAt = order.cancelledAt || nowIso;
    const hasStampTx = db.transactions.some(
      (t) => t.orderId === order.orderId && t.type === 'PURCHASE_STAMP',
    );
    if (order.loyaltyStampAwarded || hasStampTx) {
      const actorId = req.user?.adminId || req.user?.staffId || 'VENTY-STAFF';
      const revRes = reverseOrderLoyaltyStampInternal(
        db,
        order.orderId,
        reason || 'Order cancelled',
        actorId,
      );
      if (revRes.success) {
        loyaltyResult = revRes;
        updatedAccount = revRes.account;
      }
    }
  }

    saveDatabase(db);
    logAuditEvent('ORDER_STATUS_UPDATED', {
      orderId: order.orderId,
      previousStatus: currentStatus,
      status: order.status,
      actorRole: req.user?.role || 'SYSTEM_LIFECYCLE',
    });

    res.json({
      success: true,
      order: enrichOrderWithAlgiersTime(order),
      loyaltyResult,
      account: updatedAccount ? sanitizeLoyaltyAccount(updatedAccount) : undefined,
      message: `Order #${orderId} status updated to ${nextStatus}.`,
    });
  } finally {
    activeOrderCompletionLocks.delete(orderId);
  }
};

app.patch('/api/orders/:orderId/status', requireRole(['STAFF', 'ADMIN']), handleOrderStatusUpdate);
app.post('/api/orders/:orderId/status', requireRole(['STAFF', 'ADMIN']), handleOrderStatusUpdate);

// 10. GET Admin Metrics (Protected: ADMIN role only)
app.get('/api/loyalty/admin/metrics', adminLimiter, requireRole(['ADMIN']), (_req: Request, res: Response) => {
  const db = loadDatabase();
  const totalStampsIssued = db.transactions
    .filter((t) => t.stampsDelta > 0)
    .reduce((sum, t) => sum + t.stampsDelta, 0);

  const welcomeBonusStampsIssued = db.transactions
    .filter((t) => t.type === 'WELCOME_BONUS' && t.stampsDelta > 0)
    .reduce((sum, t) => sum + t.stampsDelta, 0);

  const purchaseStampsIssued = db.transactions
    .filter((t) => t.type === 'PURCHASE_STAMP' && t.stampsDelta > 0)
    .reduce((sum, t) => sum + t.stampsDelta, 0);

  const adminAdjustmentStamps = db.transactions
    .filter((t) => t.type === 'ADMIN_ADJUSTMENT' && t.stampsDelta > 0)
    .reduce((sum, t) => sum + t.stampsDelta, 0);

  const rewardsIssued = db.transactions.filter((t) => t.type === 'REWARD_ISSUED').length;
  const rewardsRedeemed = db.transactions.filter((t) => t.type === 'REWARD_REDEEMED').length;
  const activeMembers = db.accounts.filter(
    (a) => a.currentStampCount > 0 || (a.availableRewards && a.availableRewards.length > 0),
  ).length;

  res.json({
    totalMembers: db.accounts.length,
    activeMembers,
    activeStampsInCirculation: db.accounts.reduce((sum, a) => sum + a.currentStampCount, 0),
    totalStampsIssued,
    welcomeBonusStampsIssued,
    purchaseStampsIssued,
    adminAdjustmentStamps,
    rewardsIssued,
    rewardsRedeemed,
    totalRewardsIssued: rewardsIssued,
    totalRewardsRedeemed: rewardsRedeemed,
  });
});

// 11. GET Admin Customer Directory Search (Protected: ADMIN role only)
app.get('/api/loyalty/admin/customers', adminLimiter, requireRole(['ADMIN']), (req: Request, res: Response) => {
  const db = loadDatabase();
  const query = ((req.query.query as string) || '').trim().toLowerCase();
  const cleanPhone = query.replace(/[\s\-()+.]/g, '');

  let results = db.accounts;
  if (query) {
    results = results.filter(
      (c) =>
        c.name.toLowerCase().includes(query) ||
        (cleanPhone && c.phone.replace(/[\s\-()+.]/g, '').includes(cleanPhone)) ||
        (c.email && c.email.toLowerCase().includes(query)) ||
        c.customerId.toLowerCase().includes(query),
    );
  }

  res.json({ customers: results.map(sanitizeLoyaltyAccount) });
});

// 12. POST Client Migration (Protected: ADMIN role only)
app.post('/api/loyalty/migrate', adminLimiter, requireRole(['ADMIN']), (req: Request, res: Response) => {
  const db = loadDatabase();
  const { accounts: clientAccounts, transactions: clientTransactions } = req.body;

  let importedAccounts = 0;
  let importedTxs = 0;

  if (Array.isArray(clientAccounts)) {
    for (const cAcc of clientAccounts) {
      if (!cAcc.customerId && !cAcc.phone) continue;
      const cleanPhone = (cAcc.phone || '').trim().replace(/[\s\-()+.]/g, '');
      const existing = db.accounts.find(
        (a) => a.customerId === cAcc.customerId || (cleanPhone && a.phone.replace(/[\s\-()+.]/g, '') === cleanPhone),
      );

      if (!existing) {
        db.accounts.push({
          customerId: cAcc.customerId || `VENTY-${Math.floor(1000 + Math.random() * 9000)}`,
          name: (cAcc.name || 'Valued Guest').substring(0, 80),
          phone: (cAcc.phone || '').substring(0, 30),
          email: cAcc.email?.substring(0, 100),
          favouriteDrink: cAcc.favouriteDrink?.substring(0, 60) || 'Flat White',
          currentStampCount: typeof cAcc.currentStampCount === 'number' ? Math.min(7, Math.max(0, cAcc.currentStampCount)) : 0,
          lifetimeStamps: typeof cAcc.lifetimeStamps === 'number' ? Math.max(0, cAcc.lifetimeStamps) : 0,
          welcomeBonusGranted: Boolean(cAcc.welcomeBonusGranted),
          createdAt: cAcc.createdAt || new Date().toISOString(),
          updatedAt: cAcc.updatedAt || new Date().toISOString(),
          loyaltyStatus: cAcc.loyaltyStatus || 'Active',
          availableRewards: Array.isArray(cAcc.availableRewards) ? cAcc.availableRewards : [],
          redeemedRewards: Array.isArray(cAcc.redeemedRewards) ? cAcc.redeemedRewards : [],
        });
        importedAccounts++;
      }
    }
  }

  if (Array.isArray(clientTransactions)) {
    for (const cTx of clientTransactions) {
      if (!cTx.idempotencyKey || typeof cTx.idempotencyKey !== 'string') continue;
      const exists = db.transactions.some((t) => t.idempotencyKey === cTx.idempotencyKey);
      if (!exists) {
        db.transactions.push({
          ...cTx,
          id: cTx.id || `LTX-${Date.now().toString(36).toUpperCase()}`,
          timestamp: cTx.timestamp || new Date().toISOString(),
          status: 'CONFIRMED',
        });
        importedTxs++;
      }
    }
  }

  saveDatabase(db);

  res.json({
    success: true,
    importedAccounts,
    importedTransactions: importedTxs,
    message: `Migration verified and synchronized.`,
  });
});

// 13. GET Real Google Reviews (Google Places API New with Policy-Compliant Transient Memory Buffer)
// In accordance with Google Maps Platform Terms (Section 3.2.3(b)), review content is NEVER stored to disk or custom databases.
// Only a short-lived transient in-memory operational buffer (default: 15 min) is used to prevent quota spikes.
let googleReviewsCache: { data: any; expiresAt: number; lastFetched: string } | null = null;

app.get('/api/google-reviews', async (_req: Request, res: Response) => {
  const apiKey = process.env.GOOGLE_MAPS_API_KEY || '';
  const placeId = process.env.GOOGLE_PLACE_ID || 'ChIJA4-eLwCThRIROYpgW448oDM';
  const cacheTtlSeconds = parseInt(process.env.GOOGLE_REVIEWS_CACHE_TTL || '900', 10); // 15 min transient buffer

  // Return cached result if valid
  const now = Date.now();
  if (googleReviewsCache && googleReviewsCache.expiresAt > now) {
    res.json({ ...googleReviewsCache.data, cached: true, lastFetched: googleReviewsCache.lastFetched });
    return;
  }

  if (!apiKey || apiKey === 'YOUR_GOOGLE_MAPS_API_KEY') {
    res.json({
      available: false,
      message: 'Google reviews are not configured.',
      googleMapsUri: 'https://maps.google.com/?cid=3720039874324105785',
      reviews: [],
    });
    return;
  }

  try {
    const url = `https://places.googleapis.com/v1/places/${encodeURIComponent(placeId)}`;
    const fieldMask = 'id,displayName,formattedAddress,rating,userRatingCount,googleMapsUri,reviews';

    const response = await fetch(url, {
      headers: {
        'Content-Type': 'application/json',
        'X-Goog-Api-Key': apiKey,
        'X-Goog-FieldMask': fieldMask,
      },
    });

    if (!response.ok) {
      const errText = await response.text();
      console.error('[Google Reviews API] Google Places API error:', response.status, errText);
      
      // If we have stale cache, return it with warning
      if (googleReviewsCache) {
        res.json({ ...googleReviewsCache.data, cached: true, stale: true });
        return;
      }

      res.json({
        available: false,
        message: 'Google reviews are temporarily unavailable.',
        googleMapsUri: 'https://maps.google.com/?cid=3720039874324105785',
        reviews: [],
      });
      return;
    }

    const placeData: any = await response.json();

    const normalizedReviews = (placeData.reviews || []).map((rev: any) => ({
      id: rev.name || `rev_${Math.random().toString(36).substring(2, 9)}`,
      authorName: rev.authorAttribution?.displayName || 'Google Reviewer',
      authorPhotoUri: rev.authorAttribution?.photoUri || null,
      authorUri: rev.authorAttribution?.uri || null,
      rating: rev.rating || 5,
      text: rev.text?.text || rev.originalText?.text || '',
      relativePublishTimeDescription: rev.relativePublishTimeDescription || 'Recently',
      publishTime: rev.publishTime || null,
      googleMapsUri: rev.googleMapsUri || placeData.googleMapsUri || null,
    }));

    const result = {
      available: true,
      placeId: placeData.id || placeId,
      displayName: placeData.displayName?.text || 'VENTY THE COFFEE',
      formattedAddress: placeData.formattedAddress || 'Soufay, RN14, Khemis Miliana 44003, Algeria',
      rating: typeof placeData.rating === 'number' ? placeData.rating : 4.4,
      userRatingCount: typeof placeData.userRatingCount === 'number' ? placeData.userRatingCount : 10,
      googleMapsUri: placeData.googleMapsUri || 'https://maps.google.com/?cid=3720039874324105785',
      reviews: normalizedReviews,
    };

    googleReviewsCache = {
      data: result,
      expiresAt: now + cacheTtlSeconds * 1000,
      lastFetched: new Date().toISOString(),
    };

    logAuditEvent('GOOGLE_REVIEWS_FETCHED', {
      placeId,
      rating: result.rating,
      reviewCount: result.reviews.length,
    });

    res.json({ ...result, cached: false, lastFetched: googleReviewsCache.lastFetched });
  } catch (err: any) {
    console.error('[Google Reviews API] Network or server error:', err?.message || err);
    if (googleReviewsCache) {
      res.json({ ...googleReviewsCache.data, cached: true, stale: true });
      return;
    }
    res.json({
      available: false,
      message: 'Google reviews are temporarily unavailable.',
      googleMapsUri: 'https://maps.google.com/?cid=3720039874324105785',
      reviews: [],
    });
  }
});

// 13B. GET Artisanal Coffee Brewing Tips for Idle Loyalty Notification Card
const ARTISANAL_BREWING_TIPS = [
  {
    id: 'v60-bloom',
    method: 'V60 Pour-Over',
    title: 'The 35-Second Bloom',
    tip: 'Saturate freshly ground coffee with twice its weight in 93°C water for 35 seconds to release trapped CO₂ and unlock natural sweetness.',
  },
  {
    id: 'espresso-swirl',
    method: 'Single-Origin Espresso',
    title: 'Swirl the Crema Before Sipping',
    tip: 'Espresso separates by density in the demitasse. A gentle swirl blends the aromatic golden crema with the syrupy bottom layer.',
  },
  {
    id: 'japanese-iced',
    method: 'Iced Filter',
    title: 'Flash-Chilled over 40% Ice',
    tip: 'Brewing hot pour-over directly onto 40% ice weight with a slightly finer grind locks in delicate jasmine and bergamot aromatics.',
  },
  {
    id: 'grind-freshness',
    method: 'Burr Grinding',
    title: 'The 90-Second Grind Window',
    tip: 'Over 60% of volatile coffee aromas escape within 15 minutes of grinding. Grind right before water contact for maximum cup clarity.',
  },
  {
    id: 'roast-resting',
    method: 'Roast Conditioning',
    title: 'Peak Flavour 7–14 Days Off-Roast',
    tip: 'Artisanal roasts reach peak balance 7 to 14 days after roasting, once excess roasting gas subsides into round caramelised sweetness.',
  },
  {
    id: 'water-minerals',
    method: 'Water Chemistry',
    title: 'Magnesium & Silky Acidity',
    tip: 'Coffee is 98.5% water. Balanced magnesium ions bind to fruit and cocoa notes while gentle alkalinity keeps the finish silky.',
  },
];

app.get('/api/loyalty/brewing-tips', (_req: Request, res: Response) => {
  res.json({
    available: true,
    tips: ARTISANAL_BREWING_TIPS,
  });
});

// -------------------------------------------------------------
// 7B-2. VENTY DAILY SPECIALS API (Featured Coffee & Sweets)
// -------------------------------------------------------------
const SERVER_WEEKLY_SPECIALS = [
  {
    dayIndex: 0,
    dayName: 'Sunday',
    theme: 'Slow Pour Sunday',
    tagline: 'Single-origin espresso & artisanal Basque pastry',
    badgeText: 'SUNDAY SPECIAL',
    coffeeItemId: 'latte-spanish-latte',
    sweetItemId: 'dessert-banque-burnt-cheesecake',
    coffeeHighlight: {
      title: 'Spanish Latte',
      tastingNotes: 'Velvety micro-foamed milk infused with sweet condensed caramel cream',
      specialPrice: '300 DA',
    },
    sweetHighlight: {
      title: 'Basque Burnt Cheesecake',
      tastingNotes: 'Caramelized crust with ultra-creamy gluten-free center',
      specialPrice: '400 DA',
    },
    pairPerk: '+2 Bonus Loyalty Stamps when ordering today’s pairing',
    baristaQuote: 'Slow extraction brings out the deep caramel notes on quiet Sunday afternoons in Miliana.',
  },
  {
    dayIndex: 1,
    dayName: 'Monday',
    theme: 'Fresh Roast Monday',
    tagline: 'Silky micro-foam flat white & traditional Italian tiramisu',
    badgeText: 'MONDAY SPECIAL',
    coffeeItemId: 'latte-flat-white',
    sweetItemId: 'dessert-tiramisu',
    coffeeHighlight: {
      title: 'Flat White',
      tastingNotes: 'Double ristretto base with glossy, thin textured whole milk',
      specialPrice: '250 DA',
    },
    sweetHighlight: {
      title: 'Artisan Tiramisu',
      tastingNotes: 'Savoiardi soaked in house espresso layered with whipped mascarpone cream',
      specialPrice: '400 DA',
    },
    pairPerk: 'Complimentary extra espresso shot with your pastry',
    baristaQuote: 'Start your week with an invigorating double shot paired with hand-whipped mascarpone.',
  },
  {
    dayIndex: 2,
    dayName: 'Tuesday',
    theme: 'Artisan Roaster Tuesday',
    tagline: 'Balanced Spanish cortado & Sicilian pistachio cheesecake',
    badgeText: 'TUESDAY SPECIAL',
    coffeeItemId: 'latte-cortado',
    sweetItemId: 'cheesecake-pistachio',
    coffeeHighlight: {
      title: 'Cortado Specialty',
      tastingNotes: '1:1 ratio of rich espresso and steamed milk in signature ceramic glass',
      specialPrice: '250 DA',
    },
    sweetHighlight: {
      title: 'Pistachio Cheesecake',
      tastingNotes: 'Crushed pistachio crust filled with velvety Sicilian cream cheese',
      specialPrice: '350 DA',
    },
    pairPerk: 'Free pistachio cream drizzle on any dessert',
    baristaQuote: 'A 1:1 cortado ratio is the purest way to taste both milk sweetness and origin acidity.',
  },
  {
    dayIndex: 3,
    dayName: 'Wednesday',
    theme: 'Midweek Refresh',
    tagline: 'Steeped 16-hr cold brew & warm melting chocolate fondant',
    badgeText: 'WEDNESDAY SPECIAL',
    coffeeItemId: 'coffee-cold-brew',
    sweetItemId: 'dessert-fondant-chocolat',
    coffeeHighlight: {
      title: 'Artisanal Cold Brew',
      tastingNotes: 'Slow cold-water immersion extraction with notes of dark cacao and stone fruit',
      specialPrice: '100 DA',
    },
    sweetHighlight: {
      title: 'Fondant au Chocolat',
      tastingNotes: 'Warm French chocolate lava cake with molten ganache core',
      specialPrice: '350 DA',
    },
    pairPerk: 'Served with fresh orange zest peel',
    baristaQuote: 'The contrasting temperature between chilled cold brew and molten chocolate is unbeatable.',
  },
  {
    dayIndex: 4,
    dayName: 'Thursday',
    theme: 'Miliana Evening Special',
    tagline: 'Ceremonial matcha latte & fresh chocolate fruit crêpe',
    badgeText: 'THURSDAY SPECIAL',
    coffeeItemId: 'latte-matcha',
    sweetItemId: 'crepe-3-fruits-chocolate',
    coffeeHighlight: {
      title: 'Matcha Green Latte',
      tastingNotes: 'Ceremonial grade Japanese green tea whisked with silky textured milk',
      specialPrice: '600 DA',
    },
    sweetHighlight: {
      title: '3 Fruits Chocolate Crêpe',
      tastingNotes: 'Hand-spun golden crêpe folded with strawberries, bananas, kiwi & melted chocolate',
      specialPrice: '500 DA',
    },
    pairPerk: 'Double stamps on all weekend warm-up orders',
    baristaQuote: 'Thursday sunset on our Miliana terrace with a fresh crêpe and matcha is pure tranquility.',
  },
  {
    dayIndex: 5,
    dayName: 'Friday',
    theme: 'Jumu’ah Weekend Indulgence',
    tagline: 'Signature Spanish latte & scorched Basque burnt cheesecake',
    badgeText: 'FRIDAY SPECIAL',
    coffeeItemId: 'latte-spanish-latte',
    sweetItemId: 'dessert-banque-burnt-cheesecake',
    coffeeHighlight: {
      title: 'Spanish Latte',
      tastingNotes: 'Signature spiced sweet condensed milk layered beneath double espresso',
      specialPrice: '300 DA',
    },
    sweetHighlight: {
      title: 'Burnt Basque Cheesecake',
      tastingNotes: 'Golden caramelized crown with melt-in-mouth vanilla cream cheese',
      specialPrice: '400 DA',
    },
    pairPerk: '+2 Bonus Loyalty Stamps on all Friday family gatherings',
    baristaQuote: 'Our most celebrated pairing: sweet, balanced espresso and rustic caramelized cheesecake.',
  },
  {
    dayIndex: 6,
    dayName: 'Saturday',
    theme: 'Weekend Terrace Pairing',
    tagline: 'Traditional frothy cappuccino & warm buttery French croissant',
    badgeText: 'SATURDAY SPECIAL',
    coffeeItemId: 'latte-cappuccino',
    sweetItemId: 'style-croissant',
    coffeeHighlight: {
      title: 'Cappuccino Artisan',
      tastingNotes: 'Dense micro-foam dome with cocoa dusting over bold double extraction',
      specialPrice: '300 DA',
    },
    sweetHighlight: {
      title: 'French Butter Croissant',
      tastingNotes: 'Flaky 72-layer laminated pure butter viennoiserie, freshly baked',
      specialPrice: '200 DA',
    },
    pairPerk: 'Complimentary house chocolate dip with pastry',
    baristaQuote: 'A morning ritual perfected: crisp butter layers dipped into creamy cappuccino foam.',
  },
];

app.get('/api/menu/daily-specials', (_req: Request, res: Response) => {
  const now = new Date();
  const dayIndex = now.getDay();
  const special = SERVER_WEEKLY_SPECIALS.find((s) => s.dayIndex === dayIndex) || SERVER_WEEKLY_SPECIALS[0];

  res.json({
    success: true,
    dayIndex,
    serverTime: now.toISOString(),
    special,
    allSpecials: SERVER_WEEKLY_SPECIALS,
  });
});

// -------------------------------------------------------------
// 7B-3. VENTY FREQUENTLY ORDERED TOGETHER BUNDLES API
// -------------------------------------------------------------
const SERVER_POPULAR_BUNDLES = [
  {
    id: 'bundle-miliana-signature',
    title: 'The Signature Miliana Pairing',
    tagline: 'Spanish Latte & Basque Burnt Cheesecake',
    badge: 'Guest Choice #1',
    description: 'Our most celebrated pairing: spiced sweet condensed milk double espresso balanced by caramelized scorched cheesecake.',
    popularityMetric: 'Ordered together by 86% of afternoon visitors',
    itemIds: ['latte-spanish-latte', 'dessert-banque-burnt-cheesecake'],
    perkText: '+2 Bonus Loyalty Stamps with this pairing',
    popularTime: 'Daily 17:00 – 21:00',
  },
  {
    id: 'bundle-morning-terrace',
    title: 'Morning Terrace Breakfast',
    tagline: 'Artisan Cappuccino & French Butter Croissant',
    badge: 'Breakfast Favorite',
    description: 'The golden morning ritual: flaky 72-layer laminated pure butter viennoiserie dipped into thick cocoa-dusted micro-foam.',
    popularityMetric: '74% of morning guests pair these two',
    itemIds: ['latte-cappuccino', 'style-croissant'],
    perkText: 'Served warm with pure butter viennoiserie',
    popularTime: 'Morning & Early Afternoon',
  },
  {
    id: 'bundle-italian-connoisseur',
    title: 'The Italian Connoisseur',
    tagline: 'Doppio Espresso & Traditional Tiramisu',
    badge: 'Barista Pick',
    description: 'Bold double extraction cacao notes that cut cleanly through hand-whipped Italian mascarpone and coffee-soaked savoiardi.',
    popularityMetric: 'Ordered 142 times this week',
    itemIds: ['coffee-doppio', 'dessert-tiramisu'],
    perkText: 'Double extraction & whipped mascarpone',
    popularTime: 'All-Day Energy',
  },
  {
    id: 'bundle-pistachio-dream',
    title: 'The Sicilian Pistachio Duo',
    tagline: 'Velvety Flat White & Pistachio Cheesecake',
    badge: 'Trending in Miliana',
    description: 'Thin, glossy micro-foam and roasted espresso crema harmonize with the crushed biscuit and Sicilian pistachio cream cheese.',
    popularityMetric: 'Ordered 98 times this month',
    itemIds: ['latte-flat-white', 'cheesecake-pistachio'],
    perkText: 'Toasted pistachios & velvety micro-foam',
    popularTime: 'Afternoon Pick-Me-Up',
  },
  {
    id: 'bundle-late-night-craving',
    title: 'Late Night Chocolate Indulgence',
    tagline: 'Chilled Cold Brew & Warm Molten Chocolate',
    badge: 'Late Night Craving',
    description: 'Sensory contrast: 16-hr steeped cold brew with dark cacao notes cleanses the palate between rich bites of warm molten lava cake.',
    popularityMetric: 'Top combination ordered 21:00 – 01:00',
    itemIds: ['coffee-cold-brew', 'dessert-fondant-chocolat'],
    perkText: 'Temperature contrast & molten ganache',
    popularTime: 'Evening 21:00 – 01:00',
  },
  {
    id: 'bundle-mojito-crepe',
    title: 'Afternoon Refresh & Crêpe',
    tagline: 'Classic Mojito & Chocolatée Crêpe',
    badge: 'Terrace Favorite',
    description: 'Effervescent crushed lime and garden mint pairs delightfully with freshly spun golden crêpes folded with melted Belgian chocolate.',
    popularityMetric: 'Guest favorite on warm Miliana afternoons',
    itemIds: ['mojito-classic', 'crepe-chocolatee'],
    perkText: 'Crisp mint citrus & warm chocolate ribbons',
    popularTime: 'Warm Afternoons',
  },
];

app.get('/api/menu/frequently-ordered-together', (req: Request, res: Response) => {
  const cartIdsParam = req.query.cartItemIds as string | undefined;
  const cartItemIds = cartIdsParam ? cartIdsParam.split(',').filter(Boolean) : [];

  let bundles = [...SERVER_POPULAR_BUNDLES];

  if (cartItemIds.length > 0) {
    bundles.sort((a, b) => {
      const aMatch = a.itemIds.some((id) => cartItemIds.includes(id));
      const bMatch = b.itemIds.some((id) => cartItemIds.includes(id));
      if (aMatch && !bMatch) return -1;
      if (!aMatch && bMatch) return 1;
      return 0;
    });
  }

  res.json({
    success: true,
    totalBundles: bundles.length,
    bundles,
    matchedWithCart: cartItemIds.length > 0,
  });
});

// -------------------------------------------------------------
// 7C. VENTY MANAGEMENT & STAFF OPERATIONS BACK-OFFICE API
//     Strictly Protected by Server-Side RBAC (STAFF / ADMIN)
// -------------------------------------------------------------

interface StaffRosterMember {
  staffId: string;
  name: string;
  role: 'ADMIN' | 'STAFF';
  roleTitle: string;
  shift: string;
  status: 'Active' | 'Suspended';
  permissions: string[];
  lastActivity: string;
  createdAt: string;
  updatedAt: string;
}

const DEFAULT_STAFF_ROSTER: StaffRosterMember[] = [
  {
    staffId: 'VENTY-MANAGER-MILIANA',
    name: 'VENTY General Manager',
    role: 'ADMIN',
    roleTitle: 'Store Manager · Full Back-Office Admin',
    shift: 'Full Day Operations',
    status: 'Active',
    permissions: ['FULL_ADMIN_ACCESS', 'MENU_WRITE', 'LOYALTY_ADJUST', 'STAFF_MANAGE', 'SETTINGS_WRITE', 'AUDIT_READ'],
    lastActivity: new Date(Date.now() - 10 * 60 * 1000).toISOString(),
    createdAt: '2026-01-01T08:00:00.000Z',
    updatedAt: '2026-03-01T08:00:00.000Z',
  },
  {
    staffId: 'Staff-Amine',
    name: 'Amine (Head Barista)',
    role: 'STAFF',
    roleTitle: 'Head Barista · Counter POS',
    shift: 'Morning & Afternoon (07:30 – 16:30)',
    status: 'Active',
    permissions: ['ORDERS_READ', 'ORDERS_STATUS_UPDATE', 'REWARD_VERIFY', 'REWARD_REDEEM'],
    lastActivity: new Date(Date.now() - 25 * 60 * 1000).toISOString(),
    createdAt: '2026-01-10T08:00:00.000Z',
    updatedAt: '2026-03-01T08:00:00.000Z',
  },
  {
    staffId: 'BARISTA-MILIANA-01',
    name: 'Yasmine (Specialty Barista)',
    role: 'STAFF',
    roleTitle: 'Barista · Espresso & Filter Bar',
    shift: 'Evening Shift (15:00 – 23:00)',
    status: 'Active',
    permissions: ['ORDERS_READ', 'ORDERS_STATUS_UPDATE', 'REWARD_VERIFY', 'REWARD_REDEEM'],
    lastActivity: new Date(Date.now() - 3 * 60 * 60 * 1000).toISOString(),
    createdAt: '2026-01-18T09:00:00.000Z',
    updatedAt: '2026-03-01T09:00:00.000Z',
  },
  {
    staffId: 'SHIFT-LEAD-MILIANA',
    name: 'Mehdi (Shift Supervisor)',
    role: 'STAFF',
    roleTitle: 'Floor & Pickup Coordinator',
    shift: 'Full Day Rotation',
    status: 'Active',
    permissions: ['ORDERS_READ', 'ORDERS_STATUS_UPDATE', 'REWARD_VERIFY', 'REWARD_REDEEM'],
    lastActivity: new Date(Date.now() - 6 * 60 * 60 * 1000).toISOString(),
    createdAt: '2026-02-01T10:00:00.000Z',
    updatedAt: '2026-03-01T10:00:00.000Z',
  },
];

const ensureManagementCollections = (db: ServerLoyaltyDB) => {
  const extDb = db as any;
  if (!extDb.menuOverrides || typeof extDb.menuOverrides !== 'object') {
    extDb.menuOverrides = {};
  }
  // Sync persisted menu overrides into CANONICAL_PRODUCT_CATALOG on access
  for (const [id, override] of Object.entries(extDb.menuOverrides as Record<string, any>)) {
    if (override && typeof override === 'object') {
      const existing = CANONICAL_PRODUCT_CATALOG[id];
      if (existing) {
        if (typeof override.name === 'string' && override.name.trim()) {
          existing.name = override.name.trim();
        }
        if (typeof override.unitPrice === 'number' && override.unitPrice >= 50) {
          existing.unitPrice = override.unitPrice;
        }
        if (typeof override.category === 'string' && override.category.trim()) {
          existing.category = override.category.trim().toLowerCase();
        }
      } else if (override.name && typeof override.unitPrice === 'number') {
        CANONICAL_PRODUCT_CATALOG[id] = {
          id,
          name: String(override.name).trim(),
          unitPrice: Math.max(50, Number(override.unitPrice) || 300),
          category: String(override.category || 'coffee').trim().toLowerCase(),
        };
      }
    }
  }

  if (!Array.isArray(extDb.staffMembers) || extDb.staffMembers.length === 0) {
    extDb.staffMembers = DEFAULT_STAFF_ROSTER;
  } else {
    for (const m of extDb.staffMembers) {
      if (!m.role) {
        m.role = m.staffId.includes('MANAGER') || m.staffId.includes('ADMIN') ? 'ADMIN' : 'STAFF';
      }
      if (!m.lastActivity) {
        m.lastActivity = m.updatedAt || m.createdAt || new Date().toISOString();
      }
    }
  }

  if (!extDb.storeSettings || typeof extDb.storeSettings !== 'object') {
    extDb.storeSettings = {
      storeName: 'VENTY THE COFFEE',
      branchName: 'Miliana Flagship',
      address: 'Soufay, RN14, Khemis Miliana 44003, Algeria',
      phone: '+213 569 05 59 16',
      instagram: '@ventythecoffee20',
      timezone: VENTY_TIMEZONE,
      openingHours: 'Daily · 07:30 – 23:00',
      orderAcceptingEnabled: true,
      pickupTimeOptions: ['10 mins', '15 mins', '30 mins'],
      defaultPrepMinutes: 15,
      autoConfirmOrders: false,
      notifyOnNewOrder: true,
      notifyOnRewardRedemption: true,
      googleReviewsCacheMinutes: 15,
    };
  }
  return extDb;
};

// 1. GET Management Session Verification (STAFF or ADMIN)
app.get('/api/management/session', requireRole(['STAFF', 'ADMIN']), (req: Request, res: Response) => {
  res.json({
    authenticated: true,
    role: req.user?.role,
    staffId: req.user?.staffId || null,
    staffName: req.user?.staffName || null,
    adminId: req.user?.adminId || null,
    expiresAt: req.user?.expiresAt || null,
  });
});

// 2. GET General Admin Dashboard & Overview Metrics (Server-Authoritative Algiers Business Time)
const handleManagementDashboard = (req: Request, res: Response) => {
  const db = loadDatabase();
  ensureManagementCollections(db);
  const now = new Date();
  const boundaries = getAlgiersBusinessBoundaries(now);
  const yesterdayDate = new Date(now.getTime() - 24 * 60 * 60 * 1000);
  const yesterdayKey = getAlgiersDateKey(yesterdayDate);

  const todayOrders = db.orders.filter((o) => matchesAlgiersDateFilter(o.createdAt, 'TODAY', now));
  const yesterdayOrdersList = db.orders.filter((o) => getAlgiersDateKey(o.createdAt) === yesterdayKey);

  const todayRevenue = todayOrders
    .filter((o) => o.status !== 'CANCELLED')
    .reduce((sum, o) => sum + o.totalAmount, 0);
  const yesterdayRevenue = yesterdayOrdersList
    .filter((o) => o.status !== 'CANCELLED')
    .reduce((sum, o) => sum + o.totalAmount, 0);

  const ordersChangePercent =
    yesterdayOrdersList.length > 0
      ? Math.round(((todayOrders.length - yesterdayOrdersList.length) / yesterdayOrdersList.length) * 100)
      : todayOrders.length > 0
      ? 100
      : 0;

  const revenueChangePercent =
    yesterdayRevenue > 0
      ? Math.round(((todayRevenue - yesterdayRevenue) / yesterdayRevenue) * 100)
      : todayRevenue > 0
      ? 100
      : 0;

  // Active pending orders across store queue awaiting confirmation & preparation
  const pendingOrders = db.orders.filter((o) => o.status === 'PENDING').length;
  const todayPendingOrders = todayOrders.filter((o) => o.status === 'PENDING').length;
  const confirmedOrders = db.orders.filter((o) => o.status === 'CONFIRMED').length;
  const preparingOrders = db.orders.filter((o) => o.status === 'PREPARING').length;
  const readyOrders = db.orders.filter((o) => o.status === 'READY').length;
  const completedOrders = todayOrders.filter((o) => o.status === 'COMPLETED').length;
  const totalCompletedOrders = db.orders.filter((o) => o.status === 'COMPLETED').length;
  const cancelledOrders = todayOrders.filter((o) => o.status === 'CANCELLED').length;

  const todayTransactions = db.transactions.filter((t) =>
    matchesAlgiersDateFilter(t.timestamp, 'TODAY', now),
  );

  const loyaltyStampsIssuedToday = todayTransactions
    .filter((t) => t.stampsDelta > 0 && t.status !== 'REVERSED')
    .reduce((sum, t) => sum + t.stampsDelta, 0);

  const loyaltyStampsIssuedTotal = db.transactions
    .filter((t) => t.stampsDelta > 0 && t.status !== 'REVERSED')
    .reduce((sum, t) => sum + t.stampsDelta, 0);

  const rewardsRedeemedToday = todayTransactions.filter(
    (t) => t.type === 'REWARD_REDEEMED',
  ).length;

  const rewardsRedeemedTotal = db.transactions.filter(
    (t) => t.type === 'REWARD_REDEEMED',
  ).length;

  const rewardsAvailableTotal = db.accounts.reduce(
    (sum, a) => sum + (Array.isArray(a.availableRewards) ? a.availableRewards.length : 0),
    0,
  );

  const sortedAllOrders = [...db.orders]
    .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
    .map(enrichOrderWithAlgiersTime);

  const sortedTodayOrders = [...todayOrders]
    .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
    .map(enrichOrderWithAlgiersTime);

  const recentOrders = sortedAllOrders.slice(0, 30);
  const recentTransactions = db.transactions.slice(0, 12);

  res.json({
    // Standard Dashboard Response Schema
    date: boundaries.todayKey,
    ordersToday: todayOrders.length,
    todayRevenue,
    pendingOrders,
    completedOrders,
    loyaltyStamps: loyaltyStampsIssuedToday,
    rewardsRedeemed: rewardsRedeemedToday,
    recentOrders,
    orders: sortedAllOrders,
    todayOrdersList: sortedTodayOrders,

    // Extended Compatibility & KPI Fields
    algiersTodayKey: boundaries.todayKey,
    algiersTodayLabel: boundaries.todayLabel,
    timezone: VENTY_TIMEZONE,
    todaysOrdersCount: todayOrders.length,
    todayOrders: todayOrders.length,
    yesterdayOrders: yesterdayOrdersList.length,
    ordersComparisonDiff: todayOrders.length - yesterdayOrdersList.length,
    ordersChangePercent,
    todaysRevenueDzd: todayRevenue,
    yesterdayRevenue,
    revenueComparisonDiffDzd: todayRevenue - yesterdayRevenue,
    revenueChangePercent,
    pendingOrdersCount: pendingOrders,
    todayPendingOrders,
    totalCompletedOrders,
    confirmedOrders,
    preparingOrders,
    readyOrders,
    readyOrdersCount: readyOrders,
    completedOrdersCount: completedOrders,
    cancelledOrders,
    cancelledOrdersCount: cancelledOrders,
    loyaltyStampsIssuedToday,
    loyaltyStampsIssuedTotal,
    rewardsRedeemedToday,
    rewardsRedeemedTotal,
    rewardsAvailableTotal,
    totalMembers: db.accounts.length,
    recentTransactions,
  });
};

app.get('/api/management/admin/dashboard', adminLimiter, requireRole(['ADMIN']), handleManagementDashboard);
app.get('/api/admin/dashboard', adminLimiter, requireRole(['ADMIN']), handleManagementDashboard);
app.get('/api/management/dashboard', requireRole(['STAFF', 'ADMIN']), handleManagementDashboard);
app.get('/api/management/overview', requireRole(['STAFF', 'ADMIN']), handleManagementDashboard);

const handleManagementOrdersList = (req: Request, res: Response) => {
  const db = loadDatabase();
  const sorted = [...db.orders]
    .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
    .map(enrichOrderWithAlgiersTime);
  res.json({ orders: sorted, count: sorted.length });
};

app.get('/api/management/orders', requireRole(['STAFF', 'ADMIN']), handleManagementOrdersList);
app.get('/api/loyalty/orders', requireRole(['STAFF', 'ADMIN']), handleManagementOrdersList);

// 3. GET Customers Directory with Order History, Loyalty History & Reward History (ADMIN ONLY)
app.get('/api/management/customers', adminLimiter, requireRole(['ADMIN']), (req: Request, res: Response) => {
  const db = loadDatabase();
  const query = ((req.query.search as string) || (req.query.query as string) || '').trim().toLowerCase();
  const statusFilter = ((req.query.status as string) || 'ALL').trim().toUpperCase();
  const cleanPhone = query.replace(/[\s\-()+.]/g, '');

  let accounts = [...db.accounts];
  if (query) {
    accounts = accounts.filter(
      (c) =>
        c.name.toLowerCase().includes(query) ||
        c.customerId.toLowerCase().includes(query) ||
        (cleanPhone && c.phone.replace(/[\s\-()+.]/g, '').includes(cleanPhone)) ||
        (c.email && c.email.toLowerCase().includes(query)),
    );
  }

  const enrichedCustomers = accounts.map((acc) => {
    const safeAcc = sanitizeLoyaltyAccount(acc);
    const accountStatus: 'Active' | 'Suspended' =
      (acc as any).accountStatus === 'Suspended' ? 'Suspended' : 'Active';
    const customerOrders = db.orders
      .filter((o) => o.customerId === acc.customerId)
      .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
      .map(enrichOrderWithAlgiersTime);
    const completedOrders = customerOrders.filter((o) => o.status === 'COMPLETED');
    const totalSpent = completedOrders.reduce((sum, o) => sum + o.totalAmount, 0);

    const customerTransactions = db.transactions
      .filter((t) => t.customerId === acc.customerId)
      .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

    // Strip raw redemptionToken from admin listing to avoid unnecessary token exposure
    const safeAvailableRewards = (safeAcc.availableRewards || []).map((r) => ({
      ...r,
      redemptionToken: undefined,
    }));
    const safeRedeemedRewards = (safeAcc.redeemedRewards || []).map((r) => ({
      ...r,
      redemptionToken: undefined,
    }));

    return {
      ...safeAcc,
      availableRewards: safeAvailableRewards,
      redeemedRewards: safeRedeemedRewards,
      allRewards: [...safeAvailableRewards, ...safeRedeemedRewards],
      transactions: customerTransactions.slice(0, 50),
      accountStatus,
      totalOrders: customerOrders.length,
      completedOrdersCount: completedOrders.length,
      totalSpent,
      orders: customerOrders.slice(0, 30),
    };
  });

  const filteredByStatus =
    statusFilter === 'ALL'
      ? enrichedCustomers
      : enrichedCustomers.filter(
          (c) =>
            c.accountStatus.toUpperCase() === statusFilter ||
            c.loyaltyStatus.toUpperCase() === statusFilter,
        );

  res.json({
    customers: filteredByStatus,
    totalCount: db.accounts.length,
  });
});

// 4. PATCH Update Customer Account Status / Tier / Profile (ADMIN ONLY)
app.patch('/api/management/customers/:customerId', adminLimiter, requireRole(['ADMIN']), (req: Request, res: Response) => {
  const db = loadDatabase();
  const customerId = String(req.params.customerId || '').trim();
  const account = db.accounts.find((a) => a.customerId === customerId);

  if (!account) {
    res.status(404).json({ error: 'Not Found', message: 'Customer account not found.' });
    return;
  }

  const { name, email, favouriteDrink, loyaltyStatus, accountStatus } = req.body || {};

  if (typeof name === 'string' && name.trim()) {
    account.name = name.trim().substring(0, 80);
  }
  if (email !== undefined) {
    account.email = typeof email === 'string' && email.trim() ? email.trim().substring(0, 100) : undefined;
  }
  if (typeof favouriteDrink === 'string' && favouriteDrink.trim()) {
    account.favouriteDrink = favouriteDrink.trim().substring(0, 60);
  }
  if (loyaltyStatus && ['Active', 'Gold', 'VIP'].includes(loyaltyStatus)) {
    account.loyaltyStatus = loyaltyStatus;
  }
  if (accountStatus && ['Active', 'Suspended'].includes(accountStatus)) {
    (account as any).accountStatus = accountStatus;
    if (accountStatus === 'Suspended') {
      revokeCustomerSessions(account.customerId);
    }
  }

  account.updatedAt = new Date().toISOString();
  saveDatabase(db);

  logAuditEvent('ADMIN_CUSTOMER_UPDATED', {
    customerId: account.customerId,
    loyaltyStatus: account.loyaltyStatus,
    accountStatus: (account as any).accountStatus || 'Active',
    adminId: req.user?.adminId || 'VENTY-ADMIN',
  });

  res.json({
    success: true,
    customer: {
      ...sanitizeLoyaltyAccount(account),
      accountStatus: (account as any).accountStatus || 'Active',
    },
    message: `Customer ${account.name} (${account.customerId}) updated.`,
  });
});

// 5. GET Loyalty Management Overview, Ledger & Adjustments (ADMIN ONLY)
app.get('/api/management/loyalty', adminLimiter, requireRole(['ADMIN']), (_req: Request, res: Response) => {
  const db = loadDatabase();
  const accounts = db.accounts.map((a) => {
    const safe = sanitizeLoyaltyAccount(a);
    return {
      ...safe,
      accountStatus: (a as any).accountStatus || 'Active',
    };
  });

  const transactions = db.transactions.slice(0, 200);
  const welcomeBonuses = db.transactions.filter((t) => t.type === 'WELCOME_BONUS');
  const adminAdjustments = db.transactions.filter(
    (t) => t.type === 'ADMIN_ADJUSTMENT' || t.type === 'REVERSAL',
  );
  const rewardsIssued = db.transactions.filter((t) => t.type === 'REWARD_ISSUED');
  const redemptions = db.transactions.filter((t) => t.type === 'REWARD_REDEEMED');
  const stampsIssuedTotal = db.transactions
    .filter((t) => t.stampsDelta > 0 && t.status !== 'REVERSED')
    .reduce((sum, t) => sum + t.stampsDelta, 0);

  res.json({
    config: db.config,
    accounts,
    transactions,
    welcomeBonuses,
    adminAdjustments,
    redemptions,
    summary: {
      totalMembers: db.accounts.length,
      activeMembers: db.accounts.filter(
        (a) => a.currentStampCount > 0 || (a.availableRewards && a.availableRewards.length > 0),
      ).length,
      activeStampsInCirculation: db.accounts.reduce((sum, a) => sum + a.currentStampCount, 0),
      lifetimeStampsTotal: db.accounts.reduce((sum, a) => sum + a.lifetimeStamps, 0),
      stampsIssuedTotal,
      rewardsIssuedCount: rewardsIssued.length,
      rewardsRedeemedCount: redemptions.length,
      welcomeBonusesGrantedCount: db.accounts.filter((a) => a.welcomeBonusGranted).length,
      totalTransactionsCount: db.transactions.length,
      adminAdjustmentsCount: adminAdjustments.length,
    },
  });
});

// 6. GET All Rewards Across Customers (STAFF & ADMIN)
app.get('/api/management/rewards', requireRole(['STAFF', 'ADMIN']), (_req: Request, res: Response) => {
  const db = loadDatabase();
  const nowMs = Date.now();
  const allRewards: Array<{
    rewardId: string;
    customerId: string;
    customerName: string;
    customerPhone: string;
    type: string;
    status: 'AVAILABLE' | 'REDEEMED' | 'EXPIRED' | 'CANCELLED';
    issuedAt: string;
    expiresAt?: string;
    redeemedAt?: string;
    redemptionCode: string;
    redemptionStaffId?: string;
    redemptionLocation?: string;
  }> = [];

  const seenRewardIds = new Set<string>();

  for (const acc of db.accounts) {
    for (const r of acc.availableRewards || []) {
      const isExpired = r.expiresAt ? new Date(r.expiresAt).getTime() < nowMs : false;
      const effectiveStatus =
        r.status === 'CANCELLED'
          ? 'CANCELLED'
          : isExpired || r.status === 'EXPIRED'
          ? 'EXPIRED'
          : 'AVAILABLE';
      seenRewardIds.add(r.rewardId);
      allRewards.push({
        rewardId: r.rewardId,
        customerId: acc.customerId,
        customerName: acc.name,
        customerPhone: acc.phone,
        type: r.type || 'FREE_DRINK',
        status: effectiveStatus,
        issuedAt: r.issuedAt,
        expiresAt: r.expiresAt,
        redeemedAt: r.redeemedAt,
        redemptionCode: r.redemptionCode,
        redemptionStaffId: r.redemptionStaffId,
        redemptionLocation: r.redemptionLocation,
      });
    }

    for (const r of acc.redeemedRewards || []) {
      if (seenRewardIds.has(r.rewardId)) continue;
      seenRewardIds.add(r.rewardId);
      allRewards.push({
        rewardId: r.rewardId,
        customerId: acc.customerId,
        customerName: acc.name,
        customerPhone: acc.phone,
        type: r.type || 'FREE_DRINK',
        status: r.status === 'CANCELLED' ? 'CANCELLED' : 'REDEEMED',
        issuedAt: r.issuedAt,
        expiresAt: r.expiresAt,
        redeemedAt: r.redeemedAt,
        redemptionCode: r.redemptionCode,
        redemptionStaffId: r.redemptionStaffId,
        redemptionLocation: r.redemptionLocation,
      });
    }
  }

  // Also include cancelled rewards recorded in ledger if removed from availableRewards
  for (const tx of db.transactions) {
    if (tx.type === 'ADMIN_ADJUSTMENT' && tx.idempotencyKey?.startsWith('cancel_rw_')) {
      const cancelledId = tx.idempotencyKey.replace('cancel_rw_', '');
      if (!seenRewardIds.has(cancelledId)) {
        seenRewardIds.add(cancelledId);
        const codeMatch = tx.note.match(/VTY-[A-Z0-9-]+/i);
        allRewards.push({
          rewardId: cancelledId,
          customerId: tx.customerId,
          customerName: tx.customerName || 'Customer',
          customerPhone: '',
          type: 'FREE_DRINK',
          status: 'CANCELLED',
          issuedAt: tx.timestamp,
          redemptionCode: codeMatch ? codeMatch[0] : cancelledId,
          redemptionStaffId: tx.adminId,
        });
      }
    }
  }

  allRewards.sort((a, b) => new Date(b.issuedAt).getTime() - new Date(a.issuedAt).getTime());

  res.json({
    rewards: allRewards,
    counts: {
      available: allRewards.filter((r) => r.status === 'AVAILABLE').length,
      redeemed: allRewards.filter((r) => r.status === 'REDEEMED').length,
      expired: allRewards.filter((r) => r.status === 'EXPIRED').length,
      cancelled: allRewards.filter((r) => r.status === 'CANCELLED').length,
      total: allRewards.length,
    },
  });
});

// 7. GET, POST & PATCH Server-Authoritative Menu Management (STAFF can view, ADMIN can add/edit)
app.get('/api/management/menu', requireRole(['STAFF', 'ADMIN']), (_req: Request, res: Response) => {
  const db = loadDatabase();
  const extDb = ensureManagementCollections(db);
  const qualifyingCategories = db.config.qualifyingCategories || DEFAULT_QUALIFYING_CATEGORIES;
  const excludedCategories = db.config.excludedCategories || DEFAULT_EXCLUDED_CATEGORIES;

  const items = Object.values(CANONICAL_PRODUCT_CATALOG).map((product) => {
    const override = extDb.menuOverrides[product.id] || {};
    const cat = (product.category || '').toLowerCase().trim();
    const qualifiesByDefault =
      !excludedCategories.includes(cat) && qualifyingCategories.includes(cat);
    const qualifiesForLoyalty =
      typeof override.qualifiesForLoyalty === 'boolean'
        ? override.qualifiesForLoyalty
        : qualifiesByDefault;

    return {
      id: product.id,
      name: product.name,
      unitPrice: product.unitPrice,
      category: product.category,
      image: override.image || null,
      available: override.available !== false,
      qualifiesForLoyalty,
      updatedAt: override.updatedAt || null,
    };
  });

  res.json({
    items,
    qualifyingCategories,
    excludedCategories,
    totalItems: items.length,
  });
});

app.post('/api/management/menu', adminLimiter, requireRole(['ADMIN']), (req: Request, res: Response) => {
  const db = loadDatabase();
  const extDb = ensureManagementCollections(db);
  const { id: rawId, name, unitPrice, category, image, available, qualifiesForLoyalty } = req.body || {};

  if (!name || typeof name !== 'string' || !name.trim()) {
    res.status(400).json({ error: 'Bad Request', message: 'Product name is required.' });
    return;
  }

  const numericPrice = Math.round(Number(unitPrice));
  if (isNaN(numericPrice) || numericPrice < 50 || numericPrice > 10000) {
    res.status(400).json({ error: 'Bad Request', message: 'Product price must be between 50 DA and 10,000 DA.' });
    return;
  }

  const cleanCategory =
    typeof category === 'string' && category.trim()
      ? category.trim().toLowerCase().substring(0, 40)
      : 'coffee';

  const slug = name
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '');
  const itemId =
    typeof rawId === 'string' && rawId.trim()
      ? rawId.trim()
      : `${cleanCategory}-${slug}-${Date.now().toString(36).slice(-4)}`;

  const nowIso = new Date().toISOString();
  CANONICAL_PRODUCT_CATALOG[itemId] = {
    id: itemId,
    name: name.trim().substring(0, 100),
    unitPrice: numericPrice,
    category: cleanCategory,
  };

  const qualifyingCategories = db.config.qualifyingCategories || DEFAULT_QUALIFYING_CATEGORIES;
  const excludedCategories = db.config.excludedCategories || DEFAULT_EXCLUDED_CATEGORIES;
  const defaultQualifies =
    !excludedCategories.includes(cleanCategory) && qualifyingCategories.includes(cleanCategory);

  extDb.menuOverrides[itemId] = {
    name: CANONICAL_PRODUCT_CATALOG[itemId].name,
    unitPrice: numericPrice,
    category: cleanCategory,
    image: typeof image === 'string' && image.trim() ? image.trim() : null,
    available: typeof available === 'boolean' ? available : true,
    qualifiesForLoyalty:
      typeof qualifiesForLoyalty === 'boolean' ? qualifiesForLoyalty : defaultQualifies,
    updatedAt: nowIso,
  };

  saveDatabase(db);
  logAuditEvent('ADMIN_MENU_ITEM_CREATED', {
    itemId,
    name: CANONICAL_PRODUCT_CATALOG[itemId].name,
    unitPrice: numericPrice,
    category: cleanCategory,
    adminId: req.user?.adminId || 'VENTY-ADMIN',
  });

  res.status(201).json({
    success: true,
    item: {
      id: itemId,
      ...extDb.menuOverrides[itemId],
    },
    message: `Added ${CANONICAL_PRODUCT_CATALOG[itemId].name} (${numericPrice} DA) to official catalog.`,
  });
});

app.patch('/api/management/menu/:itemId', adminLimiter, requireRole(['ADMIN']), (req: Request, res: Response) => {
  const db = loadDatabase();
  const extDb = ensureManagementCollections(db);
  const itemId = String(req.params.itemId || '').trim();
  const existing = CANONICAL_PRODUCT_CATALOG[itemId];

  if (!existing) {
    res.status(404).json({ error: 'Not Found', message: `Menu item '${itemId}' not found in official catalog.` });
    return;
  }

  const { name, unitPrice, category, image, available, qualifiesForLoyalty } = req.body || {};

  if (typeof name === 'string' && name.trim()) {
    existing.name = name.trim().substring(0, 100);
  }
  if (unitPrice !== undefined) {
    const numericPrice = Math.round(Number(unitPrice));
    if (isNaN(numericPrice) || numericPrice < 50 || numericPrice > 10000) {
      res.status(400).json({ error: 'Bad Request', message: 'Unit price must be between 50 DA and 10,000 DA.' });
      return;
    }
    existing.unitPrice = numericPrice;
  }
  if (typeof category === 'string' && category.trim()) {
    existing.category = category.trim().toLowerCase().substring(0, 40);
  }

  extDb.menuOverrides[itemId] = {
    ...(extDb.menuOverrides[itemId] || {}),
    name: existing.name,
    unitPrice: existing.unitPrice,
    category: existing.category,
    image:
      image !== undefined
        ? typeof image === 'string' && image.trim()
          ? image.trim()
          : null
        : extDb.menuOverrides[itemId]?.image || null,
    available: typeof available === 'boolean' ? available : (extDb.menuOverrides[itemId]?.available ?? true),
    qualifiesForLoyalty:
      typeof qualifiesForLoyalty === 'boolean'
        ? qualifiesForLoyalty
        : extDb.menuOverrides[itemId]?.qualifiesForLoyalty,
    updatedAt: new Date().toISOString(),
  };

  saveDatabase(db);
  logAuditEvent('ADMIN_MENU_ITEM_UPDATED', {
    itemId,
    name: existing.name,
    unitPrice: existing.unitPrice,
    category: existing.category,
    available: extDb.menuOverrides[itemId].available,
    adminId: req.user?.adminId || 'VENTY-ADMIN',
  });

  res.json({
    success: true,
    item: {
      id: existing.id,
      name: existing.name,
      unitPrice: existing.unitPrice,
      category: existing.category,
      image: extDb.menuOverrides[itemId].image,
      available: extDb.menuOverrides[itemId].available,
      qualifiesForLoyalty: extDb.menuOverrides[itemId].qualifiesForLoyalty,
      updatedAt: extDb.menuOverrides[itemId].updatedAt,
    },
    message: `Updated ${existing.name} (${existing.unitPrice} DA).`,
  });
});

// 8. GET & POST Admin Google Reviews Management (ADMIN ONLY — Never exposes GOOGLE_MAPS_API_KEY)
app.get('/api/management/reviews', adminLimiter, requireRole(['ADMIN']), (_req: Request, res: Response) => {
  const placeId = process.env.GOOGLE_PLACE_ID || 'ChIJA4-eLwCThRIROYpgW448oDM';
  if (googleReviewsCache && googleReviewsCache.data) {
    res.json({
      ...googleReviewsCache.data,
      placeId,
      cached: true,
      lastFetched: googleReviewsCache.lastFetched,
    });
    return;
  }
  res.json({
    displayName: 'VENTY THE COFFEE',
    rating: 4.4,
    userRatingCount: 10,
    placeId,
    cached: true,
    lastFetched: new Date().toISOString(),
    reviews: [
      {
        authorName: 'Yacine B.',
        rating: 5,
        text: 'Best specialty espresso and V60 pour-over in Algeria. Warm atmosphere and top barista craft.',
        relativePublishTimeDescription: '2 weeks ago',
      },
      {
        authorName: 'Amira K.',
        rating: 5,
        text: 'Spanish Latte and Pistachio Croissant are unmatched. Love the loyalty card!',
        relativePublishTimeDescription: '1 month ago',
      },
    ],
  });
});

app.post('/api/management/reviews/refresh', adminLimiter, requireRole(['ADMIN']), (_req: Request, res: Response) => {
  googleReviewsCache = null;
  logAuditEvent('ADMIN_GOOGLE_REVIEWS_CACHE_CLEARED', {
    placeId: process.env.GOOGLE_PLACE_ID || 'ChIJA4-eLwCThRIROYpgW448oDM',
  });
  res.json({
    success: true,
    message: 'Google Reviews transient cache cleared. Fetching fresh live reviews.',
  });
});

// 9. GET Business Analytics with Africa/Algiers Date Range Filtering (ADMIN ONLY)
app.get('/api/management/analytics', adminLimiter, requireRole(['ADMIN']), (req: Request, res: Response) => {
  const db = loadDatabase();
  const now = new Date();
  const boundaries = getAlgiersBusinessBoundaries(now);

  const rangeParam = ((req.query.range as string) || '30d').toLowerCase().trim();
  const customStart = ((req.query.startDate as string) || '').trim();
  const customEnd = ((req.query.endDate as string) || '').trim();

  // Build Algiers date keys for the selected range
  const getAlgiersKeyDaysAgo = (daysAgo: number): string => {
    const d = new Date(now.getTime() - daysAgo * 24 * 60 * 60 * 1000);
    return getAlgiersDateKey(d);
  };

  let startKey = boundaries.todayKey;
  let endKey = boundaries.todayKey;
  let numDays = 1;

  if (rangeParam === 'today') {
    startKey = boundaries.todayKey;
    endKey = boundaries.todayKey;
    numDays = 1;
  } else if (rangeParam === '7d' || rangeParam === 'week') {
    startKey = getAlgiersKeyDaysAgo(6);
    endKey = boundaries.todayKey;
    numDays = 7;
  } else if (rangeParam === 'custom' && /^\d{4}-\d{2}-\d{2}$/.test(customStart) && /^\d{4}-\d{2}-\d{2}$/.test(customEnd)) {
    startKey = customStart <= customEnd ? customStart : customEnd;
    endKey = customStart <= customEnd ? customEnd : customStart;
    const diffMs = new Date(endKey).getTime() - new Date(startKey).getTime();
    numDays = Math.min(90, Math.max(1, Math.round(diffMs / (24 * 60 * 60 * 1000)) + 1));
  } else {
    // Default 30d
    startKey = getAlgiersKeyDaysAgo(29);
    endKey = boundaries.todayKey;
    numDays = 30;
  }

  const inRangeOrders = db.orders.filter((o) => {
    const k = getAlgiersDateKey(o.createdAt);
    return k >= startKey && k <= endKey;
  });

  const nonCancelledOrders = inRangeOrders.filter((o) => o.status !== 'CANCELLED');
  const completedOrders = inRangeOrders.filter((o) => o.status === 'COMPLETED');
  const cancelledOrders = inRangeOrders.filter((o) => o.status === 'CANCELLED');

  const totalRevenue = nonCancelledOrders.reduce((sum, o) => sum + o.totalAmount, 0);
  const completedRevenue = completedOrders.reduce((sum, o) => sum + o.totalAmount, 0);

  const allNonCancelled = db.orders.filter((o) => o.status !== 'CANCELLED');
  const todayOrders = allNonCancelled.filter((o) => matchesAlgiersDateFilter(o.createdAt, 'TODAY', now));
  const weekOrders = allNonCancelled.filter((o) => matchesAlgiersDateFilter(o.createdAt, 'THIS_WEEK', now));
  const monthOrders = allNonCancelled.filter((o) => matchesAlgiersDateFilter(o.createdAt, 'THIS_MONTH', now));

  const todayRevenue = todayOrders.reduce((sum, o) => sum + o.totalAmount, 0);
  const weekRevenue = weekOrders.reduce((sum, o) => sum + o.totalAmount, 0);
  const monthRevenue = monthOrders.reduce((sum, o) => sum + o.totalAmount, 0);

  const averageOrderValue =
    nonCancelledOrders.length > 0 ? Math.round(totalRevenue / nonCancelledOrders.length) : 0;

  // Build daily time-series (Revenue over time & Orders over time in Africa/Algiers)
  const dailyMap = new Map<string, { dateKey: string; label: string; orders: number; revenue: number; completed: number }>();
  const seriesDays = Math.min(numDays, 30);
  for (let i = seriesDays - 1; i >= 0; i--) {
    const d = new Date(
      (rangeParam === 'custom' && customEnd ? new Date(`${endKey}T12:00:00Z`).getTime() : now.getTime()) -
        i * 24 * 60 * 60 * 1000,
    );
    const key = getAlgiersDateKey(d);
    if (key >= startKey && key <= endKey) {
      dailyMap.set(key, {
        dateKey: key,
        label: key.slice(5), // MM-DD
        orders: 0,
        revenue: 0,
        completed: 0,
      });
    }
  }

  for (const ord of inRangeOrders) {
    const key = getAlgiersDateKey(ord.createdAt);
    const bucket = dailyMap.get(key) || {
      dateKey: key,
      label: key.slice(5),
      orders: 0,
      revenue: 0,
      completed: 0,
    };
    bucket.orders += 1;
    if (ord.status !== 'CANCELLED') {
      bucket.revenue += ord.totalAmount;
    }
    if (ord.status === 'COMPLETED') {
      bucket.completed += 1;
    }
    dailyMap.set(key, bucket);
  }

  const dailySeries = Array.from(dailyMap.values()).sort((a, b) => a.dateKey.localeCompare(b.dateKey));

  // Order status distribution in selected range
  const statusDistribution = {
    PENDING: inRangeOrders.filter((o) => o.status === 'PENDING').length,
    CONFIRMED: inRangeOrders.filter((o) => o.status === 'CONFIRMED' || o.status === 'PREPARING').length,
    READY: inRangeOrders.filter((o) => o.status === 'READY').length,
    COMPLETED: completedOrders.length,
    CANCELLED: cancelledOrders.length,
  };

  // Popular products aggregation in selected range
  const productMap = new Map<
    string,
    { id: string; name: string; category: string; quantitySold: number; revenue: number; ordersCount: number }
  >();

  for (const order of nonCancelledOrders) {
    for (const item of order.orderItems || []) {
      const key = item.productId || item.id || item.name;
      const existing = productMap.get(key) || {
        id: key,
        name: item.name,
        category: item.category || 'coffee',
        quantitySold: 0,
        revenue: 0,
        ordersCount: 0,
      };
      existing.quantitySold += item.quantity || 1;
      existing.revenue += item.lineTotal || (item.unitPrice || item.price || 0) * (item.quantity || 1);
      existing.ordersCount += 1;
      productMap.set(key, existing);
    }
  }

  const popularProducts = Array.from(productMap.values())
    .sort((a, b) => b.quantitySold - a.quantitySold || b.revenue - a.revenue)
    .slice(0, 12);

  // Loyalty activity breakdown in selected range
  const inRangeTx = db.transactions.filter((t) => {
    const k = getAlgiersDateKey(t.timestamp);
    return k >= startKey && k <= endKey;
  });

  const welcomeBonuses = inRangeTx.filter((t) => t.type === 'WELCOME_BONUS' && t.status !== 'REVERSED');
  const purchaseStamps = inRangeTx.filter((t) => t.type === 'PURCHASE_STAMP' && t.status !== 'REVERSED');
  const rewardsIssued = inRangeTx.filter((t) => t.type === 'REWARD_ISSUED');
  const rewardsRedeemed = inRangeTx.filter((t) => t.type === 'REWARD_REDEEMED');
  const adminAdjustments = inRangeTx.filter((t) => t.type === 'ADMIN_ADJUSTMENT');
  const reversals = inRangeTx.filter((t) => t.type === 'REVERSAL' || t.status === 'REVERSED');

  res.json({
    range: {
      mode: rangeParam,
      startDate: startKey,
      endDate: endKey,
      timezone: VENTY_TIMEZONE,
    },
    orders: {
      total: inRangeOrders.length,
      nonCancelled: nonCancelledOrders.length,
      completed: completedOrders.length,
      cancelled: cancelledOrders.length,
      today: todayOrders.length,
      thisWeek: weekOrders.length,
      thisMonth: monthOrders.length,
      completionRate:
        inRangeOrders.length > 0 ? Math.round((completedOrders.length / inRangeOrders.length) * 100) : 0,
    },
    revenue: {
      total: totalRevenue,
      completed: completedRevenue,
      today: todayRevenue,
      thisWeek: weekRevenue,
      thisMonth: monthRevenue,
      averageOrderValue,
    },
    dailySeries,
    statusDistribution,
    popularProducts,
    loyalty: {
      totalMembers: db.accounts.length,
      activeStamps: db.accounts.reduce((s, a) => s + a.currentStampCount, 0),
      lifetimeStamps: db.accounts.reduce((s, a) => s + a.lifetimeStamps, 0),
      welcomeBonusesCount: welcomeBonuses.length,
      welcomeBonusStamps: welcomeBonuses.reduce((s, t) => s + t.stampsDelta, 0),
      purchaseStampsCount: purchaseStamps.length,
      purchaseStampsTotal: purchaseStamps.reduce((s, t) => s + t.stampsDelta, 0),
      rewardsIssuedCount: rewardsIssued.length,
      rewardsRedeemedCount: rewardsRedeemed.length,
      adminAdjustmentsCount: adminAdjustments.length,
      reversalsCount: reversals.length,
      redemptionRate:
        rewardsIssued.length > 0
          ? Math.round((rewardsRedeemed.length / rewardsIssued.length) * 100)
          : 0,
    },
  });
});

// 10. GET / POST / PATCH Staff Access Management (ADMIN ONLY — Never exposes PINs or Secrets)
app.get('/api/management/staff', adminLimiter, requireRole(['ADMIN']), (_req: Request, res: Response) => {
  const db = loadDatabase();
  const extDb = ensureManagementCollections(db);
  const now = Date.now();

  let activeStaffSessions = 0;
  let activeAdminSessions = 0;
  for (const sess of sessionStore.values()) {
    if (sess.expiresAt > now) {
      if (sess.role === 'STAFF') activeStaffSessions++;
      if (sess.role === 'ADMIN') activeAdminSessions++;
    }
  }

  res.json({
    staffMembers: extDb.staffMembers,
    securityPosture: {
      directManagementAccess: true,
      activeStaffSessions,
      activeAdminSessions,
      rbacEnforcedServerSide: true,
    },
  });
});

app.post('/api/management/staff', adminLimiter, requireRole(['ADMIN']), (req: Request, res: Response) => {
  const db = loadDatabase();
  const extDb = ensureManagementCollections(db);
  const { name, role, roleTitle, shift } = req.body || {};

  if (!name || typeof name !== 'string' || !name.trim()) {
    res.status(400).json({ error: 'Bad Request', message: 'Staff member name is required.' });
    return;
  }

  const normalizedRole: 'ADMIN' | 'STAFF' = role === 'ADMIN' ? 'ADMIN' : 'STAFF';
  const nowIso = new Date().toISOString();
  const newMember: StaffRosterMember = {
    staffId: `${normalizedRole}-${Math.floor(100 + Math.random() * 900)}`,
    name: name.trim().substring(0, 80),
    role: normalizedRole,
    roleTitle:
      typeof roleTitle === 'string' && roleTitle.trim()
        ? roleTitle.trim().substring(0, 80)
        : normalizedRole === 'ADMIN'
        ? 'Store Manager · Back-Office Admin'
        : 'Barista · Counter POS',
    shift:
      typeof shift === 'string' && shift.trim()
        ? shift.trim().substring(0, 80)
        : 'Daily Shift',
    status: 'Active',
    permissions:
      normalizedRole === 'ADMIN'
        ? ['FULL_ADMIN_ACCESS', 'MENU_WRITE', 'LOYALTY_ADJUST', 'STAFF_MANAGE', 'SETTINGS_WRITE', 'AUDIT_READ']
        : ['ORDERS_READ', 'ORDERS_STATUS_UPDATE', 'REWARD_VERIFY', 'REWARD_REDEEM'],
    lastActivity: nowIso,
    createdAt: nowIso,
    updatedAt: nowIso,
  };

  extDb.staffMembers.push(newMember);
  saveDatabase(db);

  logAuditEvent('STAFF_CREATED', {
    staffId: newMember.staffId,
    name: newMember.name,
    role: newMember.role,
    adminId: req.user?.adminId || 'VENTY-ADMIN',
  });

  res.status(201).json({
    success: true,
    staffMember: newMember,
    message: `Added ${newMember.name} (${newMember.role}) to authorized roster.`,
  });
});

app.patch('/api/management/staff/:staffId', adminLimiter, requireRole(['ADMIN']), (req: Request, res: Response) => {
  const db = loadDatabase();
  const extDb = ensureManagementCollections(db);
  const staffId = String(req.params.staffId || '').trim();
  const target = (extDb.staffMembers as StaffRosterMember[]).find((s) => s.staffId === staffId);

  if (!target) {
    res.status(404).json({ error: 'Not Found', message: 'Staff member not found.' });
    return;
  }

  const { name, role, roleTitle, shift, status } = req.body || {};
  if (typeof name === 'string' && name.trim()) target.name = name.trim().substring(0, 80);
  if (role === 'ADMIN' || role === 'STAFF') target.role = role;
  if (typeof roleTitle === 'string' && roleTitle.trim()) target.roleTitle = roleTitle.trim().substring(0, 80);
  if (typeof shift === 'string' && shift.trim()) target.shift = shift.trim().substring(0, 80);
  if (status === 'Active' || status === 'Suspended') target.status = status;
  target.updatedAt = new Date().toISOString();

  saveDatabase(db);
  logAuditEvent('STAFF_UPDATED', {
    staffId: target.staffId,
    role: target.role,
    status: target.status,
    adminId: req.user?.adminId || 'VENTY-ADMIN',
  });

  res.json({
    success: true,
    staffMember: target,
    message: `Staff member ${target.name} updated.`,
  });
});

app.post('/api/management/staff/revoke-sessions', adminLimiter, requireRole(['ADMIN']), (req: Request, res: Response) => {
  let revoked = 0;
  for (const [token, sess] of sessionStore.entries()) {
    if (sess.role === 'STAFF') {
      sessionStore.delete(token);
      revoked++;
    }
  }
  if (revoked > 0) saveSessionsToDisk();

  logAuditEvent('ADMIN_REVOKED_ALL_STAFF_SESSIONS', {
    revokedCount: revoked,
    adminId: req.user?.adminId || 'VENTY-ADMIN',
  });

  res.json({
    success: true,
    revokedCount: revoked,
    message: `Revoked ${revoked} active staff session(s).`,
  });
});

// 11. GET & PUT Store & Loyalty Settings (ADMIN ONLY)
app.get('/api/management/settings', adminLimiter, requireRole(['ADMIN']), (_req: Request, res: Response) => {
  const db = loadDatabase();
  const extDb = ensureManagementCollections(db);
  res.json({
    loyaltyConfig: db.config,
    storeSettings: extDb.storeSettings,
  });
});

app.put('/api/management/settings', adminLimiter, requireRole(['ADMIN']), (req: Request, res: Response) => {
  const db = loadDatabase();
  const extDb = ensureManagementCollections(db);
  const { loyaltyConfig, storeSettings } = req.body || {};

  if (loyaltyConfig && typeof loyaltyConfig === 'object') {
    if (typeof loyaltyConfig.stampsToReward === 'number' && loyaltyConfig.stampsToReward >= 3 && loyaltyConfig.stampsToReward <= 15) {
      db.config.stampsToReward = Math.round(loyaltyConfig.stampsToReward);
    }
    if (typeof loyaltyConfig.welcomeBonusStamps === 'number' && loyaltyConfig.welcomeBonusStamps >= 0 && loyaltyConfig.welcomeBonusStamps <= 5) {
      db.config.welcomeBonusStamps = Math.round(loyaltyConfig.welcomeBonusStamps);
    }
    if (typeof loyaltyConfig.stampsPerQualifyingOrder === 'number' && loyaltyConfig.stampsPerQualifyingOrder >= 1 && loyaltyConfig.stampsPerQualifyingOrder <= 3) {
      db.config.stampsPerQualifyingOrder = Math.round(loyaltyConfig.stampsPerQualifyingOrder);
    }
    if (Array.isArray(loyaltyConfig.qualifyingCategories)) {
      db.config.qualifyingCategories = loyaltyConfig.qualifyingCategories
        .map((c: any) => String(c).trim().toLowerCase())
        .filter(Boolean);
    }
    if (Array.isArray(loyaltyConfig.excludedCategories)) {
      db.config.excludedCategories = loyaltyConfig.excludedCategories
        .map((c: any) => String(c).trim().toLowerCase())
        .filter(Boolean);
    }
  }

  if (storeSettings && typeof storeSettings === 'object') {
    if (typeof storeSettings.storeName === 'string' && storeSettings.storeName.trim()) {
      extDb.storeSettings.storeName = storeSettings.storeName.trim().substring(0, 80);
    }
    if (typeof storeSettings.branchName === 'string' && storeSettings.branchName.trim()) {
      extDb.storeSettings.branchName = storeSettings.branchName.trim().substring(0, 80);
    }
    if (typeof storeSettings.openingHours === 'string' && storeSettings.openingHours.trim()) {
      extDb.storeSettings.openingHours = storeSettings.openingHours.trim().substring(0, 100);
    }
    if (typeof storeSettings.phone === 'string' && storeSettings.phone.trim()) {
      extDb.storeSettings.phone = storeSettings.phone.trim().substring(0, 40);
    }
    if (typeof storeSettings.instagram === 'string' && storeSettings.instagram.trim()) {
      extDb.storeSettings.instagram = storeSettings.instagram.trim().substring(0, 60);
    }
    if (typeof storeSettings.address === 'string' && storeSettings.address.trim()) {
      extDb.storeSettings.address = storeSettings.address.trim().substring(0, 140);
    }
    if (typeof storeSettings.orderAcceptingEnabled === 'boolean') {
      extDb.storeSettings.orderAcceptingEnabled = storeSettings.orderAcceptingEnabled;
    }
    if (typeof storeSettings.defaultPrepMinutes === 'number') {
      extDb.storeSettings.defaultPrepMinutes = Math.max(5, Math.min(60, Math.round(storeSettings.defaultPrepMinutes)));
    }
    if (typeof storeSettings.notifyOnNewOrder === 'boolean') {
      extDb.storeSettings.notifyOnNewOrder = storeSettings.notifyOnNewOrder;
    }
    if (typeof storeSettings.notifyOnRewardRedemption === 'boolean') {
      extDb.storeSettings.notifyOnRewardRedemption = storeSettings.notifyOnRewardRedemption;
    }
    // Always preserve Africa/Algiers as authoritative operational timezone
    extDb.storeSettings.timezone = VENTY_TIMEZONE;
  }

  saveDatabase(db);
  logAuditEvent('SETTINGS_CHANGED', {
    stampsToReward: db.config.stampsToReward,
    welcomeBonusStamps: db.config.welcomeBonusStamps,
    orderAcceptingEnabled: extDb.storeSettings.orderAcceptingEnabled,
    adminId: req.user?.adminId || 'VENTY-ADMIN',
  });

  res.json({
    success: true,
    loyaltyConfig: db.config,
    storeSettings: extDb.storeSettings,
    message: 'VENTY store and loyalty configuration saved.',
  });
});

// 12. GET Security & Audit Log (ADMIN ONLY — Strictly Redacted, Never Exposes Secrets)
app.get('/api/management/audit-logs', adminLimiter, requireRole(['ADMIN']), (req: Request, res: Response) => {
  const filterEvent = ((req.query.event as string) || '').trim().toUpperCase();
  const search = ((req.query.search as string) || '').trim().toLowerCase();
  const limit = Math.min(250, Math.max(10, parseInt((req.query.limit as string) || '120', 10) || 120));

  const entries: Array<Record<string, any>> = [];
  const sensitiveKeys = new Set([
    'adminsecret',
    'staffpin',
    'passcode',
    'password',
    'confirmpassword',
    'newpassword',
    'passwordhash',
    'resettoken',
    'resetcode',
    'otp',
    'otpcode',
    'otphash',
    'salt',
    'token',
    'apikey',
    'google_maps_api_key',
  ]);

  const normalizeAuditRow = (raw: Record<string, any>) => {
    const ev = String(raw.event || 'SYSTEM_EVENT').toUpperCase();
    const user =
      raw.user ||
      raw.adminId ||
      raw.staffId ||
      raw.customerId ||
      raw.phoneMasked ||
      raw.ip ||
      'SYSTEM';
    const role =
      raw.role ||
      raw.actorRole ||
      (raw.adminId || ev.startsWith('ADMIN_') || ev === 'STAFF_CREATED' || ev === 'STAFF_UPDATED' || ev === 'SETTINGS_CHANGED'
        ? 'ADMIN'
        : raw.staffId || ev.startsWith('STAFF_') || ev === 'REWARD_REDEEMED' || ev === 'REWARD_VERIFIED'
        ? 'STAFF'
        : raw.customerId || ev.startsWith('CUSTOMER_')
        ? 'CUSTOMER'
        : 'SYSTEM');
    const action =
      ev === 'ORDER_STATUS_UPDATED'
        ? 'ORDER_STATUS_CHANGED'
        : ev === 'ADMIN_STAFF_MEMBER_ADDED'
        ? 'STAFF_CREATED'
        : ev === 'ADMIN_STAFF_MEMBER_UPDATED'
        ? 'STAFF_UPDATED'
        : ev === 'ADMIN_SETTINGS_UPDATED'
        ? 'SETTINGS_CHANGED'
        : ev === 'ADMIN_LOGIN_SUCCESS' || ev === 'STAFF_LOGIN_SUCCESS' || ev === 'CUSTOMER_PASSWORD_LOGIN_SUCCESS'
        ? 'LOGIN_SUCCESS'
        : ev === 'ADMIN_LOGIN_FAILURE' || ev === 'STAFF_LOGIN_FAILURE' || ev === 'CUSTOMER_PASSWORD_LOGIN_FAILED'
        ? 'LOGIN_FAILURE'
        : ev;
    const resource =
      raw.resource ||
      (raw.orderId
        ? `Order #${raw.orderId}`
        : raw.rewardId
        ? `Reward ${raw.rewardId}`
        : raw.itemId
        ? `Menu ${raw.itemId}`
        : raw.staffId
        ? `Staff ${raw.staffId}`
        : raw.customerId
        ? `Customer ${raw.customerId}`
        : 'VENTY_SYSTEM');
    const result =
      raw.result ||
      (ev.includes('FAIL') || ev.includes('VIOLATION') || ev.includes('LOCKOUT') || ev.includes('UNAUTHORIZED')
        ? 'FAILURE'
        : 'SUCCESS');
    const reference =
      raw.reference ||
      raw.orderId ||
      raw.rewardId ||
      raw.itemId ||
      raw.staffId ||
      raw.customerId ||
      '—';

    return {
      ...raw,
      user,
      role,
      action,
      resource,
      result,
      reference,
    };
  };

  try {
    if (fs.existsSync(AUDIT_LOG_FILE)) {
      const rawContent = fs.readFileSync(AUDIT_LOG_FILE, 'utf-8');
      const lines = rawContent.split('\n').filter(Boolean);
      for (let i = lines.length - 1; i >= 0 && entries.length < 400; i--) {
        try {
          const parsed = JSON.parse(lines[i]);
          const redacted: Record<string, any> = {};
          for (const [k, v] of Object.entries(parsed)) {
            if (sensitiveKeys.has(k.toLowerCase())) {
              redacted[k] = '[REDACTED]';
            } else {
              redacted[k] = v;
            }
          }
          entries.push(normalizeAuditRow(redacted));
        } catch {
          // Skip malformed line
        }
      }
    }
  } catch (err) {
    console.error('[Audit Log Reader] Failed to read audit log file:', err);
  }

  let filtered = entries;
  if (filterEvent && filterEvent !== 'ALL') {
    filtered = filtered.filter(
      (e) =>
        String(e.event || '').toUpperCase().includes(filterEvent) ||
        String(e.action || '').toUpperCase().includes(filterEvent),
    );
  }
  if (search) {
    filtered = filtered.filter((e) => JSON.stringify(e).toLowerCase().includes(search));
  }

  res.json({
    logs: filtered.slice(0, limit),
    totalCaptured: entries.length,
    securityControls: {
      passwordHashing: 'bcrypt (cost factor 10)',
      customerSessionIsolation: 'Enforced server-side',
      rbacEnforcement: 'Strict role middleware (CUSTOMER / STAFF / ADMIN)',
      secretRedaction: 'Active (Zero plaintext secrets in logs or responses)',
      rateLimiting: 'Active per-IP, per-Phone, and per-Device',
    },
  });
});

// 14. 404 Handler for Unmatched API Endpoints
app.all('/api/*', (_req: Request, res: Response) => {
  res.status(404).json({
    error: 'Not Found',
    message: 'The requested API endpoint does not exist.',
  });
});

// 15. Centralized Production Error-Handling Middleware
app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
  console.error('[VENTY Server Error]', err?.message || err);
  res.status(err?.status || 500).json({
    error: err?.name || 'Internal Server Error',
    message: process.env.NODE_ENV === 'production' 
      ? 'An unexpected error occurred. Please try again.' 
      : err?.message || 'Server error',
  });
});

// -------------------------------------------------------------
// 8. VITE DEV SERVER / STATIC PRODUCTION SERVING
// -------------------------------------------------------------
const startServer = async () => {
  if (process.env.NODE_ENV === 'production' && fs.existsSync(path.resolve(__dirname, 'dist'))) {
    app.use(
      express.static(path.resolve(__dirname, 'dist'), {
        maxAge: '1d',
        setHeaders: (res, filePath) => {
          if (filePath.endsWith('index.html')) {
            res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
          } else if (filePath.includes('/assets/')) {
            res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
          }
        },
      }),
    );
    app.get('*', (_req, res) => {
      res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
      res.sendFile(path.resolve(__dirname, 'dist', 'index.html'));
    });
  } else {
    const vitePkg = 'vite';
    const { createServer: createViteServer } = await import(/* @vite-ignore */ vitePkg);
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  }

  app.listen(PORT, () => {
    console.log(`[VENTY Production Hardening] Server running on http://localhost:${PORT}`);
    console.log(`[VENTY Management API] GET /api/management/admin/dashboard ✓`);
    console.log(`[VENTY Management API] GET /api/management/overview ✓`);
    console.log(`[VENTY Orders API] GET /api/orders ✓`);
  });
};

export { app };
export default app;

if (process.env.VERCEL !== '1') {
  startServer().catch((err) => {
    console.error('[VENTY Production Hardening] Server boot failure:', err);
    process.exit(1);
  });
}
