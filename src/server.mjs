import express from 'express';
import helmet from 'helmet';
import pg from 'pg';
import {
  clone, cleanText, finite, round3, publicProduct, validatePublicOrder,
  findVariant, makeOrderLine, nextOrderStatus, validateProductRecord
} from './domain.mjs';
import { createHmac, createHash, timingSafeEqual, randomBytes, scrypt as scryptCallback } from 'node:crypto';
import { promisify } from 'node:util';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const scrypt = promisify(scryptCallback);
const { Pool } = pg;
const PORT = Math.max(1, Number(process.env.PORT) || 8787);
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET || '';
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || '';
const JWT_TTL_SECONDS = Math.max(900, Math.min(86400, Number(process.env.JWT_TTL_SECONDS) || 43200));
const MAX_ORDER_LINES = Math.max(1, Math.min(200, Number(process.env.MAX_ORDER_LINES) || 80));
const DELIVERY_FEE_DZD = Math.max(0, finite(process.env.DELIVERY_FEE_DZD));
const FREE_DELIVERY_THRESHOLD_DZD = Math.max(0, finite(process.env.FREE_DELIVERY_THRESHOLD_DZD));
const allowedOrigins = new Set(String(process.env.ALLOWED_ORIGINS || '').split(',').map(x => x.trim()).filter(Boolean));
if (!DATABASE_URL) throw new Error('DATABASE_URL is required');
if (JWT_SECRET.length < 32) throw new Error('JWT_SECRET must contain at least 32 characters');
if (!ADMIN_PASSWORD_HASH.startsWith('scrypt$')) throw new Error('ADMIN_PASSWORD_HASH is required; generate it with npm run admin:hash');

const pool = new Pool({ connectionString: DATABASE_URL, ssl: process.env.PGSSLMODE === 'disable' ? false : (process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false), max: 10, idleTimeoutMillis: 30000, connectionTimeoutMillis: 10000 });
pool.on('error', error => console.error('Unexpected PostgreSQL pool error:', error.message));
const app = express();
app.disable('x-powered-by');
if (process.env.TRUST_PROXY === 'true') app.set('trust proxy', 1);
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' }, contentSecurityPolicy: false }));
app.use((req, res, next) => {
  const origin = req.headers.origin;
  const ownOrigin = `${req.protocol}://${req.get('host')}`;
  if (origin && origin !== ownOrigin && !allowedOrigins.has(origin) && !allowedOrigins.has('*')) {
    return res.status(403).json(failure('ORIGIN_NOT_ALLOWED', 'مصدر الاتصال غير مسموح.'));
  }
  if (origin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization,Idempotency-Key,If-Match');
    res.setHeader('Access-Control-Expose-Headers', 'ETag');
  }
  if (req.method === 'OPTIONS') return res.status(204).end();
  next();
});
app.use(express.json({ limit: '6mb', strict: true }));

const response = (data, meta = {}) => ({ ok: true, data: clone(data), meta: { apiVersion: '1.0.0', ...meta } });
const failure = (code, message, extra = {}) => ({ ok: false, error: { code, message, ...extra }, meta: { apiVersion: '1.0.0' } });
const asyncRoute = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const nowIso = () => new Date().toISOString();

function b64url(value) { return Buffer.from(value).toString('base64url'); }
function signToken(username) {
  const now = Math.floor(Date.now() / 1000);
  const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const payload = b64url(JSON.stringify({ sub: username, role: 'admin', jti: randomBytes(18).toString('base64url'), iat: now, exp: now + JWT_TTL_SECONDS }));
  const data = `${header}.${payload}`;
  const signature = createHmac('sha256', JWT_SECRET).update(data).digest('base64url');
  return `${data}.${signature}`;
}
function verifyToken(token) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) return null;
  const data = `${parts[0]}.${parts[1]}`;
  const expected = createHmac('sha256', JWT_SECRET).update(data).digest();
  let actual;
  try { actual = Buffer.from(parts[2], 'base64url'); } catch { return null; }
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) return null;
  try {
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    if (!payload.sub || !payload.jti || payload.role !== 'admin' || payload.exp <= Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch { return null; }
}
async function verifyPassword(password, encoded) {
  const parts = String(encoded || '').split('$');
  if (parts.length !== 3 || parts[0] !== 'scrypt') return false;
  try {
    const salt = Buffer.from(parts[1], 'base64url');
    const expected = Buffer.from(parts[2], 'base64url');
    const actual = Buffer.from(await scrypt(String(password), salt, expected.length));
    return expected.length === actual.length && timingSafeEqual(expected, actual);
  } catch { return false; }
}
const loginAttempts = new Map();
function loginLimiter(req, res, next) {
  const key = req.ip || req.socket.remoteAddress || 'unknown';
  const now = Date.now();
  let state = loginAttempts.get(key);
  if (!state || now - state.start > 15 * 60 * 1000) state = { start: now, count: 0 };
  state.count += 1;
  loginAttempts.set(key, state);
  if (loginAttempts.size > 5000) for (const [k, v] of loginAttempts) if (now - v.start > 15 * 60 * 1000) loginAttempts.delete(k);
  if (state.count > 12) return res.status(429).json(failure('RATE_LIMITED', 'محاولات تسجيل الدخول كثيرة. حاول بعد 15 دقيقة.'));
  next();
}
function requireAdmin(req, res, next) {
  const token = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  const user = verifyToken(token);
  if (!user) return res.status(401).json(failure('AUTH_REQUIRED', 'تسجيل الدخول مطلوب لهذه العملية.'));
  pool.query('SELECT 1 FROM revoked_tokens WHERE jti=$1 AND expires_at > NOW()', [user.jti])
    .then(result => {
      if (result.rowCount) return res.status(401).json(failure('AUTH_REQUIRED', 'انتهت صلاحية الجلسة. سجّل الدخول مجددًا.'));
      req.admin = user; next();
    }).catch(next);
}
const publicOrderAttempts = new Map();
function publicOrderLimiter(req, res, next) {
  const key = req.ip || req.socket.remoteAddress || 'unknown';
  const now = Date.now();
  let state = publicOrderAttempts.get(key);
  if (!state || now - state.start > 10 * 60 * 1000) state = { start: now, count: 0 };
  state.count += 1;
  publicOrderAttempts.set(key, state);
  if (publicOrderAttempts.size > 5000) for (const [k, v] of publicOrderAttempts) if (now - v.start > 10 * 60 * 1000) publicOrderAttempts.delete(k);
  if (state.count > 30) return res.status(429).json(failure('RATE_LIMITED', 'تم تجاوز عدد الطلبات المسموح مؤقتًا. حاول لاحقًا.'));
  next();
}
async function transaction(fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const value = await fn(client);
    await client.query('COMMIT');
    return value;
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw error;
  } finally { client.release(); }
}
async function getRow(client, table, keyColumn, key, lock = false) {
  const allowed = { products: 'id', customers: 'id', orders: 'reference' };
  if (allowed[table] !== keyColumn) throw new Error('invalid-table-key');
  const result = await client.query(`SELECT payload, version FROM ${table} WHERE ${keyColumn} = $1${lock ? ' FOR UPDATE' : ''}`, [String(key)]);
  return result.rows[0] || null;
}
async function saveRecord(client, table, keyColumn, key, payload, expectedVersion = null) {
  const existing = await getRow(client, table, keyColumn, key, true);
  if (existing && expectedVersion !== null && Number(expectedVersion) !== Number(existing.version)) {
    const error = new Error('version-conflict'); error.code = 'CONFLICT'; error.status = 409; error.current = { ...existing.payload, version: Number(existing.version) }; error.expectedVersion = Number(expectedVersion); throw error;
  }
  const version = existing ? Number(existing.version) + 1 : 1;
  const updatedAt = nowIso();
  const record = { ...payload, version, updatedAt };
  if (!existing) record.createdAt = payload.createdAt || updatedAt;
  await client.query(`INSERT INTO ${table} (${keyColumn}, payload, version, created_at, updated_at) VALUES ($1, $2::jsonb, $3, COALESCE($4::timestamptz, NOW()), NOW()) ON CONFLICT (${keyColumn}) DO UPDATE SET payload = EXCLUDED.payload, version = EXCLUDED.version, updated_at = NOW()`, [String(key), JSON.stringify(record), version, record.createdAt]);
  return record;
}
async function listRecords(table, orderBy = 'updated_at DESC') {
  if (!['products', 'customers', 'orders'].includes(table)) throw new Error('invalid-table');
  const result = await pool.query(`SELECT payload, version FROM ${table} ORDER BY ${orderBy}`);
  return result.rows.map(row => ({ ...row.payload, version: Number(row.version) }));
}
function syncPrimaryStock(product) {
  if (Array.isArray(product?.variants) && product.variants.length) {
    product.q = product.variants[0].q;
    product.reservedQty = product.variants[0].reservedQty;
  }
  return product;
}
async function idempotent(client, key, work) {
  const safeKey = cleanText(key, 180);
  if (!safeKey) return work();
  await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [safeKey]);
  const prior = await client.query('SELECT response FROM idempotency_keys WHERE key=$1', [safeKey]);
  if (prior.rows[0]) return { reference: prior.rows[0].response.reference, idempotentReplay: true };
  const result = await work();
  // Store only the order reference here; customer details remain in the orders table.
  await client.query('INSERT INTO idempotency_keys(key,response) VALUES($1,$2::jsonb) ON CONFLICT(key) DO NOTHING', [safeKey, JSON.stringify({ reference: result.order.reference })]);
  return result;
}
function conflictPayload(error) {
  return failure('CONFLICT', 'تم تعديل السجل في جهاز آخر. أعد تحميل البيانات قبل الحفظ.', { current: error.current, expectedVersion: error.expectedVersion });
}

app.get('/api/v1/health', asyncRoute(async (_req, res) => {
  await pool.query('SELECT 1');
  res.json(response({ status: 'ok', database: 'connected', time: nowIso() }));
}));
app.get('/api/v1/catalog', asyncRoute(async (_req, res) => {
  const rows = await pool.query('SELECT payload, version FROM products ORDER BY updated_at DESC');
  const visible = rows.rows.filter(row => (row.payload?.status || 'active') !== 'inactive').map(row => publicProduct({ ...row.payload, version: Number(row.version) }));
  res.json(response(visible, { catalogReady: rows.rowCount > 0 }));
}));

app.post('/api/v1/auth/login', loginLimiter, asyncRoute(async (req, res) => {
  const username = cleanText(req.body?.username, 80);
  const password = String(req.body?.password || '');
  const userOk = username === ADMIN_USERNAME;
  const passOk = await verifyPassword(password, ADMIN_PASSWORD_HASH);
  if (!userOk || !passOk) return res.status(401).json(failure('INVALID_CREDENTIALS', 'اسم المستخدم أو كلمة المرور غير صحيحة.'));
  res.json(response({ token: signToken(username), tokenType: 'Bearer', expiresIn: JWT_TTL_SECONDS, user: { username, role: 'admin' } }));
}));
app.post('/api/v1/auth/logout', asyncRoute(async (req, res) => {
  const token = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  const user = verifyToken(token);
  if (user) await pool.query('INSERT INTO revoked_tokens(jti,expires_at) VALUES($1,to_timestamp($2)) ON CONFLICT(jti) DO NOTHING', [user.jti, user.exp]);
  res.json(response(true));
}));
app.get('/api/v1/auth/me', requireAdmin, (req, res) => res.json(response({ username: req.admin.sub, role: req.admin.role })));

app.get('/api/v1/products', requireAdmin, asyncRoute(async (_req, res) => res.json(response(await listRecords('products')))));
app.get('/api/v1/products/:id', requireAdmin, asyncRoute(async (req, res) => {
  const row = await getRow(pool, 'products', 'id', req.params.id);
  if (!row) return res.status(404).json(failure('NOT_FOUND', 'المنتج غير موجود.'));
  res.json(response({ ...row.payload, version: Number(row.version) }));
}));
app.post('/api/v1/products', requireAdmin, asyncRoute(async (req, res) => {
  const p = req.body;
  if (!validateProductRecord(p)) return res.status(422).json(failure('INVALID_PRODUCT', 'بيانات المنتج أو مقاساته أو مخزونه أو أسعاره غير صالحة.'));
  const saved = await transaction(async client => {
    const existing = await getRow(client, 'products', 'id', p.id, true);
    if (existing) { const error = new Error('product-already-exists'); error.status = 409; error.code = 'DUPLICATE_PRODUCT'; throw error; }
    return saveRecord(client, 'products', 'id', p.id, p);
  });
  res.status(201).json(response(saved));
}));
app.put('/api/v1/products/:id', requireAdmin, asyncRoute(async (req, res) => {
  const p = req.body;
  if (!p || String(p.id) !== String(req.params.id) || !validateProductRecord(p)) return res.status(422).json(failure('INVALID_PRODUCT', 'بيانات المنتج أو مقاساته أو مخزونه أو أسعاره غير صالحة.'));
  const expected = req.headers['if-match'] === undefined ? null : Number(req.headers['if-match']);
  const saved = await transaction(async client => {
    const current = await getRow(client, 'products', 'id', req.params.id, true);
    if (!current) { const error = new Error('not-found'); error.status = 404; throw error; }
    if (expected !== null && expected !== Number(current.version)) { const error = new Error('version-conflict'); error.code = 'CONFLICT'; error.status = 409; error.current = { ...current.payload, version: Number(current.version) }; error.expectedVersion = expected; throw error; }
    const variants = Array.isArray(p.variants) ? p.variants : [];
    for (const v of variants) {
      const old = findVariant(current.payload, v.id);
      const reserved = finite(old?.reservedQty);
      const onHand = finite(v.q);
      if (reserved > onHand) { const error = new Error('reserved-stock-below-onhand'); error.status = 409; error.code = 'STOCK_CONFLICT'; throw error; }
      v.reservedQty = reserved;
    }
    if (variants.length) { p.q = variants[0].q; p.reservedQty = variants[0].reservedQty; }
    if (!variants.length) {
      const reserved = finite(current.payload.reservedQty);
      if (reserved > finite(p.q)) { const error = new Error('reserved-stock-below-onhand'); error.status = 409; error.code = 'STOCK_CONFLICT'; throw error; }
      p.reservedQty = reserved;
    }
    return saveRecord(client, 'products', 'id', req.params.id, p, expected);
  });
  res.json(response(saved));
}));
app.delete('/api/v1/products/:id', requireAdmin, asyncRoute(async (req, res) => {
  const deleted = await transaction(async client => {
    const row = await getRow(client, 'products', 'id', req.params.id, true);
    if (!row) return false;
    const product = row.payload;
    const reserved = Array.isArray(product.variants)
      ? product.variants.reduce((sum, v) => sum + finite(v.reservedQty), 0)
      : finite(product.reservedQty);
    if (reserved > 0) { const error = new Error('لا يمكن حذف منتج عليه كميات محجوزة.'); error.status = 409; error.code = 'PRODUCT_RESERVED'; throw error; }
    const referenced = await client.query(`SELECT 1 FROM orders WHERE EXISTS (SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(payload->'lines')='array' THEN payload->'lines' ELSE '[]'::jsonb END) AS lines(line) WHERE lines.line->>'productId'=$1) LIMIT 1`, [String(req.params.id)]);
    if (referenced.rowCount) { const error = new Error('للمنتج سجل في طلبات سابقة. عطّله بدل حذفه للحفاظ على سجل المبيعات.'); error.status = 409; error.code = 'PRODUCT_IN_ORDER_HISTORY'; throw error; }
    await client.query('DELETE FROM products WHERE id=$1', [req.params.id]);
    return true;
  });
  res.json(response({ deleted }));
}));

app.get('/api/v1/customers', requireAdmin, asyncRoute(async (_req, res) => res.json(response(await listRecords('customers')))));
app.post('/api/v1/customers', requireAdmin, asyncRoute(async (req, res) => {
  const c = req.body;
  if (!c || !cleanText(c.id, 80) || !cleanText(c.name, 120)) return res.status(422).json(failure('INVALID_CUSTOMER', 'بيانات العميل غير مكتملة.'));
  const expected = req.headers['if-match'] === undefined ? null : Number(req.headers['if-match']);
  const saved = await transaction(async client => saveRecord(client, 'customers', 'id', c.id, c, expected));
  res.json(response(saved));
}));
app.delete('/api/v1/customers/:id', requireAdmin, asyncRoute(async (req, res) => {
  const result = await pool.query('DELETE FROM customers WHERE id=$1', [req.params.id]);
  res.json(response({ deleted: result.rowCount > 0 }));
}));

app.post('/api/v1/orders/submit', publicOrderLimiter, asyncRoute(async (req, res) => {
  const validated = validatePublicOrder(req.body, MAX_ORDER_LINES);
  if (!validated.ok) return res.status(422).json(failure('INVALID_ORDER', validated.message));
  const input = validated.value;
  const submissionTokenHash = createHash('sha256').update(input.submissionToken).digest('hex');
  const idemKey = `public-order:${input.reference}:${submissionTokenHash}`;
  const created = await transaction(async client => idempotent(client, idemKey, async () => {
    await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [`order:${input.reference}`]);
    const prior = await client.query('SELECT payload, version, submission_token_hash FROM orders WHERE reference=$1 FOR UPDATE', [input.reference]);
    if (prior.rows[0]) {
      if (prior.rows[0].submission_token_hash !== submissionTokenHash) { const error = new Error('reference-in-use'); error.code = 'REFERENCE_IN_USE'; error.status = 409; throw error; }
      return { order: { ...prior.rows[0].payload, version: Number(prior.rows[0].version) }, replay: true };
    }
    const requestedProducts = [...new Set(input.lines.map(line => line.productId))].sort((a,b) => String(a).localeCompare(String(b), 'en'));
    const locked = new Map();
    for (const id of requestedProducts) {
      const row = await getRow(client, 'products', 'id', id, true);
      if (!row) { const error = new Error(`المنتج رقم ${id} لم يعد متوفرًا.`); error.code = 'PRODUCT_UNAVAILABLE'; error.status = 409; throw error; }
      locked.set(String(id), { ...row.payload, version: Number(row.version) });
    }
    const aggregates = new Map();
    const lines = [];
    let totalVolume = 0, itemsTotal = 0;
    for (const [index, requested] of input.lines.entries()) {
      const product = locked.get(String(requested.productId));
      if (!product || product.status === 'inactive') { const error = new Error('أحد المنتجات لم يعد متاحًا للبيع.'); error.code = 'PRODUCT_UNAVAILABLE'; error.status = 409; throw error; }
      const variant = findVariant(product, requested.variantId);
      if (!variant || variant.status === 'inactive') { const error = new Error('أحد مقاسات المنتج لم يعد متاحًا.'); error.code = 'VARIANT_UNAVAILABLE'; error.status = 409; throw error; }
      const line = makeOrderLine(product, variant, requested, index + 1);
      lines.push(line);
      const key = `${requested.productId}::${requested.variantId}`;
      const prior = aggregates.get(key);
      if (prior) prior.quantity = round3(prior.quantity + line.quantity);
      else aggregates.set(key, { productId: requested.productId, variantId: requested.variantId, quantity: line.quantity, state: 'reserved' });
      totalVolume += line.unit === 'm3' ? line.volume : 0;
      itemsTotal += line.estimatedValue;
    }
    // Validate aggregate quantities after grouping duplicate lines for the same variant.
    for (const allocation of aggregates.values()) {
      const product = locked.get(String(allocation.productId));
      const variant = findVariant(product, allocation.variantId);
      const available = Math.max(0, round3(finite(variant.q) - finite(variant.reservedQty)));
      if (available < allocation.quantity) { const error = new Error(`المخزون المتاح غير كافٍ للمنتج ${product.name}. المتاح ${available} والمطلوب ${allocation.quantity}.`); error.code = 'INSUFFICIENT_STOCK'; error.status = 409; throw error; }
      variant.reservedQty = round3(finite(variant.reservedQty) + allocation.quantity);
      if (!Array.isArray(product.variants) || !product.variants.length) product.reservedQty = variant.reservedQty;
      syncPrimaryStock(product);
    }
    for (const [id, product] of locked) await saveRecord(client, 'products', 'id', id, product, product.version);
    const shippingFee = input.customer.fulfillment === 'pickup' ? 0 : (FREE_DELIVERY_THRESHOLD_DZD > 0 && itemsTotal >= FREE_DELIVERY_THRESHOLD_DZD ? 0 : DELIVERY_FEE_DZD);
    const now = nowIso();
    const customerId = `CUST-${Buffer.from(input.customer.phone.replace(/\D/g, '')).toString('hex').slice(0, 28) || randomBytes(8).toString('hex')}`;
    const customer = { id: customerId, schemaVersion: 2, ...input.customer, status: 'active', createdAt: now, updatedAt: now };
    const order = {
      schemaVersion: 7, reference: input.reference, status: 'sent', createdAt: input.createdAt || now, updatedAt: now,
      customerId, customer: { ...input.customer, shippingFee }, lines, totalVolume: round3(totalVolume),
      itemsTotal: Math.round(itemsTotal * 100) / 100, shippingFee,
      estimatedTotal: Math.round((itemsTotal + shippingFee) * 100) / 100,
      statusHistory: [{ from: 'draft', to: 'sent', at: now }],
      inventoryAllocation: [...aggregates.values()].map(x => ({ ...x, updatedAt: now })),
      paymentMethod: 'cod', paymentStatus: 'due_on_delivery', paymentReference: '', serverReceivedAt: now, version: 1
    };
    await client.query('INSERT INTO customers(id,payload,version,created_at,updated_at) VALUES($1,$2::jsonb,1,NOW(),NOW()) ON CONFLICT(id) DO UPDATE SET payload=EXCLUDED.payload,version=customers.version+1,updated_at=NOW()', [customerId, JSON.stringify(customer)]);
    await client.query('INSERT INTO orders(reference,payload,version,submission_token_hash,created_at,updated_at) VALUES($1,$2::jsonb,1,$3,NOW(),NOW())', [order.reference, JSON.stringify(order), submissionTokenHash]);
    return { order, replay: false };
  }));
  let savedOrder = created.order;
  if (!savedOrder && created.reference) { const row = await getRow(pool, 'orders', 'reference', created.reference); savedOrder = row ? { ...row.payload, version: Number(row.version) } : null; }
  if (!savedOrder) throw new Error('idempotent-order-reference-missing');
  const replayed = !!(created.replay || created.idempotentReplay);
  res.status(replayed ? 200 : 201).json(response(savedOrder, { receivedByServer: true, idempotentReplay: replayed }));
}));

app.get('/api/v1/orders', requireAdmin, asyncRoute(async (_req, res) => res.json(response(await listRecords('orders', 'created_at DESC')))));
app.get('/api/v1/orders/:reference', requireAdmin, asyncRoute(async (req, res) => {
  const row = await getRow(pool, 'orders', 'reference', req.params.reference);
  if (!row) return res.status(404).json(failure('NOT_FOUND', 'الطلب غير موجود.'));
  res.json(response({ ...row.payload, version: Number(row.version) }));
}));
app.post('/api/v1/orders', requireAdmin, asyncRoute(async (req, res) => {
  const incoming = req.body;
  if (!incoming || !cleanText(incoming.reference, 80)) return res.status(422).json(failure('INVALID_ORDER', 'مرجع الطلب غير صالح.'));
  const expected = req.headers['if-match'] === undefined ? null : Number(req.headers['if-match']);
  const saved = await transaction(async client => {
    const current = await getRow(client, 'orders', 'reference', incoming.reference, true);
    if (!current) {
      const payload = { ...incoming, status: incoming.status || 'draft', inventoryAllocation: Array.isArray(incoming.inventoryAllocation) ? incoming.inventoryAllocation : [] };
      delete payload.submissionToken;
      return saveRecord(client, 'orders', 'reference', incoming.reference, payload, expected);
    }
    if (expected !== null && expected !== Number(current.version)) { const error = new Error('version-conflict'); error.code = 'CONFLICT'; error.status = 409; error.current = { ...current.payload, version: Number(current.version) }; error.expectedVersion = expected; throw error; }
    const old = current.payload;
    const nextStatus = cleanText(incoming.status || old.status, 40);
    let pathStatus = old.status;
    for (const step of (Array.isArray(incoming.statusHistory) ? incoming.statusHistory : [])) {
      if (step?.from === pathStatus && nextOrderStatus(pathStatus, step?.to)) pathStatus = step.to;
    }
    if (pathStatus !== nextStatus && !nextOrderStatus(old.status, nextStatus)) { const error = new Error('invalid-order-transition'); error.code = 'INVALID_TRANSITION'; error.status = 409; throw error; }
    let allocations = Array.isArray(old.inventoryAllocation) ? clone(old.inventoryAllocation) : [];
    const activeReserved = allocations.filter(a => a.state === 'reserved');
    if (nextStatus === 'confirmed' && !activeReserved.length) {
      const aggregate = new Map();
      for (const line of old.lines || []) {
        const key = `${line.productId}::${line.variantId}`;
        aggregate.set(key, (aggregate.get(key) || 0) + finite(line.quantity));
      }
      for (const [key, quantity] of aggregate) {
        const [productId, variantId] = key.split('::');
        const row = await getRow(client, 'products', 'id', productId, true);
        if (!row) { const error = new Error('product-not-found'); error.status = 409; throw error; }
        const product = row.payload; const variant = findVariant(product, variantId);
        if (!variant || finite(variant.q) - finite(variant.reservedQty) < quantity) { const error = new Error('insufficient-stock'); error.code = 'INSUFFICIENT_STOCK'; error.status = 409; throw error; }
        variant.reservedQty = round3(finite(variant.reservedQty) + quantity);
        if (!Array.isArray(product.variants) || !product.variants.length) product.reservedQty = variant.reservedQty;
        syncPrimaryStock(product);
        await saveRecord(client, 'products', 'id', productId, product, Number(row.version));
        allocations.push({ productId: Number.isFinite(Number(productId)) ? Number(productId) : productId, variantId, quantity, state: 'reserved', updatedAt: nowIso() });
      }
    }
    if (nextStatus === 'cancelled' || nextStatus === 'delivered') {
      for (const allocation of allocations.filter(a => a.state === 'reserved')) {
        const row = await getRow(client, 'products', 'id', allocation.productId, true);
        if (!row) { const error = new Error('product-not-found-for-stock-transition'); error.status = 409; throw error; }
        const product = row.payload; const variant = findVariant(product, allocation.variantId);
        if (!variant) { const error = new Error('variant-not-found-for-stock-transition'); error.status = 409; throw error; }
        const quantity = finite(allocation.quantity);
        variant.reservedQty = Math.max(0, round3(finite(variant.reservedQty) - quantity));
        if (nextStatus === 'delivered') {
          if (finite(variant.q) < quantity) { const error = new Error('onhand-below-reservation'); error.status = 409; throw error; }
          variant.q = Math.max(0, round3(finite(variant.q) - quantity));
          allocation.state = 'consumed';
        } else allocation.state = 'released';
        allocation.updatedAt = nowIso();
        if (!Array.isArray(product.variants) || !product.variants.length) { product.q = variant.q; product.reservedQty = variant.reservedQty; }
        syncPrimaryStock(product);
        await saveRecord(client, 'products', 'id', allocation.productId, product, Number(row.version));
      }
    }
    const statusHistory = [...(Array.isArray(old.statusHistory) ? old.statusHistory : []), { from: old.status, to: nextStatus, at: nowIso() }].slice(-30);
    const updated = { ...old, status: nextStatus, statusHistory, inventoryAllocation: allocations,
      paymentStatus: incoming.paymentStatus || old.paymentStatus,
      paymentReference: cleanText(incoming.paymentReference ?? old.paymentReference, 120),
      customer: old.customer, lines: old.lines, itemsTotal: old.itemsTotal, estimatedTotal: old.estimatedTotal };
    return saveRecord(client, 'orders', 'reference', incoming.reference, updated, expected);
  });
  res.json(response(saved));
}));
app.delete('/api/v1/orders/:reference', requireAdmin, asyncRoute(async (req, res) => {
  const error = new Error('orders-cannot-be-hard-deleted'); error.status = 409; error.code = 'USE_CANCEL_TRANSITION'; throw error;
}));

const publicDirectory = fileURLToPath(new URL('../public/', import.meta.url));
app.use(express.static(publicDirectory, { index: 'index.html', maxAge: '1h', setHeaders(res, filePath) {
  if (filePath.endsWith('.html')) res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
} }));
app.use((req, res) => res.status(404).json(failure('NOT_FOUND', 'المسار المطلوب غير موجود.')));
app.use((error, _req, res, _next) => {
  if (res.headersSent) return;
  if (error.code === 'CONFLICT') return res.status(409).json(conflictPayload(error));
  if (error.code === 'DUPLICATE_PRODUCT') return res.status(409).json(failure('DUPLICATE_PRODUCT', 'يوجد منتج بهذا المعرّف بالفعل.'));
  if (error.code === 'REFERENCE_IN_USE') return res.status(409).json(failure('REFERENCE_IN_USE', 'مرجع الطلب مستخدم مسبقًا. أنشئ طلبًا جديدًا أو استعد المسودة الأصلية.'));
  if (error.code === 'PRODUCT_RESERVED' || error.code === 'PRODUCT_IN_ORDER_HISTORY') return res.status(409).json(failure(error.code, error.message));
  if (error.code === 'INSUFFICIENT_STOCK' || error.code === 'PRODUCT_UNAVAILABLE' || error.code === 'VARIANT_UNAVAILABLE') return res.status(error.status || 409).json(failure(error.code, error.message));
  if (error.code === 'INVALID_TRANSITION' || error.code === 'STOCK_CONFLICT') return res.status(error.status || 409).json(failure(error.code, error.message || 'تعارض في حالة الطلب أو المخزون.'));
  if (error.status) return res.status(error.status).json(failure(error.code || 'REQUEST_FAILED', error.message || 'تعذر تنفيذ الطلب.'));
  if (error.type === 'entity.too.large') return res.status(413).json(failure('PAYLOAD_TOO_LARGE', 'حجم البيانات أكبر من الحد المسموح.'));
  console.error('API error:', error);
  res.status(500).json(failure('INTERNAL_ERROR', 'حدث خطأ داخلي. لم يتم عرض تفاصيل الخادم للعميل.'));
});

const schema = await readFile(new URL('../sql/schema.sql', import.meta.url), 'utf8');
await pool.query(schema);
await pool.query("DELETE FROM idempotency_keys WHERE created_at < NOW() - INTERVAL '30 days'");
await pool.query('DELETE FROM revoked_tokens WHERE expires_at < NOW()');
const server = app.listen(PORT, '0.0.0.0', () => console.log(`DJ WOOD API listening on :${PORT}`));
async function shutdown() { server.close(); await pool.end(); process.exit(0); }
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
