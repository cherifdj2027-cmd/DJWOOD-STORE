import pg from 'pg';
import { validateProductRecord } from '../src/domain.mjs';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
const { Pool } = pg;
const file = process.argv[2];
if (!file) {
  console.error('الاستخدام: node --env-file-if-exists=.env scripts/import-products.mjs ./products.json');
  process.exit(1);
}
if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is required');
const parsed = JSON.parse(await readFile(file, 'utf8'));
let products = Array.isArray(parsed) ? parsed : (parsed.products || parsed.data?.products || parsed.collections?.products);
if (typeof products === 'string') products = JSON.parse(products);
if (!products && parsed?.data?.['DJ_WOOD_PRODUCTS_V1']) products = JSON.parse(parsed.data['DJ_WOOD_PRODUCTS_V1']);
if (!Array.isArray(products)) throw new Error('ملف JSON يجب أن يحتوي على مصفوفة منتجات أو الخاصية products.');
const invalid = products.filter(p => p && !validateProductRecord(p));
if (invalid.length) throw new Error(`يوجد ${invalid.length} منتجًا غير صالح. صحح البيانات قبل الاستيراد.`);
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false });
try {
  const schema = await readFile(new URL('../sql/schema.sql', import.meta.url), 'utf8');
  await pool.query(schema);
  await pool.query('BEGIN');
  let imported = 0;
  for (const source of products) {
    if (!source || source.id === undefined || !String(source.name || '').trim()) continue;
    const id = String(source.id);
    const now = new Date().toISOString();
    const payload = { ...source, version: Math.max(1, Number(source.version) || 1), createdAt: source.createdAt || now, updatedAt: now };
    await pool.query(`INSERT INTO products(id,payload,version,created_at,updated_at) VALUES($1,$2::jsonb,$3,COALESCE($4::timestamptz,NOW()),NOW()) ON CONFLICT(id) DO UPDATE SET payload=EXCLUDED.payload,version=products.version+1,updated_at=NOW()`, [id, JSON.stringify(payload), payload.version, payload.createdAt]);
    imported++;
  }
  await pool.query('COMMIT');
  console.log(`تم استيراد/تحديث ${imported} منتجًا.`);
} catch (error) {
  await pool.query('ROLLBACK').catch(() => {});
  throw error;
} finally { await pool.end(); }
