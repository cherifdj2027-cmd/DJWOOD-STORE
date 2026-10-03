import test from 'node:test';
import assert from 'node:assert/strict';
import { publicProduct, measurePerItem, salePrice, validatePublicOrder, makeOrderLine, nextOrderStatus, validateProductRecord } from '../src/domain.mjs';

test('public catalog never exposes purchase price fields or purchase history', () => {
  const source = { id: 7, name: 'MDF', p: 100, pricing: { sale: { m3: 900 }, purchase: { m3: 500 }, history: [{ purchase: { m3: 400 } }] }, variants: [{ id: 'v1', p: 100, pricing: { sale: { m3: 900 }, purchase: { m3: 500 }, history: [{ purchase: { m3: 400 } }] } }] };
  const result = publicProduct(source);
  assert.equal('p' in result, false);
  assert.equal('purchase' in result.pricing, false);
  assert.equal('p' in result.variants[0], false);
  assert.equal('purchase' in result.variants[0].pricing, false);
  assert.equal(JSON.stringify(result).includes('400'), false);
  assert.equal(source.pricing.purchase.m3, 500, 'source remains unchanged');
});

test('wood dimensions are measured correctly in m3, m2 and piece', () => {
  assert.equal(measurePerItem({ unit: 'm3', L: 200, W: 10, T: 5 }), 0.01);
  assert.equal(measurePerItem({ unit: 'm2', L: 200, W: 10, T: 5 }), 0.2);
  assert.equal(measurePerItem({ unit: 'piece', L: 200, W: 10, T: 5 }), 1);
});

test('discount price calculation respects percentage and fixed discount', () => {
  assert.equal(salePrice({ unit: 'm3', p: 1000, pricing: { sale: { m3: 1000 }, discount: { enabled: true, type: 'percent', value: 10 } } }).final, 900);
  assert.equal(salePrice({ unit: 'piece', p: 500, pricing: { sale: { piece: 500 }, discount: { enabled: true, type: 'fixed', value: 50 } } }).final, 450);
});

test('public order validation only permits COD and valid customer information', () => {
  const good = validatePublicOrder({ reference: 'DJW-2026-001', submissionToken: 'a'.repeat(64), paymentMethod: 'cod', customer: { name: 'Ali', phone: '0550123456', fulfillment: 'delivery', address: 'Blida' }, lines: [{ productId: 1, variantId: 'v1', quantity: 2 }] });
  assert.equal(good.ok, true);
  assert.equal(validatePublicOrder({ ...{ reference: 'DJW-2026-002', submissionToken: 'b'.repeat(64), paymentMethod: 'online', customer: { name: 'Ali', phone: '0550123456', address: 'Blida' }, lines: [{ productId: 1, quantity: 1 }] } }).ok, false);
  assert.equal(validatePublicOrder({ reference: 'DJW-2026-003', submissionToken: 'c'.repeat(64), paymentMethod: 'cod', customer: { name: 'Ali', phone: '0550123456' }, lines: [{ productId: 1, quantity: 1 }] }).ok, false);
  assert.equal(validatePublicOrder({ reference: 'DJW-2026-004', paymentMethod: 'cod', customer: { name: 'Ali', phone: '0550123456', address: 'Blida' }, lines: [{ productId: 1, quantity: 1 }] }).ok, false, 'order retry token is mandatory');
});

test('server order line uses canonical price and checks available stock', () => {
  const product = { id: 1, name: 'MDF', category: 'مشتقات خشبية' };
  const variant = { id: 'v1', name: '18mm', sku: 'MDF18', unit: 'piece', L: 244, W: 122, T: 1.8, q: 4, reservedQty: 1, p: 2000, pricing: { sale: { piece: 2000 }, discount: { enabled: false } } };
  const line = makeOrderLine(product, variant, { quantity: 2 }, 1);
  assert.equal(line.estimatedValue, 4000);
  assert.throws(() => makeOrderLine(product, variant, { quantity: 4 }, 1), { code: 'INSUFFICIENT_STOCK' });
  assert.throws(() => makeOrderLine(product, variant, { quantity: 1.5 }, 1), /عددًا صحيحًا/);
});

test('order transitions match the store lifecycle', () => {
  assert.equal(nextOrderStatus('sent', 'under_review'), true);
  assert.equal(nextOrderStatus('sent', 'delivered'), false);
  assert.equal(nextOrderStatus('ready', 'delivered'), true);
  assert.equal(nextOrderStatus('delivered', 'cancelled'), false);
});

test('product validation rejects invalid stock and dimensions before catalog import', () => {
  const good = { id: 1, name: 'MDF', status: 'active', variants: [{ id: 'v1', sku: 'MDF1', unit: 'piece', L: 244, W: 122, T: 1.8, q: 4, reservedQty: 1, p: 1000, pricing: { sale: { piece: 1000 }, discount: { enabled: false } } }] };
  assert.equal(validateProductRecord(good), true);
  assert.equal(validateProductRecord({ ...good, variants: [{ ...good.variants[0], reservedQty: 5 }] }), false);
  assert.equal(validateProductRecord({ ...good, variants: [{ ...good.variants[0], L: 0 }] }), false);
  assert.equal(validateProductRecord({ ...good, variants: [{ ...good.variants[0], q: 2.5 }] }), false);
  assert.equal(validateProductRecord({ ...good, variants: [{ ...good.variants[0], pricing: { sale: { piece: -100 }, discount: { enabled: false } } }] }), false);
});
