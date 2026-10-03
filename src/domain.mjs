export const ORDER_TRANSITIONS = Object.freeze({
  draft: ["sent", "cancelled"],
  sent: ["under_review", "cancelled"],
  under_review: ["confirmed", "cancelled"],
  confirmed: ["preparing", "cancelled"],
  preparing: ["ready", "cancelled"],
  ready: ["delivered", "cancelled"],
  delivered: ["completed"],
  completed: [],
  cancelled: []
});

export const clone = value => value == null ? value : JSON.parse(JSON.stringify(value));
export const finite = (value, fallback = 0) => {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
};
export const round3 = value => Math.round((finite(value) + Number.EPSILON) * 1000) / 1000;
export const cleanText = (value, max = 500) => String(value ?? "").replace(/[<>\u0000-\u001f]/g, " ").trim().slice(0, max);
export const normalizeUnit = value => ["m3", "m2", "piece"].includes(value) ? value : "m3";
export const normalizeQty = (value, unit) => {
  const n = finite(value, -1);
  if (n < 0) return null;
  return unit === "piece" ? Math.floor(n) : round3(n);
};
export const measurePerItem = variant => {
  const unit = normalizeUnit(variant?.unit);
  if (unit === "piece") return 1;
  const L = Math.max(0, finite(variant?.L));
  const W = Math.max(0, finite(variant?.W));
  const T = Math.max(0, finite(variant?.T));
  return unit === "m2" ? (L * W) / 10000 : (L * W * T) / 1000000;
};

export function findVariant(product, variantId) {
  if (Array.isArray(product?.variants) && product.variants.length) {
    return product.variants.find(v => String(v.id) === String(variantId)) || null;
  }
  return String(variantId || "v1") === "v1" ? product : null;
}

export function salePrice(variant, now = Date.now()) {
  const unit = normalizeUnit(variant?.unit);
  const pricing = variant?.pricing || {};
  const saleMap = pricing.sale || {};
  const base = Math.max(0, finite(saleMap[unit] ?? variant?.p));
  const discount = pricing.discount || {};
  let amount = 0;
  if (discount.enabled && finite(discount.value) > 0) {
    const start = discount.startAt ? Date.parse(discount.startAt) : NaN;
    const end = discount.endAt ? Date.parse(discount.endAt) : NaN;
    const inWindow = (!Number.isFinite(start) || now >= start) && (!Number.isFinite(end) || now <= end);
    if (inWindow) {
      amount = discount.type === "percent" ? base * finite(discount.value) / 100 : finite(discount.value);
      amount = Math.min(base, Math.max(0, amount));
    }
  }
  return { base, discount: amount, final: Math.max(0, base - amount), discountLabel: cleanText(discount.label, 80) };
}

export function validateProductRecord(product) {
  if (!product || typeof product !== 'object' || Array.isArray(product)) return false;
  if (product.id === undefined || product.id === null || !String(product.id).trim()) return false;
  if (!cleanText(product.name, 120) || !['active', 'inactive', undefined].includes(product.status)) return false;
  const variants = Array.isArray(product.variants) && product.variants.length ? product.variants : [product];
  if (variants.length > 100) return false;
  const ids = new Set();
  const skus = new Set();
  for (const variant of variants) {
    if (!variant || typeof variant !== 'object') return false;
    if (!['m3', 'm2', 'piece'].includes(variant.unit)) return false;
    const id = String(variant.id || (variants.length === 1 ? 'v1' : ''));
    if (!id || ids.has(id)) return false;
    ids.add(id);
    const sku = String(variant.sku || product.sku || '').trim().toUpperCase();
    if (sku && skus.has(sku)) return false;
    if (sku) skus.add(sku);
    const q = finite(variant.q, -1);
    const reserved = finite(variant.reservedQty, 0);
    if (q < 0 || reserved < 0 || reserved > q) return false;
    if (variant.unit === 'piece' && (!Number.isInteger(q) || !Number.isInteger(reserved))) return false;
    if (!(finite(variant.L) > 0) || !(finite(variant.W) > 0) || !(finite(variant.T) > 0)) return false;
    const rawSale = variant.pricing?.sale?.[variant.unit] ?? variant.p ?? 0;
    if (!Number.isFinite(Number(rawSale)) || Number(rawSale) < 0) return false;
    const discount = variant.pricing?.discount || {};
    if (discount.enabled === true && (finite(discount.value, -1) < 0 || !['percent', 'fixed', undefined].includes(discount.type))) return false;
    const price = salePrice(variant).final;
    if (!Number.isFinite(price) || price < 0) return false;
    if (variant.status !== undefined && !['active', 'inactive'].includes(variant.status)) return false;
  }
  return true;
}

export function publicProduct(product) {
  const copy = clone(product || {});
  const scrubVariant = variant => {
    const v = { ...variant };
    delete v.p;
    if (v.pricing) {
      const { sale, discount, version, currency } = v.pricing;
      v.pricing = { sale: clone(sale || {}), discount: clone(discount || {}), version: finite(version, 1), currency: currency || "DZD" };
    }
    return v;
  };
  delete copy.p;
  if (copy.pricing) {
    const { sale, discount, version, currency } = copy.pricing;
    copy.pricing = { sale: clone(sale || {}), discount: clone(discount || {}), version: finite(version, 1), currency: currency || "DZD" };
  }
  if (Array.isArray(copy.variants)) copy.variants = copy.variants.map(scrubVariant);
  return copy;
}

export function validatePublicOrder(body, maxLines = 80) {
  if (!body || typeof body !== "object" || Array.isArray(body)) return { ok: false, message: "بيانات الطلب غير صالحة." };
  const reference = cleanText(body.reference, 80);
  const submissionToken = cleanText(body.submissionToken, 100);
  const customer = body.customer && typeof body.customer === "object" ? body.customer : {};
  const name = cleanText(customer.name, 120);
  const phone = cleanText(customer.phone, 40);
  const address = cleanText(customer.address, 500);
  const fulfillment = customer.fulfillment === "pickup" ? "pickup" : "delivery";
  const paymentMethod = body.paymentMethod === "cod" ? "cod" : "";
  const lines = Array.isArray(body.lines) ? body.lines : [];
  if (!reference || !/^[A-Za-z0-9_-]{4,80}$/.test(reference)) return { ok: false, message: "مرجع الطلب غير صالح." };
  if (!/^[A-Fa-f0-9]{64}$/.test(submissionToken)) return { ok: false, message: "رمز حماية الطلب غير صالح. أعد المحاولة." };
  if (!name || phone.replace(/\D/g, "").length < 8) return { ok: false, message: "اسم العميل أو رقم الهاتف غير صالح." };
  if (fulfillment === "delivery" && !address) return { ok: false, message: "عنوان التوصيل مطلوب." };
  if (!paymentMethod) return { ok: false, message: "طريقة الدفع المتاحة حاليًا هي الدفع عند الاستلام." };
  if (!lines.length || lines.length > maxLines) return { ok: false, message: "عدد منتجات الطلب غير صالح." };
  const normalized = [];
  for (const line of lines) {
    const productId = String(line?.productId ?? "").slice(0, 80);
    const variantId = String(line?.variantId || "v1").slice(0, 40);
    const quantity = finite(line?.quantity, -1);
    if (!productId || !variantId || !Number.isFinite(quantity) || quantity <= 0) return { ok: false, message: "أحد أسطر الطلب يحتوي على كمية أو منتج غير صالح." };
    normalized.push({ productId, variantId, quantity });
  }
  const shippingFee = 0; // The server applies its configured delivery policy; never trust a browser-supplied fee.
  return { ok: true, value: { reference, submissionToken, customer: { name, phone, address, note: cleanText(customer.note, 1000), fulfillment, shippingFee }, lines: normalized, paymentMethod, createdAt: body.createdAt } };
}

export function makeOrderLine(product, variant, requested, index, now = Date.now()) {
  const unit = normalizeUnit(variant.unit);
  const rawQuantity = finite(requested.quantity, -1);
  if (unit === 'piece' && !Number.isInteger(rawQuantity)) throw new Error('كمية القطع يجب أن تكون عددًا صحيحًا.');
  const quantity = normalizeQty(rawQuantity, unit);
  const available = Math.max(0, round3(finite(variant.q) - finite(variant.reservedQty)));
  if (quantity === null || quantity <= 0) throw new Error("الكمية المطلوبة غير صالحة.");
  if (available < quantity) {
    const error = new Error(`المخزون المتاح غير كافٍ للمنتج ${cleanText(product.name, 120)} / ${cleanText(variant.name || "الأساسي", 60)}. المتاح ${available} والمطلوب ${quantity}.`);
    error.code = "INSUFFICIENT_STOCK";
    error.status = 409;
    throw error;
  }
  const measure = measurePerItem(variant);
  if (!(measure > 0)) throw new Error("أبعاد المنتج غير صالحة.");
  const price = salePrice(variant, now);
  const volume = round3(measure * quantity);
  const value = Math.round(volume * price.final * 100) / 100;
  return {
    index,
    productId: Number.isFinite(Number(product.id)) ? Number(product.id) : product.id,
    variantId: String(variant.id || requested.variantId || "v1"),
    variantName: cleanText(variant.name || "الأساسي", 60),
    sku: cleanText(variant.sku || product.sku, 40),
    category: cleanText(product.category || "خشب طبيعي", 80),
    name: cleanText(product.name, 120),
    description: cleanText(product.description, 500),
    type: cleanText(product.type, 80),
    L: finite(variant.L), W: finite(variant.W), T: finite(variant.T),
    quantity, volume, unit, unitPrice: price.final, baseUnitPrice: price.base,
    discountAmount: price.discount, discountLabel: price.discountLabel,
    pricingVersion: Math.max(1, Math.floor(finite(variant.pricing?.version, 1))),
    estimatedValue: value
  };
}

export function nextOrderStatus(current, next) {
  if (current === next) return true;
  return Array.isArray(ORDER_TRANSITIONS[current]) && ORDER_TRANSITIONS[current].includes(next);
}
