CREATE TABLE IF NOT EXISTS products (
  id TEXT PRIMARY KEY,
  payload JSONB NOT NULL,
  version BIGINT NOT NULL DEFAULT 1,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS products_updated_at_idx ON products(updated_at);

CREATE TABLE IF NOT EXISTS customers (
  id TEXT PRIMARY KEY,
  payload JSONB NOT NULL,
  version BIGINT NOT NULL DEFAULT 1,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS customers_phone_idx ON customers ((payload->>'phone'));

CREATE TABLE IF NOT EXISTS orders (
  reference TEXT PRIMARY KEY,
  payload JSONB NOT NULL,
  version BIGINT NOT NULL DEFAULT 1,
  submission_token_hash TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE orders ADD COLUMN IF NOT EXISTS submission_token_hash TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS orders_created_at_idx ON orders(created_at DESC);
CREATE INDEX IF NOT EXISTS orders_status_idx ON orders ((payload->>'status'));

CREATE TABLE IF NOT EXISTS idempotency_keys (
  key TEXT PRIMARY KEY,
  response JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idempotency_created_at_idx ON idempotency_keys(created_at);

CREATE TABLE IF NOT EXISTS revoked_tokens (
  jti TEXT PRIMARY KEY,
  expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS revoked_tokens_expiry_idx ON revoked_tokens(expires_at);
