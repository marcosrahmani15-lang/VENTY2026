export const SCHEMA_SQL = `
-- 1. Customers Table
CREATE TABLE IF NOT EXISTS customers (
  id VARCHAR(64) PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  phone VARCHAR(32) NOT NULL UNIQUE,
  email VARCHAR(255),
  favourite_drink VARCHAR(255),
  status VARCHAR(32) NOT NULL DEFAULT 'Active',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_customers_phone ON customers(phone);

-- 2. Loyalty Accounts (1:1 with Customers)
CREATE TABLE IF NOT EXISTS loyalty_accounts (
  customer_id VARCHAR(64) PRIMARY KEY REFERENCES customers(id) ON DELETE CASCADE,
  current_stamp_count INT NOT NULL DEFAULT 0,
  lifetime_stamps INT NOT NULL DEFAULT 0,
  welcome_bonus_granted BOOLEAN NOT NULL DEFAULT FALSE,
  status VARCHAR(32) NOT NULL DEFAULT 'Active',
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 3. Loyalty Transactions
CREATE TABLE IF NOT EXISTS loyalty_transactions (
  id VARCHAR(64) PRIMARY KEY,
  customer_id VARCHAR(64) NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
  customer_name VARCHAR(255) NOT NULL,
  type VARCHAR(32) NOT NULL,
  stamps_delta INT NOT NULL,
  source VARCHAR(64),
  status VARCHAR(32) NOT NULL DEFAULT 'CONFIRMED',
  idempotency_key VARCHAR(128) UNIQUE,
  order_id VARCHAR(64),
  reward_id VARCHAR(64),
  note TEXT,
  previous_value INT,
  new_value INT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_loyalty_tx_customer ON loyalty_transactions(customer_id);
CREATE INDEX IF NOT EXISTS idx_loyalty_tx_order ON loyalty_transactions(order_id);

-- 4. Rewards (Available & Redeemed)
CREATE TABLE IF NOT EXISTS rewards (
  id VARCHAR(64) PRIMARY KEY,
  customer_id VARCHAR(64) NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
  customer_name VARCHAR(255) NOT NULL,
  customer_phone VARCHAR(32) NOT NULL,
  type VARCHAR(32) NOT NULL DEFAULT 'FREE_DRINK',
  status VARCHAR(32) NOT NULL DEFAULT 'AVAILABLE',
  redemption_code VARCHAR(32) UNIQUE,
  redemption_token VARCHAR(128) UNIQUE,
  issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ,
  redeemed_at TIMESTAMPTZ,
  redemption_staff_id VARCHAR(64),
  redemption_location VARCHAR(255),
  source_order_id VARCHAR(64),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_rewards_customer ON rewards(customer_id);
CREATE INDEX IF NOT EXISTS idx_rewards_code ON rewards(redemption_code);

-- 5. Orders
CREATE TABLE IF NOT EXISTS orders (
  id VARCHAR(64) PRIMARY KEY,
  customer_id VARCHAR(64) REFERENCES customers(id) ON DELETE SET NULL,
  customer_name VARCHAR(255) NOT NULL,
  customer_phone VARCHAR(32),
  total_amount NUMERIC(10, 2) NOT NULL DEFAULT 0,
  status VARCHAR(32) NOT NULL DEFAULT 'PENDING',
  pickup_time VARCHAR(64) NOT NULL DEFAULT '15 mins',
  notes TEXT,
  qualifies_for_loyalty BOOLEAN NOT NULL DEFAULT FALSE,
  loyalty_stamp_awarded BOOLEAN NOT NULL DEFAULT FALSE,
  loyalty_stamps_delta INT NOT NULL DEFAULT 0,
  loyalty_transaction_id VARCHAR(64),
  idempotency_key VARCHAR(128) UNIQUE,
  payload_fingerprint VARCHAR(128),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMPTZ,
  cancelled_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_orders_customer ON orders(customer_id);
CREATE INDEX IF NOT EXISTS idx_orders_status ON orders(status);
CREATE INDEX IF NOT EXISTS idx_orders_created_at ON orders(created_at DESC);

-- 6. Order Items
CREATE TABLE IF NOT EXISTS order_items (
  id VARCHAR(128) PRIMARY KEY,
  order_id VARCHAR(64) NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
  product_id VARCHAR(64) NOT NULL,
  name VARCHAR(255) NOT NULL,
  category VARCHAR(64) NOT NULL,
  unit_price NUMERIC(10, 2) NOT NULL,
  quantity INT NOT NULL DEFAULT 1,
  line_total NUMERIC(10, 2) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_order_items_order ON order_items(order_id);

-- 7. Store Settings & Config
CREATE TABLE IF NOT EXISTS store_settings (
  key VARCHAR(64) PRIMARY KEY,
  value JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 8. Customer Sessions (Durable multi-instance session storage)
CREATE TABLE IF NOT EXISTS customer_sessions (
  session_hash VARCHAR(64) PRIMARY KEY,
  customer_id VARCHAR(64) NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
  session_id VARCHAR(64) NOT NULL,
  role VARCHAR(32) NOT NULL DEFAULT 'CUSTOMER',
  expires_at BIGINT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON customer_sessions(expires_at);

-- 9. Customer OTP Challenges (Durable multi-instance OTP storage)
CREATE TABLE IF NOT EXISTS customer_otp_challenges (
  phone VARCHAR(32) PRIMARY KEY,
  code_hash VARCHAR(128) NOT NULL,
  name VARCHAR(255),
  email VARCHAR(255),
  favourite_drink VARCHAR(255),
  purpose VARCHAR(32) NOT NULL DEFAULT 'LOGIN',
  attempts_remaining INT NOT NULL DEFAULT 3,
  expires_at BIGINT NOT NULL,
  created_at BIGINT NOT NULL
);

-- 10. Audit Logs
CREATE TABLE IF NOT EXISTS audit_logs (
  id BIGSERIAL PRIMARY KEY,
  event_type VARCHAR(64) NOT NULL,
  details JSONB NOT NULL,
  timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_audit_logs_event ON audit_logs(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_logs_time ON audit_logs(timestamp DESC);
`;
