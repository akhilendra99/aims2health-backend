-- Run this schema change in the target environment before deploying code that
-- enforces account-level password-login lockout. No production DB was changed.
CREATE TABLE IF NOT EXISTS login_lockout_state (
  lock_key CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  window_started_at DATETIME(3) NOT NULL,
  failed_attempts INT UNSIGNED NOT NULL,
  locked_until DATETIME(3) NULL,
  expires_at DATETIME(3) NOT NULL,
  PRIMARY KEY (lock_key),
  KEY idx_login_lockout_expires_at (expires_at)
) ENGINE=InnoDB;
