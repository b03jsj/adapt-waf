-- OpenResty WAF 增量迁移脚本（MySQL 8.0+）
-- 目标：
-- 1) 已有环境补齐 pattern_key_text/pattern_key_hash
-- 2) 对 waf_pattern_state / waf_exemption_candidate 做兼容升级
-- 3) 尽量幂等，支持重复执行

SET @schema_name = DATABASE();

-- =========================================================
-- 1) waf_alert_event 升级
-- =========================================================
ALTER TABLE waf_alert_event
    ADD COLUMN IF NOT EXISTS pattern_key_text VARCHAR(768) NULL AFTER pattern_key,
    ADD COLUMN IF NOT EXISTS pattern_key_hash VARCHAR(64) NULL AFTER pattern_key_text;

UPDATE waf_alert_event
SET pattern_key_text = pattern_key
WHERE pattern_key_text IS NULL OR pattern_key_text = '';

UPDATE waf_alert_event
SET pattern_key_hash = SHA2(pattern_key_text, 256)
WHERE pattern_key_hash IS NULL OR pattern_key_hash = '';

ALTER TABLE waf_alert_event
    MODIFY COLUMN pattern_key_text VARCHAR(768) NOT NULL,
    MODIFY COLUMN pattern_key_hash VARCHAR(64) NOT NULL;

SET @idx_exists = (
    SELECT COUNT(1)
    FROM information_schema.statistics
    WHERE table_schema = @schema_name
      AND table_name = 'waf_alert_event'
      AND index_name = 'idx_pattern_hash'
);
SET @sql = IF(
    @idx_exists = 0,
    'ALTER TABLE waf_alert_event ADD INDEX idx_pattern_hash (pattern_key_hash, event_time)',
    'SELECT 1'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- =========================================================
-- 2) waf_pattern_state 升级
-- =========================================================
ALTER TABLE waf_pattern_state
    ADD COLUMN IF NOT EXISTS pattern_key_text VARCHAR(768) NULL,
    ADD COLUMN IF NOT EXISTS pattern_key_hash VARCHAR(64) NULL;

SET @legacy_pattern_col_exists = (
    SELECT COUNT(1)
    FROM information_schema.columns
    WHERE table_schema = @schema_name
      AND table_name = 'waf_pattern_state'
      AND column_name = 'pattern_key'
);

SET @sql = IF(
    @legacy_pattern_col_exists = 1,
    'UPDATE waf_pattern_state SET pattern_key_text = COALESCE(NULLIF(pattern_key_text, ''''), pattern_key) WHERE pattern_key_text IS NULL OR pattern_key_text = ''''',
    'SELECT 1'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

UPDATE waf_pattern_state
SET pattern_key_hash = SHA2(pattern_key_text, 256)
WHERE pattern_key_hash IS NULL OR pattern_key_hash = '';

ALTER TABLE waf_pattern_state
    MODIFY COLUMN pattern_key_text VARCHAR(768) NOT NULL,
    MODIFY COLUMN pattern_key_hash VARCHAR(64) NOT NULL;

-- 若旧表仍是 pattern_key 主键，则切换到 pattern_key_hash 主键。
SET @pk_col = (
    SELECT column_name
    FROM information_schema.key_column_usage
    WHERE table_schema = @schema_name
      AND table_name = 'waf_pattern_state'
      AND constraint_name = 'PRIMARY'
    ORDER BY ordinal_position
    LIMIT 1
);

SET @sql = IF(
    @pk_col IS NULL,
    'ALTER TABLE waf_pattern_state ADD PRIMARY KEY (pattern_key_hash)',
    IF(@pk_col = 'pattern_key_hash', 'SELECT 1', 'ALTER TABLE waf_pattern_state DROP PRIMARY KEY, ADD PRIMARY KEY (pattern_key_hash)')
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- 兼容旧列：若存在 pattern_key 列，改为可空，避免新代码插入失败。
SET @sql = IF(
    @legacy_pattern_col_exists = 1,
    'ALTER TABLE waf_pattern_state MODIFY COLUMN pattern_key VARCHAR(768) NULL',
    'SELECT 1'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @idx_exists = (
    SELECT COUNT(1)
    FROM information_schema.statistics
    WHERE table_schema = @schema_name
      AND table_name = 'waf_pattern_state'
      AND index_name = 'idx_pattern_text'
);
SET @sql = IF(
    @idx_exists = 0,
    'ALTER TABLE waf_pattern_state ADD INDEX idx_pattern_text (pattern_key_text(255))',
    'SELECT 1'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- =========================================================
-- 3) waf_exemption_candidate 升级
-- =========================================================
ALTER TABLE waf_exemption_candidate
    ADD COLUMN IF NOT EXISTS pattern_key_text VARCHAR(768) NULL AFTER candidate_id,
    ADD COLUMN IF NOT EXISTS pattern_key_hash VARCHAR(64) NULL AFTER pattern_key_text;

SET @legacy_candidate_pattern_col_exists = (
    SELECT COUNT(1)
    FROM information_schema.columns
    WHERE table_schema = @schema_name
      AND table_name = 'waf_exemption_candidate'
      AND column_name = 'pattern_key'
);

SET @sql = IF(
    @legacy_candidate_pattern_col_exists = 1,
    'UPDATE waf_exemption_candidate SET pattern_key_text = COALESCE(NULLIF(pattern_key_text, ''''), pattern_key) WHERE pattern_key_text IS NULL OR pattern_key_text = ''''',
    'SELECT 1'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

UPDATE waf_exemption_candidate
SET pattern_key_hash = SHA2(pattern_key_text, 256)
WHERE pattern_key_hash IS NULL OR pattern_key_hash = '';

ALTER TABLE waf_exemption_candidate
    MODIFY COLUMN pattern_key_text VARCHAR(768) NOT NULL,
    MODIFY COLUMN pattern_key_hash VARCHAR(64) NOT NULL;

SET @sql = IF(
    @legacy_candidate_pattern_col_exists = 1,
    'ALTER TABLE waf_exemption_candidate MODIFY COLUMN pattern_key VARCHAR(768) NULL',
    'SELECT 1'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @idx_exists = (
    SELECT COUNT(1)
    FROM information_schema.statistics
    WHERE table_schema = @schema_name
      AND table_name = 'waf_exemption_candidate'
      AND index_name = 'idx_candidate_pattern_hash'
);
SET @sql = IF(
    @idx_exists = 0,
    'ALTER TABLE waf_exemption_candidate ADD INDEX idx_candidate_pattern_hash (pattern_key_hash)',
    'SELECT 1'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @idx_exists = (
    SELECT COUNT(1)
    FROM information_schema.statistics
    WHERE table_schema = @schema_name
      AND table_name = 'waf_exemption_candidate'
      AND index_name = 'idx_candidate_pattern_text'
);
SET @sql = IF(
    @idx_exists = 0,
    'ALTER TABLE waf_exemption_candidate ADD INDEX idx_candidate_pattern_text (pattern_key_text(255))',
    'SELECT 1'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SELECT 'migration_20260305_incremental_upgrade_done' AS migration_status;

