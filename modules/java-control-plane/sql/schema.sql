-- OpenResty WAF 控制面 MySQL 表结构（MySQL 8.0+）
-- 说明：waf_alert_event 建议按日分区，示例仅给出初始分区，生产需配合定时任务自动建分区/删分区。

CREATE TABLE IF NOT EXISTS waf_alert_event (
    id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    event_id VARCHAR(64) NOT NULL,
    event_time DATETIME(3) NOT NULL,
    event_date DATE NOT NULL,
    route_key VARCHAR(255) NOT NULL,
    method VARCHAR(16) NOT NULL,
    content_type VARCHAR(128) NOT NULL,
    surface VARCHAR(32) NOT NULL,
    field_name VARCHAR(255) NOT NULL DEFAULT '-',
    json_path VARCHAR(255) NOT NULL DEFAULT '-',
    detector VARCHAR(64) NOT NULL,
    detector_signature VARCHAR(255) NOT NULL DEFAULT '-',
    threat_classification VARCHAR(32) NOT NULL DEFAULT 'none',
    alert_level VARCHAR(16) NOT NULL DEFAULT 'info',
    final_action VARCHAR(32) NOT NULL DEFAULT 'allow',
    status_code INT NOT NULL DEFAULT 0,
    client_ip VARCHAR(64) NOT NULL,
    user_agent_hash VARCHAR(64) NOT NULL,
    pattern_key VARCHAR(768) NOT NULL,
    pattern_key_text VARCHAR(768) NOT NULL,
    pattern_key_hash VARCHAR(64) NOT NULL,
    first_seen_pattern TINYINT(1) NOT NULL DEFAULT 0,
    exemption_applied TINYINT(1) NOT NULL DEFAULT 0,
    exemption_id VARCHAR(64) NULL,
    exemption_match_scope VARCHAR(64) NULL,
    policy_decision_basis VARCHAR(64) NOT NULL DEFAULT 'none',
    normalization_profile VARCHAR(32) NOT NULL DEFAULT 'norm-v1',
    payload_json JSON NULL,
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    UNIQUE KEY uniq_event_id (event_id),
    KEY idx_time (event_time),
    KEY idx_review (alert_level, first_seen_pattern, event_time),
    KEY idx_pattern (pattern_key(255), event_time),
    KEY idx_pattern_hash (pattern_key_hash, event_time),
    KEY idx_route_field (route_key, field_name, event_time),
    KEY idx_first_seen_time (first_seen_pattern, event_time),
    KEY idx_first_seen_detector (first_seen_pattern, detector, event_time),
    KEY idx_first_seen_surface (first_seen_pattern, surface, event_time)
) ENGINE=InnoDB
PARTITION BY RANGE COLUMNS(event_date) (
    PARTITION p202603 VALUES LESS THAN ('2026-04-01'),
    PARTITION pmax VALUES LESS THAN (MAXVALUE)
);

CREATE TABLE IF NOT EXISTS waf_pattern_state (
    pattern_key_hash VARCHAR(64) NOT NULL PRIMARY KEY,
    pattern_key_text VARCHAR(768) NOT NULL,
    pattern_state ENUM('unknown', 'benign_confirmed', 'attack_confirmed') NOT NULL DEFAULT 'unknown',
    first_seen DATETIME(3) NOT NULL,
    last_seen DATETIME(3) NOT NULL,
    hit_count BIGINT NOT NULL DEFAULT 1,
    last_decision VARCHAR(64) NOT NULL DEFAULT 'none',
    updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    KEY idx_pattern_text (pattern_key_text(255))
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS waf_exemption_candidate (
    candidate_id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    pattern_key_hash VARCHAR(64) NOT NULL,
    pattern_key_text VARCHAR(768) NOT NULL,
    candidate_status ENUM('auto_suggested', 'approved', 'rejected', 'expired') NOT NULL DEFAULT 'auto_suggested',
    candidate_reason VARCHAR(64) NOT NULL,
    metrics_snapshot JSON NULL,
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    KEY idx_candidate_status (candidate_status, updated_at),
    KEY idx_candidate_pattern_hash (pattern_key_hash),
    KEY idx_candidate_pattern_text (pattern_key_text(255))
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS waf_exemption_rule (
    rule_id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    exemption_id VARCHAR(64) NOT NULL,
    enabled TINYINT(1) NOT NULL DEFAULT 1,
    match_scope ENUM('signature_exact', 'detector_field') NOT NULL DEFAULT 'signature_exact',
    detector VARCHAR(64) NOT NULL,
    signature VARCHAR(255) NULL,
    method VARCHAR(16) NOT NULL,
    route_key VARCHAR(255) NOT NULL,
    content_type VARCHAR(128) NOT NULL,
    surface VARCHAR(32) NOT NULL,
    field_name VARCHAR(255) NOT NULL DEFAULT '-',
    json_path VARCHAR(255) NOT NULL DEFAULT '-',
    action VARCHAR(32) NOT NULL DEFAULT 'allow_log',
    reason VARCHAR(255) NOT NULL,
    owner VARCHAR(64) NOT NULL,
    source_event_ids JSON NULL,
    expires_at DATETIME(3) NULL,
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    UNIQUE KEY uniq_exemption_id (exemption_id),
    KEY idx_rule_lookup (enabled, detector, method, route_key, content_type, surface, field_name, json_path)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS waf_exemption_publish (
    publish_id VARCHAR(64) NOT NULL PRIMARY KEY,
    generation BIGINT NOT NULL,
    sha256 VARCHAR(128) NOT NULL,
    operator VARCHAR(64) NOT NULL,
    reason VARCHAR(255) NOT NULL,
    status ENUM('running', 'partial_success', 'success', 'failed') NOT NULL DEFAULT 'running',
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    UNIQUE KEY uniq_generation (generation)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS waf_exemption_publish_snapshot (
    id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    publish_id VARCHAR(64) NOT NULL,
    generation BIGINT NOT NULL,
    sha256 VARCHAR(128) NOT NULL,
    compiled_content LONGBLOB NOT NULL,
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    UNIQUE KEY uniq_publish_snapshot_publish_id (publish_id),
    UNIQUE KEY uniq_publish_snapshot_generation (generation),
    CONSTRAINT fk_publish_snapshot_publish
        FOREIGN KEY (publish_id) REFERENCES waf_exemption_publish(publish_id)
        ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS waf_exemption_publish_node_result (
    id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    publish_id VARCHAR(64) NOT NULL,
    node_id VARCHAR(128) NOT NULL,
    node_status ENUM('pending', 'success', 'failed') NOT NULL DEFAULT 'pending',
    current_generation BIGINT NOT NULL DEFAULT 0,
    last_error VARCHAR(512) NULL,
    updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    UNIQUE KEY uniq_publish_node (publish_id, node_id),
    KEY idx_node_status (node_status, updated_at),
    CONSTRAINT fk_publish_node_publish
        FOREIGN KEY (publish_id) REFERENCES waf_exemption_publish(publish_id)
        ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS waf_review_audit (
    audit_id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    operator VARCHAR(64) NOT NULL,
    action VARCHAR(64) NOT NULL,
    target_type VARCHAR(64) NOT NULL,
    target_id VARCHAR(128) NOT NULL,
    before_json JSON NULL,
    after_json JSON NULL,
    reason VARCHAR(255) NOT NULL,
    ticket_id VARCHAR(128) NULL,
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    KEY idx_audit_time (created_at),
    KEY idx_audit_operator (operator, created_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS waf_ingest_checkpoint (
    id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    source_node VARCHAR(128) NOT NULL,
    file_path VARCHAR(512) NOT NULL,
    inode BIGINT NOT NULL,
    offset_bytes BIGINT NOT NULL,
    updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    UNIQUE KEY uniq_source_file (source_node, file_path)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS waf_batch_operation (
    operation_id VARCHAR(64) NOT NULL PRIMARY KEY,
    operation_type ENUM('approve', 'reject') NOT NULL,
    status ENUM('running', 'success', 'partial_success', 'failed') NOT NULL DEFAULT 'running',
    operator VARCHAR(64) NOT NULL,
    reason VARCHAR(255) NOT NULL,
    ticket_id VARCHAR(128) NULL,
    requested_scope VARCHAR(32) NULL,
    requested_pattern_state VARCHAR(32) NULL,
    total_count INT NOT NULL DEFAULT 0,
    success_count INT NOT NULL DEFAULT 0,
    failed_count INT NOT NULL DEFAULT 0,
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    KEY idx_batch_op_status_time (status, created_at),
    KEY idx_batch_op_operator_time (operator, created_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS waf_batch_operation_item (
    id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    operation_id VARCHAR(64) NOT NULL,
    candidate_id BIGINT NOT NULL,
    success TINYINT(1) NOT NULL,
    exemption_id VARCHAR(64) NULL,
    match_scope VARCHAR(32) NULL,
    error VARCHAR(512) NULL,
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    UNIQUE KEY uniq_batch_op_candidate (operation_id, candidate_id),
    KEY idx_batch_item_op_time (operation_id, id),
    CONSTRAINT fk_batch_item_operation
        FOREIGN KEY (operation_id) REFERENCES waf_batch_operation(operation_id)
        ON DELETE CASCADE
) ENGINE=InnoDB;
