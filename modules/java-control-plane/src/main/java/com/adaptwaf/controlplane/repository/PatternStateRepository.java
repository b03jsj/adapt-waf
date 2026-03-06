package com.adaptwaf.controlplane.repository;

import java.time.Instant;
import java.util.Map;

/**
 * 模式状态仓储接口。
 */
public interface PatternStateRepository {

    /**
     * 更新模式命中统计，并返回是否首次入库。
     * 约定：以“首次成功入库”为 first_seen 判定标准，避免乱序歧义。
     *
     * @param patternKey 模式键
     * @param eventTime 事件时间
     * @param decision 最新策略结果
     * @return true 表示首次见到该模式
     */
    boolean upsertAndCheckFirstSeen(String patternKey, Instant eventTime, String decision);

    /**
     * 更新模式状态。
     *
     * @param patternKey 模式键
     * @param patternState 状态值
     */
    void updatePatternState(String patternKey, String patternState);

    /**
     * 加载运行时需要下发的模式状态索引。
     *
     * @return key 为 pattern_key_hash，value 为状态（benign_confirmed/attack_confirmed）
     */
    Map<String, String> loadRuntimePatternStateIndex();
}
