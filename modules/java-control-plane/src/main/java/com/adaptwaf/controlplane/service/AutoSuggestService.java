package com.adaptwaf.controlplane.service;

import java.util.Map;

/**
 * Shadow 期自动豁免候选判定服务（骨架）。
 */
public class AutoSuggestService {

    private final long minHits;
    private final double min2xxRatio;
    private final int minUniqueIp;
    private final double maxSingleIpRatio;
    private final double minIpEntropyBits;
    private final int minActiveDays;
    private final double maxPeakDayRatio;

    public AutoSuggestService(
            long minHits,
            double min2xxRatio,
            int minUniqueIp,
            double maxSingleIpRatio,
            double minIpEntropyBits,
            int minActiveDays,
            double maxPeakDayRatio
    ) {
        this.minHits = minHits;
        this.min2xxRatio = min2xxRatio;
        this.minUniqueIp = minUniqueIp;
        this.maxSingleIpRatio = maxSingleIpRatio;
        this.minIpEntropyBits = minIpEntropyBits;
        this.minActiveDays = minActiveDays;
        this.maxPeakDayRatio = maxPeakDayRatio;
    }

    /**
     * 判定是否满足自动候选条件。
     *
     * @param hits 命中次数
     * @param ratio2xx 2xx 比例
     * @param uniqueIp 独立 IP 数
     * @param singleIpRatio 单 IP 占比
     * @param activeDays 活跃天数
     * @param peakDayRatio 单日峰值占比
     * @param ipHitCount IP 命中分布
     * @return true 表示可标记为 auto_suggested
     */
    public boolean shouldSuggest(
            long hits,
            double ratio2xx,
            int uniqueIp,
            double singleIpRatio,
            int activeDays,
            double peakDayRatio,
            Map<String, Long> ipHitCount
    ) {
        // 基于来源 IP 请求分布计算 Shannon entropy（bits）。
        // 例如 entropy=2.5 大约对应 2^2.5≈5.66（约 6 个均匀独立来源）。
        double entropy = EntropyService.shannonEntropyBits(ipHitCount);
        return hits >= minHits
                && ratio2xx >= min2xxRatio
                && uniqueIp >= minUniqueIp
                && singleIpRatio < maxSingleIpRatio
                && activeDays >= minActiveDays
                && peakDayRatio <= maxPeakDayRatio
                && entropy >= minIpEntropyBits;
    }
}
