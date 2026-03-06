package com.adaptwaf.controlplane.service;

import java.util.Map;

/**
 * Shannon 熵计算服务。
 */
public final class EntropyService {

    private EntropyService() {
    }

    /**
     * 计算来源 IP 分布熵，单位 bits。
     *
     * @param ipHitCount 来源 IP 命中次数
     * @return 熵值（bits）
     */
    public static double shannonEntropyBits(Map<String, Long> ipHitCount) {
        long total = ipHitCount.values().stream().mapToLong(Long::longValue).sum();
        if (total <= 0) {
            return 0D;
        }

        double entropy = 0D;
        for (Long count : ipHitCount.values()) {
            if (count == null || count <= 0) {
                continue;
            }
            double p = (double) count / (double) total;
            entropy -= p * (Math.log(p) / Math.log(2D));
        }
        return entropy;
    }

    /**
     * 按熵值换算等效独立来源数（2^H）。
     *
     * @param entropyBits 熵值（bits）
     * @return 等效来源数
     */
    public static double effectiveCount(double entropyBits) {
        return Math.pow(2D, entropyBits);
    }
}
