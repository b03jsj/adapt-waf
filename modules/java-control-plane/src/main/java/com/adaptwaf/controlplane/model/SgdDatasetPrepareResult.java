package com.adaptwaf.controlplane.model;

import java.nio.file.Path;
import java.util.Map;

/**
 * SGD 样本准备结果。
 */
public record SgdDatasetPrepareResult(
        Path outputDir,
        long totalSamples,
        Map<String, Long> sourceCounts,
        Map<String, Long> attackTypeCounts
) {
}
