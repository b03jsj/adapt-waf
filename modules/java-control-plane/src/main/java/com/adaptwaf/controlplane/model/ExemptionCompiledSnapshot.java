package com.adaptwaf.controlplane.model;

/**
 * 编译后的豁免快照。
 */
public record ExemptionCompiledSnapshot(
        long generation,
        String publishId,
        String sha256,
        byte[] content
) {
}
