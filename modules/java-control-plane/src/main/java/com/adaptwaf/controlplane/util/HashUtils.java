package com.adaptwaf.controlplane.util;

import java.security.MessageDigest;

/**
 * 哈希工具类。
 */
public final class HashUtils {

    private HashUtils() {
    }

    /**
     * 计算字节数组的 SHA-256 十六进制字符串。
     *
     * @param data 输入数据
     * @return 十六进制摘要
     */
    public static String sha256Hex(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(data);
            StringBuilder sb = new StringBuilder(hash.length * 2);
            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            throw new IllegalStateException("sha256_compute_failed", e);
        }
    }
}
