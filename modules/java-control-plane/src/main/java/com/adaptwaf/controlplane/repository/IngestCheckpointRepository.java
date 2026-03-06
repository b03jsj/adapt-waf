package com.adaptwaf.controlplane.repository;

/**
 * 日志采集位点仓储接口。
 */
public interface IngestCheckpointRepository {

    /**
     * 读取采集位点。
     *
     * @param sourceNode 节点标识
     * @param filePath 文件路径
     * @return 已处理偏移量（字节）
     */
    long getOffset(String sourceNode, String filePath);

    /**
     * 更新采集位点。
     *
     * @param sourceNode 节点标识
     * @param filePath 文件路径
     * @param inode 文件 inode
     * @param offsetBytes 新偏移量（字节）
     */
    void saveOffset(String sourceNode, String filePath, long inode, long offsetBytes);
}
