package com.adaptwaf.controlplane.repository;

import com.adaptwaf.controlplane.model.ReviewAuditRecord;
import java.util.List;

/**
 * 审核审计仓储接口。
 */
public interface ReviewAuditRepository {

    /**
     * 追加一条审计记录。
     *
     * @param operator 操作人
     * @param action 动作
     * @param targetType 目标类型
     * @param targetId 目标 ID
     * @param beforeJson 变更前
     * @param afterJson 变更后
     * @param reason 原因
     * @param ticketId 工单号
     */
    void append(
            String operator,
            String action,
            String targetType,
            String targetId,
            String beforeJson,
            String afterJson,
            String reason,
            String ticketId
    );

    /**
     * 审计列表查询。
     *
     * @param limit 限制条数
     * @param offset 偏移量
     * @return 审计记录
     */
    List<ReviewAuditRecord> list(int limit, int offset);

    /**
     * 统计审计记录总数。
     *
     * @return 总数
     */
    long count();
}
