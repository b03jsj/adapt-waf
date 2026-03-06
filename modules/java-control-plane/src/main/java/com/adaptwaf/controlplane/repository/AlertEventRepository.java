package com.adaptwaf.controlplane.repository;

import com.adaptwaf.controlplane.model.WafAlertEvent;
import com.adaptwaf.controlplane.model.FirstSeenEvent;
import com.adaptwaf.controlplane.model.FirstSeenQuery;
import java.util.List;

/**
 * 告警事件仓储接口。
 */
public interface AlertEventRepository {

    /**
     * 批量写入告警事件，要求幂等（按 event_id 去重）。
     *
     * @param events 事件列表
     */
    void saveBatch(List<WafAlertEvent> events);

    /**
     * 查询 first-seen 审核队列。
     *
     * @param limit 限制条数
     * @param offset 偏移量
     * @return 队列事件
     */
    List<FirstSeenEvent> listFirstSeenQueue(int limit, int offset);

    /**
     * 按条件查询 first-seen 审核队列。
     *
     * @param query 查询条件
     * @param limit 限制条数
     * @param offset 偏移量
     * @return 队列事件
     */
    List<FirstSeenEvent> listFirstSeenQueue(FirstSeenQuery query, int limit, int offset);

    /**
     * 统计 first-seen 队列总数。
     *
     * @param query 查询条件
     * @return 总数
     */
    long countFirstSeenQueue(FirstSeenQuery query);
}
