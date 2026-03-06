package com.adaptwaf.controlplane.repository;

import java.util.List;
import java.util.Map;

/**
 * 豁免规则仓储接口。
 */
public interface ExemptionRepository {

    /**
     * 读取当前已审批豁免规则。
     *
     * @return 规则列表，每条规则用键值结构表达，供编译器生成 compiled.json
     */
    List<Map<String, Object>> loadApprovedRules();

    /**
     * 新增一条豁免规则。
     *
     * @param rule 规则键值
     */
    void insertRule(Map<String, Object> rule);
}
