package com.adaptwaf.controlplane.service;

import com.adaptwaf.controlplane.model.PatternAggregateMetrics;
import com.adaptwaf.controlplane.repository.CandidateRepository;
import com.adaptwaf.controlplane.repository.PatternAggregateRepository;
import java.time.Instant;
import java.util.List;

/**
 * 自动建议候选任务。
 */
public class AutoSuggestJob {

    private final PatternAggregateRepository patternAggregateRepository;
    private final CandidateRepository candidateRepository;
    private final AutoSuggestService autoSuggestService;

    public AutoSuggestJob(
            PatternAggregateRepository patternAggregateRepository,
            CandidateRepository candidateRepository,
            AutoSuggestService autoSuggestService
    ) {
        this.patternAggregateRepository = patternAggregateRepository;
        this.candidateRepository = candidateRepository;
        this.autoSuggestService = autoSuggestService;
    }

    /**
     * 对指定窗口执行自动候选判定并落库。
     *
     * @param fromInclusive 起始时间（含）
     * @param toExclusive 结束时间（不含）
     */
    public void run(Instant fromInclusive, Instant toExclusive) {
        List<PatternAggregateMetrics> metricsList = patternAggregateRepository.queryWindow(fromInclusive, toExclusive);
        for (PatternAggregateMetrics metrics : metricsList) {
            boolean suggested = autoSuggestService.shouldSuggest(
                    metrics.hits(),
                    metrics.ratio2xx(),
                    metrics.uniqueIp(),
                    metrics.singleIpRatio(),
                    metrics.activeDays(),
                    metrics.peakDayRatio(),
                    metrics.ipHitCount()
            );
            if (suggested) {
                candidateRepository.upsertAutoSuggested(
                        metrics.patternKey(),
                        "high_freq_benign_pattern",
                        metrics
                );
            }
        }
    }
}
