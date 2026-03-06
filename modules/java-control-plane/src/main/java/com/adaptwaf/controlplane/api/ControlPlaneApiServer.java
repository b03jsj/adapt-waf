package com.adaptwaf.controlplane.api;

import com.adaptwaf.controlplane.config.ControlPlaneConfig;
import com.adaptwaf.controlplane.model.CandidateQuery;
import com.adaptwaf.controlplane.model.BatchOperation;
import com.adaptwaf.controlplane.model.BatchOperationItem;
import com.adaptwaf.controlplane.model.ExemptionCandidate;
import com.adaptwaf.controlplane.model.FirstSeenEvent;
import com.adaptwaf.controlplane.model.FirstSeenQuery;
import com.adaptwaf.controlplane.model.NodePublishResult;
import com.adaptwaf.controlplane.repository.PublishRepository;
import com.adaptwaf.controlplane.service.BatchOperationService;
import com.adaptwaf.controlplane.service.ExemptionPublishService;
import com.adaptwaf.controlplane.service.ReviewWorkflowService;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.Executors;

/**
 * 控制面审核 API 服务。
 */
public class ControlPlaneApiServer {

    private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() {
    };

    private final ControlPlaneConfig config;
    private final ObjectMapper objectMapper;
    private final ReviewWorkflowService reviewWorkflowService;
    private final BatchOperationService batchOperationService;
    private final ExemptionPublishService exemptionPublishService;
    private final PublishRepository publishRepository;

    public ControlPlaneApiServer(
            ControlPlaneConfig config,
            ObjectMapper objectMapper,
            ReviewWorkflowService reviewWorkflowService,
            BatchOperationService batchOperationService,
            ExemptionPublishService exemptionPublishService,
            PublishRepository publishRepository
    ) {
        this.config = config;
        this.objectMapper = objectMapper;
        this.reviewWorkflowService = reviewWorkflowService;
        this.batchOperationService = batchOperationService;
        this.exemptionPublishService = exemptionPublishService;
        this.publishRepository = publishRepository;
    }

    /**
     * 启动 HTTP 服务并阻塞主线程。
     *
     * @throws Exception 启动异常
     */
    public void startAndBlock() throws Exception {
        InetSocketAddress address = new InetSocketAddress(config.reviewApiHost(), config.reviewApiPort());
        HttpServer server = HttpServer.create(address, 0);
        server.createContext("/api/v1/review", this::handleReviewApi);
        server.setExecutor(Executors.newFixedThreadPool(8));
        server.start();
        System.out.println("review_api_started host=" + config.reviewApiHost() + " port=" + config.reviewApiPort());
        Thread.currentThread().join();
    }

    private void handleReviewApi(HttpExchange exchange) throws IOException {
        try {
            if (!authorize(exchange)) {
                writeJson(exchange, 401, Map.of("error", "unauthorized"));
                return;
            }

            String method = exchange.getRequestMethod();
            String path = exchange.getRequestURI().getPath();

            if ("GET".equals(method) && "/api/v1/review/healthz".equals(path)) {
                writeJson(exchange, 200, Map.of("status", "ok"));
                return;
            }
            if ("GET".equals(method) && "/api/v1/review/first-seen".equals(path)) {
                handleFirstSeen(exchange);
                return;
            }
            if ("GET".equals(method) && "/api/v1/review/candidates".equals(path)) {
                handleCandidates(exchange);
                return;
            }
            if ("GET".equals(method) && "/api/v1/review/audit".equals(path)) {
                handleAudit(exchange);
                return;
            }
            if ("GET".equals(method) && "/api/v1/review/publish".equals(path)) {
                handlePublishList(exchange);
                return;
            }
            if ("GET".equals(method) && "/api/v1/review/summary".equals(path)) {
                handleSummary(exchange);
                return;
            }
            if ("POST".equals(method) && path.matches("^/api/v1/review/candidates/\\d+/approve$")) {
                handleApproveCandidate(exchange, path);
                return;
            }
            if ("POST".equals(method) && path.matches("^/api/v1/review/candidates/\\d+/reject$")) {
                handleRejectCandidate(exchange, path);
                return;
            }
            if ("POST".equals(method) && "/api/v1/review/candidates/batch/approve".equals(path)) {
                handleBatchApprove(exchange);
                return;
            }
            if ("POST".equals(method) && "/api/v1/review/candidates/batch/reject".equals(path)) {
                handleBatchReject(exchange);
                return;
            }
            if ("POST".equals(method) && "/api/v1/review/candidates/batch/approve-async".equals(path)) {
                handleBatchApproveAsync(exchange);
                return;
            }
            if ("POST".equals(method) && "/api/v1/review/candidates/batch/reject-async".equals(path)) {
                handleBatchRejectAsync(exchange);
                return;
            }
            if ("GET".equals(method) && "/api/v1/review/candidates/batch".equals(path)) {
                handleBatchOperations(exchange);
                return;
            }
            if ("GET".equals(method) && path.matches("^/api/v1/review/candidates/batch/[A-Za-z0-9_\\-]+$")) {
                handleBatchOperationStatus(exchange, path);
                return;
            }
            if ("GET".equals(method) && path.matches("^/api/v1/review/candidates/batch/[A-Za-z0-9_\\-]+/items$")) {
                handleBatchOperationItems(exchange, path);
                return;
            }
            if ("POST".equals(method) && "/api/v1/review/publish".equals(path)) {
                handlePublish(exchange);
                return;
            }
            if ("POST".equals(method) && "/api/v1/review/rollback".equals(path)) {
                handleRollback(exchange);
                return;
            }
            if ("GET".equals(method) && path.matches("^/api/v1/review/publish/[^/]+/nodes$")) {
                handlePublishNodes(exchange, path);
                return;
            }

            writeJson(exchange, 404, Map.of("error", "not_found"));
        } catch (IllegalArgumentException e) {
            writeJson(exchange, 400, Map.of("error", safeError(e)));
        } catch (Exception e) {
            writeJson(exchange, 500, Map.of("error", safeError(e)));
        } finally {
            exchange.close();
        }
    }

    private void handleFirstSeen(HttpExchange exchange) throws IOException {
        Map<String, String> query = parseQuery(exchange.getRequestURI().getRawQuery());
        int limit = parseInt(query.get("limit"), 100);
        int offset = parseInt(query.get("offset"), 0);
        FirstSeenQuery firstSeenQuery = new FirstSeenQuery(
                queryText(query, "route_key"),
                queryText(query, "detector"),
                queryText(query, "method"),
                queryText(query, "content_type"),
                queryText(query, "surface"),
                queryText(query, "alert_level"),
                parseInstant(queryText(query, "from_time")),
                parseInstant(queryText(query, "to_time"))
        );
        List<FirstSeenEvent> items = reviewWorkflowService.listFirstSeenQueue(firstSeenQuery, limit, offset);
        long total = reviewWorkflowService.countFirstSeenQueue(firstSeenQuery);

        if (isCsvFormat(query)) {
            List<List<String>> rows = new ArrayList<>();
            for (FirstSeenEvent item : items) {
                rows.add(List.of(
                        safeCsv(item.eventId()),
                        safeCsv(item.eventTime().toString()),
                        safeCsv(item.routeKey()),
                        safeCsv(item.method()),
                        safeCsv(item.contentType()),
                        safeCsv(item.surface()),
                        safeCsv(item.fieldName()),
                        safeCsv(item.jsonPath()),
                        safeCsv(item.detector()),
                        safeCsv(item.detectorSignature()),
                        safeCsv(item.patternKey()),
                        safeCsv(item.alertLevel()),
                        safeCsv(item.finalAction()),
                        safeCsv(item.policyDecisionBasis())
                ));
            }
            writeCsv(
                    exchange,
                    "first-seen.csv",
                    List.of(
                            "event_id", "event_time", "route_key", "method", "content_type", "surface",
                            "field_name", "json_path", "detector", "detector_signature",
                            "pattern_key", "alert_level", "final_action", "policy_decision_basis"
                    ),
                    rows
            );
            return;
        }

        writeJson(exchange, 200, Map.of(
                "items", items,
                "total", total,
                "limit", limit,
                "offset", offset
        ));
    }

    private void handleCandidates(HttpExchange exchange) throws IOException {
        Map<String, String> query = parseQuery(exchange.getRequestURI().getRawQuery());
        String status = query.getOrDefault("status", "auto_suggested");
        int limit = parseInt(query.get("limit"), 100);
        int offset = parseInt(query.get("offset"), 0);
        CandidateQuery candidateQuery = new CandidateQuery(
                status,
                queryText(query, "reason_like"),
                queryText(query, "pattern_key_like"),
                parseInstant(queryText(query, "updated_from")),
                parseInstant(queryText(query, "updated_to"))
        );
        List<ExemptionCandidate> items = reviewWorkflowService.listCandidates(candidateQuery, limit, offset);
        long total = reviewWorkflowService.countCandidates(candidateQuery);

        if (isCsvFormat(query)) {
            List<List<String>> rows = new ArrayList<>();
            for (ExemptionCandidate item : items) {
                rows.add(List.of(
                        Long.toString(item.candidateId()),
                        safeCsv(item.patternKey()),
                        safeCsv(item.candidateStatus()),
                        safeCsv(item.candidateReason()),
                        safeCsv(item.createdAt().toString()),
                        safeCsv(item.updatedAt().toString())
                ));
            }
            writeCsv(
                    exchange,
                    "candidates.csv",
                    List.of("candidate_id", "pattern_key", "candidate_status", "candidate_reason", "created_at", "updated_at"),
                    rows
            );
            return;
        }

        writeJson(exchange, 200, Map.of(
                "items", items,
                "total", total,
                "status", status,
                "limit", limit,
                "offset", offset
        ));
    }

    private void handleAudit(HttpExchange exchange) throws IOException {
        Map<String, String> query = parseQuery(exchange.getRequestURI().getRawQuery());
        int limit = parseInt(query.get("limit"), 100);
        int offset = parseInt(query.get("offset"), 0);
        writeJson(exchange, 200, Map.of(
                "items", reviewWorkflowService.listAudit(limit, offset),
                "total", reviewWorkflowService.countAudit(),
                "limit", limit,
                "offset", offset
        ));
    }

    private void handlePublishList(HttpExchange exchange) throws IOException {
        Map<String, String> query = parseQuery(exchange.getRequestURI().getRawQuery());
        int limit = parseInt(query.get("limit"), 50);
        int offset = parseInt(query.get("offset"), 0);
        String status = queryText(query, "status");
        writeJson(exchange, 200, Map.of(
                "items", publishRepository.listPublishes(status, limit, offset),
                "total", publishRepository.countPublishes(status),
                "status", status,
                "limit", limit,
                "offset", offset
        ));
    }

    private void handleApproveCandidate(HttpExchange exchange, String path) throws IOException {
        long candidateId = parseCandidateId(path);
        Map<String, Object> body = readBodyAsMap(exchange);
        String operator = text(body, "operator", "unknown");
        String reason = text(body, "reason", "approved");
        String ticketId = text(body, "ticket_id", null);
        String matchScope = text(body, "match_scope", "signature_exact");
        String expiresAt = text(body, "expires_at", null);

        ReviewWorkflowService.ApprovalResult result = reviewWorkflowService.approveCandidate(
                candidateId,
                operator,
                reason,
                ticketId,
                matchScope,
                expiresAt
        );
        writeJson(exchange, 200, Map.of(
                "approved", true,
                "candidate_id", result.candidateId(),
                "exemption_id", result.exemptionId(),
                "match_scope", result.matchScope()
        ));
    }

    private void handleRejectCandidate(HttpExchange exchange, String path) throws IOException {
        long candidateId = parseCandidateId(path);
        Map<String, Object> body = readBodyAsMap(exchange);
        String operator = text(body, "operator", "unknown");
        String reason = text(body, "reason", "rejected");
        String ticketId = text(body, "ticket_id", null);
        String patternState = text(body, "pattern_state", "unknown");

        reviewWorkflowService.rejectCandidate(
                candidateId,
                operator,
                reason,
                ticketId,
                patternState
        );
        writeJson(exchange, 200, Map.of(
                "rejected", true,
                "candidate_id", candidateId
        ));
    }

    private void handleBatchApprove(HttpExchange exchange) throws IOException {
        Map<String, Object> body = readBodyAsMap(exchange);
        List<Long> candidateIds = parseCandidateIds(body.get("candidate_ids"));
        String operator = text(body, "operator", "unknown");
        String reason = text(body, "reason", "approved");
        String ticketId = text(body, "ticket_id", null);
        String matchScope = text(body, "match_scope", "signature_exact");
        String expiresAt = text(body, "expires_at", null);
        Map<String, String> query = parseQuery(exchange.getRequestURI().getRawQuery());

        List<Map<String, Object>> items = candidateIds.stream().map(candidateId -> {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("candidate_id", candidateId);
            try {
                ReviewWorkflowService.ApprovalResult result = reviewWorkflowService.approveCandidate(
                        candidateId,
                        operator,
                        reason,
                        ticketId,
                        matchScope,
                        expiresAt
                );
                item.put("success", true);
                item.put("exemption_id", result.exemptionId());
                item.put("match_scope", result.matchScope());
            } catch (Exception e) {
                item.put("success", false);
                item.put("error", e.getMessage());
            }
            return item;
        }).toList();

        long successCount = items.stream().filter(item -> Boolean.TRUE.equals(item.get("success"))).count();

        if (isCsvFormat(query)) {
            writeBatchResultCsv(exchange, "batch-approve-result.csv", items);
            return;
        }

        writeJson(exchange, 200, Map.of(
                "total", candidateIds.size(),
                "success_count", successCount,
                "failed_count", candidateIds.size() - successCount,
                "items", items
        ));
    }

    private void handleBatchReject(HttpExchange exchange) throws IOException {
        Map<String, Object> body = readBodyAsMap(exchange);
        List<Long> candidateIds = parseCandidateIds(body.get("candidate_ids"));
        String operator = text(body, "operator", "unknown");
        String reason = text(body, "reason", "rejected");
        String ticketId = text(body, "ticket_id", null);
        String patternState = text(body, "pattern_state", "unknown");
        Map<String, String> query = parseQuery(exchange.getRequestURI().getRawQuery());

        List<Map<String, Object>> items = candidateIds.stream().map(candidateId -> {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("candidate_id", candidateId);
            try {
                reviewWorkflowService.rejectCandidate(
                        candidateId,
                        operator,
                        reason,
                        ticketId,
                        patternState
                );
                item.put("success", true);
            } catch (Exception e) {
                item.put("success", false);
                item.put("error", e.getMessage());
            }
            return item;
        }).toList();

        long successCount = items.stream().filter(item -> Boolean.TRUE.equals(item.get("success"))).count();

        if (isCsvFormat(query)) {
            writeBatchResultCsv(exchange, "batch-reject-result.csv", items);
            return;
        }

        writeJson(exchange, 200, Map.of(
                "total", candidateIds.size(),
                "success_count", successCount,
                "failed_count", candidateIds.size() - successCount,
                "items", items
        ));
    }

    private void handleBatchApproveAsync(HttpExchange exchange) throws IOException {
        Map<String, Object> body = readBodyAsMap(exchange);
        List<Long> candidateIds = parseCandidateIds(body.get("candidate_ids"));
        String operator = text(body, "operator", "unknown");
        String reason = text(body, "reason", "approved");
        String ticketId = text(body, "ticket_id", null);
        String matchScope = text(body, "match_scope", "signature_exact");
        String expiresAt = text(body, "expires_at", null);

        String operationId = batchOperationService.submitApprove(
                candidateIds,
                operator,
                reason,
                ticketId,
                matchScope,
                expiresAt
        );
        writeJson(exchange, 202, Map.of(
                "accepted", true,
                "operation_id", operationId,
                "status", "running"
        ));
    }

    private void handleBatchRejectAsync(HttpExchange exchange) throws IOException {
        Map<String, Object> body = readBodyAsMap(exchange);
        List<Long> candidateIds = parseCandidateIds(body.get("candidate_ids"));
        String operator = text(body, "operator", "unknown");
        String reason = text(body, "reason", "rejected");
        String ticketId = text(body, "ticket_id", null);
        String patternState = text(body, "pattern_state", "unknown");

        String operationId = batchOperationService.submitReject(
                candidateIds,
                operator,
                reason,
                ticketId,
                patternState
        );
        writeJson(exchange, 202, Map.of(
                "accepted", true,
                "operation_id", operationId,
                "status", "running"
        ));
    }

    private void handleBatchOperationStatus(HttpExchange exchange, String path) throws IOException {
        String operationId = parseBatchOperationId(path);
        BatchOperation operation = batchOperationService.getOperation(operationId);
        if (operation == null) {
            writeJson(exchange, 404, Map.of("error", "operation_not_found"));
            return;
        }
        writeJson(exchange, 200, Map.of(
                "operation", operation
        ));
    }

    private void handleBatchOperations(HttpExchange exchange) throws IOException {
        Map<String, String> query = parseQuery(exchange.getRequestURI().getRawQuery());
        String status = queryText(query, "status");
        int limit = parseInt(query.get("limit"), 100);
        int offset = parseInt(query.get("offset"), 0);
        long total = batchOperationService.countOperations(status);
        writeJson(exchange, 200, Map.of(
                "items", batchOperationService.listOperations(status, limit, offset),
                "total", total,
                "status", status,
                "limit", limit,
                "offset", offset
        ));
    }

    private void handleBatchOperationItems(HttpExchange exchange, String path) throws IOException {
        String operationId = parseBatchOperationId(path);
        Map<String, String> query = parseQuery(exchange.getRequestURI().getRawQuery());
        int limit = parseInt(query.get("limit"), 200);
        int offset = parseInt(query.get("offset"), 0);
        List<BatchOperationItem> items = batchOperationService.listItems(operationId, limit, offset);
        BatchOperation operation = batchOperationService.getOperation(operationId);
        if (operation == null) {
            writeJson(exchange, 404, Map.of("error", "operation_not_found"));
            return;
        }

        if (isCsvFormat(query)) {
            List<List<String>> rows = new ArrayList<>();
            for (BatchOperationItem item : items) {
                rows.add(List.of(
                        Long.toString(item.id()),
                        safeCsv(item.operationId()),
                        Long.toString(item.candidateId()),
                        safeCsv(Boolean.toString(item.success())),
                        safeCsv(item.exemptionId()),
                        safeCsv(item.matchScope()),
                        safeCsv(item.error()),
                        safeCsv(item.createdAt().toString())
                ));
            }
            writeCsv(
                    exchange,
                    "batch-operation-items.csv",
                    List.of("id", "operation_id", "candidate_id", "success", "exemption_id", "match_scope", "error", "created_at"),
                    rows
            );
            return;
        }

        writeJson(exchange, 200, Map.of(
                "operation_id", operationId,
                "total", operation.totalCount(),
                "items", items,
                "limit", limit,
                "offset", offset
        ));
    }

    private void handleSummary(HttpExchange exchange) throws IOException {
        FirstSeenQuery firstSeenQuery = new FirstSeenQuery(null, null, null, null, null, null, null, null);
        CandidateQuery candidateQuery = new CandidateQuery("auto_suggested", null, null, null, null);
        writeJson(exchange, 200, Map.of(
                "first_seen_total", reviewWorkflowService.countFirstSeenQueue(firstSeenQuery),
                "auto_suggested_total", reviewWorkflowService.countCandidates(candidateQuery),
                "publish_running_total", publishRepository.countPublishes("running"),
                "batch_running_total", batchOperationService.countOperations("running"),
                "audit_total", reviewWorkflowService.countAudit()
        ));
    }

    private void handlePublish(HttpExchange exchange) throws Exception {
        Map<String, Object> body = readBodyAsMap(exchange);
        long generation = parseLong(Objects.toString(body.get("generation"), null), 0L);
        if (generation <= 0) {
            throw new IllegalArgumentException("invalid_generation");
        }
        String operator = text(body, "operator", "unknown");
        String reason = text(body, "reason", "manual_publish");
        String sourcePathText = text(body, "authoring_source", null);
        Path sourcePath = (sourcePathText == null || sourcePathText.isBlank()) ? null : Path.of(sourcePathText);
        List<String> nodes = parseNodes(body.get("nodes"));
        if (nodes.isEmpty()) {
            nodes = config.publishNodes();
        }

        List<NodePublishResult> results = exemptionPublishService.publish(generation, nodes, operator, reason, sourcePath);
        writeJson(exchange, 200, Map.of(
                "published", true,
                "generation", generation,
                "results", results
        ));
    }

    private void handleRollback(HttpExchange exchange) throws Exception {
        Map<String, Object> body = readBodyAsMap(exchange);
        long rollbackFromGeneration = parseLong(Objects.toString(body.get("rollback_from_generation"), null), 0L);
        long newGeneration = parseLong(Objects.toString(body.get("new_generation"), null), 0L);
        if (rollbackFromGeneration <= 0 || newGeneration <= 0) {
            throw new IllegalArgumentException("invalid_generation");
        }
        String operator = text(body, "operator", "unknown");
        String reason = text(body, "reason", "manual_rollback");
        List<String> nodes = parseNodes(body.get("nodes"));
        if (nodes.isEmpty()) {
            nodes = config.publishNodes();
        }

        List<NodePublishResult> results = exemptionPublishService.rollback(
                rollbackFromGeneration,
                newGeneration,
                nodes,
                operator,
                reason
        );
        writeJson(exchange, 200, Map.of(
                "rollback_published", true,
                "rollback_from_generation", rollbackFromGeneration,
                "new_generation", newGeneration,
                "results", results
        ));
    }

    private void handlePublishNodes(HttpExchange exchange, String path) throws IOException {
        String[] parts = path.split("/");
        String publishId = parts[5];
        writeJson(exchange, 200, Map.of(
                "publish_id", publishId,
                "nodes", publishRepository.listNodeResults(publishId)
        ));
    }

    private boolean authorize(HttpExchange exchange) {
        String token = config.reviewApiToken();
        if (token == null || token.isBlank()) {
            return true;
        }
        Headers headers = exchange.getRequestHeaders();
        String provided = headers.getFirst("X-Waf-Api-Token");
        return token.equals(provided);
    }

    private Map<String, Object> readBodyAsMap(HttpExchange exchange) throws IOException {
        try (InputStream is = exchange.getRequestBody()) {
            byte[] bodyBytes = is.readAllBytes();
            if (bodyBytes.length == 0) {
                return new HashMap<>();
            }
            return objectMapper.readValue(bodyBytes, MAP_TYPE);
        }
    }

    private void writeJson(HttpExchange exchange, int status, Object payload) throws IOException {
        byte[] data = objectMapper.writeValueAsBytes(payload);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.sendResponseHeaders(status, data.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(data);
        }
    }

    private void writeCsv(
            HttpExchange exchange,
            String fileName,
            List<String> headers,
            List<List<String>> rows
    ) throws IOException {
        StringBuilder builder = new StringBuilder();
        builder.append(String.join(",", headers)).append('\n');
        for (List<String> row : rows) {
            builder.append(String.join(",", row)).append('\n');
        }
        byte[] data = builder.toString().getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/csv; charset=utf-8");
        exchange.getResponseHeaders().set("Content-Disposition", "attachment; filename=\"" + fileName + "\"");
        exchange.sendResponseHeaders(200, data.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(data);
        }
    }

    private void writeBatchResultCsv(
            HttpExchange exchange,
            String fileName,
            List<Map<String, Object>> items
    ) throws IOException {
        List<List<String>> rows = new ArrayList<>();
        for (Map<String, Object> item : items) {
            rows.add(List.of(
                    safeCsv(Objects.toString(item.get("candidate_id"), "")),
                    safeCsv(Objects.toString(item.get("success"), "")),
                    safeCsv(Objects.toString(item.get("exemption_id"), "")),
                    safeCsv(Objects.toString(item.get("match_scope"), "")),
                    safeCsv(Objects.toString(item.get("error"), ""))
            ));
        }
        writeCsv(
                exchange,
                fileName,
                List.of("candidate_id", "success", "exemption_id", "match_scope", "error"),
                rows
        );
    }

    private Map<String, String> parseQuery(String rawQuery) {
        if (rawQuery == null || rawQuery.isBlank()) {
            return Collections.emptyMap();
        }
        Map<String, String> query = new LinkedHashMap<>();
        for (String kv : rawQuery.split("&")) {
            if (kv.isBlank()) {
                continue;
            }
            String[] parts = kv.split("=", 2);
            String key = urlDecode(parts[0]);
            String value = parts.length == 2 ? urlDecode(parts[1]) : "";
            query.put(key, value);
        }
        return query;
    }

    private String urlDecode(String text) {
        return java.net.URLDecoder.decode(text, StandardCharsets.UTF_8);
    }

    private String queryText(Map<String, String> query, String key) {
        String value = query.get(key);
        if (value == null || value.isBlank()) {
            return null;
        }
        return value.trim();
    }

    private Instant parseInstant(String text) {
        if (text == null || text.isBlank()) {
            return null;
        }
        try {
            return Instant.parse(text);
        } catch (DateTimeParseException e) {
            throw new IllegalArgumentException("invalid_time_format:" + text);
        }
    }

    private boolean isCsvFormat(Map<String, String> query) {
        String format = query.get("format");
        return format != null && "csv".equalsIgnoreCase(format);
    }

    private int parseInt(String raw, int defaultValue) {
        try {
            if (raw == null || raw.isBlank()) {
                return defaultValue;
            }
            return Integer.parseInt(raw);
        } catch (Exception ignored) {
            return defaultValue;
        }
    }

    private long parseLong(String raw, long defaultValue) {
        try {
            if (raw == null || raw.isBlank()) {
                return defaultValue;
            }
            return Long.parseLong(raw);
        } catch (Exception ignored) {
            return defaultValue;
        }
    }

    private long parseCandidateId(String path) {
        String[] parts = path.split("/");
        return Long.parseLong(parts[5]);
    }

    private String parseBatchOperationId(String path) {
        String[] parts = path.split("/");
        if (parts.length < 7) {
            throw new IllegalArgumentException("invalid_operation_path");
        }
        return parts[6];
    }

    @SuppressWarnings("unchecked")
    private List<String> parseNodes(Object raw) {
        if (raw == null) {
            return Collections.emptyList();
        }
        if (raw instanceof List<?> list) {
            return list.stream().map(String::valueOf).toList();
        }
        return Collections.emptyList();
    }

    private List<Long> parseCandidateIds(Object raw) {
        if (!(raw instanceof List<?> list)) {
            throw new IllegalArgumentException("candidate_ids_required");
        }
        LinkedHashSet<Long> ids = new LinkedHashSet<>();
        for (Object value : list) {
            long parsed = parseLong(Objects.toString(value, null), -1);
            if (parsed <= 0) {
                throw new IllegalArgumentException("invalid_candidate_id:" + value);
            }
            ids.add(parsed);
        }
        if (ids.isEmpty()) {
            throw new IllegalArgumentException("candidate_ids_empty");
        }
        return List.copyOf(ids);
    }

    private String text(Map<String, Object> map, String key, String defaultValue) {
        Object value = map.get(key);
        if (value == null) {
            return defaultValue;
        }
        String text = value.toString();
        if (text.isBlank()) {
            return defaultValue;
        }
        return text;
    }

    private String safeCsv(String value) {
        if (value == null) {
            return "\"\"";
        }
        String escaped = value
                .replace("\"", "\"\"")
                .replace("\r", " ")
                .replace("\n", " ");
        return "\"" + escaped + "\"";
    }

    private String safeError(Exception e) {
        if (e == null || e.getMessage() == null || e.getMessage().isBlank()) {
            return "unexpected_error";
        }
        return e.getMessage();
    }
}
