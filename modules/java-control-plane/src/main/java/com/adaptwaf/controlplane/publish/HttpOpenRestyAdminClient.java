package com.adaptwaf.controlplane.publish;

import com.adaptwaf.controlplane.model.ExemptionCompiledSnapshot;
import com.adaptwaf.controlplane.model.NodePublishResult;
import com.adaptwaf.controlplane.util.HashUtils;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;

/**
 * 基于 JDK HttpClient 的 OpenResty 管理接口实现。
 */
public class HttpOpenRestyAdminClient implements OpenRestyAdminClient {

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final Map<String, String> nodeBaseUrl;
    private final String sharedSecret;

    public HttpOpenRestyAdminClient(
            HttpClient httpClient,
            ObjectMapper objectMapper,
            Map<String, String> nodeBaseUrl,
            String sharedSecret
    ) {
        this.httpClient = httpClient;
        this.objectMapper = objectMapper;
        this.nodeBaseUrl = nodeBaseUrl;
        this.sharedSecret = sharedSecret;
    }

    @Override
    public NodePublishResult publish(String nodeId, ExemptionCompiledSnapshot snapshot) {
        try {
            String baseUrl = resolveBaseUrl(nodeId);
            String body = objectMapper.writeValueAsString(Map.of(
                    "publish_id", snapshot.publishId(),
                    "generation", snapshot.generation(),
                    "compiled_sha256", snapshot.sha256(),
                    "compiled_size", snapshot.content().length,
                    "compiled_content_base64", Base64.getEncoder().encodeToString(snapshot.content())
            ));
            String timestamp = Long.toString(Instant.now().getEpochSecond());
            String nonce = UUID.randomUUID().toString().replace("-", "");

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(baseUrl + "/_waf/internal/exemptions/publish"))
                    .header("Content-Type", "application/json")
                    .header("X-Waf-Timestamp", timestamp)
                    .header("X-Waf-Nonce", nonce)
                    .header("X-Waf-Signature", signature(timestamp, nonce, body))
                    .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            if (response.statusCode() / 100 != 2) {
                return new NodePublishResult(nodeId, false, 0, "http_status_" + response.statusCode());
            }

            JsonNode jsonNode = objectMapper.readTree(response.body());
            long generation = jsonNode.path("generation").asLong(0);
            return new NodePublishResult(nodeId, true, generation, null);
        } catch (Exception e) {
            return new NodePublishResult(nodeId, false, 0, "publish_failed:" + e.getMessage());
        }
    }

    @Override
    public NodePublishResult status(String nodeId) {
        try {
            String baseUrl = resolveBaseUrl(nodeId);
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(baseUrl + "/_waf/internal/exemptions/status"))
                    .GET()
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            if (response.statusCode() / 100 != 2) {
                return new NodePublishResult(nodeId, false, 0, "http_status_" + response.statusCode());
            }

            JsonNode jsonNode = objectMapper.readTree(response.body());
            long generation = jsonNode.path("current_generation").asLong(0);
            String status = jsonNode.path("last_apply_status").asText("unknown");
            String error = jsonNode.path("last_error").asText(null);
            return new NodePublishResult(nodeId, "ok".equals(status), generation, error);
        } catch (Exception e) {
            return new NodePublishResult(nodeId, false, 0, "status_failed:" + e.getMessage());
        }
    }

    private String resolveBaseUrl(String nodeId) {
        String baseUrl = nodeBaseUrl.get(nodeId);
        if (baseUrl == null || baseUrl.isBlank()) {
            throw new IllegalArgumentException("unknown_node_id:" + nodeId);
        }
        if (baseUrl.endsWith("/")) {
            return baseUrl.substring(0, baseUrl.length() - 1);
        }
        return baseUrl;
    }

    /**
     * 生成管理接口请求签名。
     *
     * @param timestamp 秒级时间戳
     * @param nonce 随机串
     * @param body 请求体
     * @return 签名串
     */
    private String signature(String timestamp, String nonce, String body) {
        String bodySha256 = HashUtils.sha256Hex(body.getBytes(StandardCharsets.UTF_8));
        String plain = timestamp + "|" + nonce + "|" + bodySha256 + "|" + sharedSecret;
        return HashUtils.sha256Hex(plain.getBytes(StandardCharsets.UTF_8));
    }
}
