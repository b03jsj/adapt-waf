package com.adaptwaf.controlplane.ingest;

import com.adaptwaf.controlplane.repository.IngestCheckpointRepository;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * 本地 NDJSON 文件增量采集任务。
 */
public class FileTailIngestJob {

    private final String sourceNode;
    private final Path logFilePath;
    private final IngestCheckpointRepository checkpointRepository;
    private final NdjsonAlertIngestor ndjsonAlertIngestor;
    private final int batchSize;

    public FileTailIngestJob(
            String sourceNode,
            Path logFilePath,
            IngestCheckpointRepository checkpointRepository,
            NdjsonAlertIngestor ndjsonAlertIngestor,
            int batchSize
    ) {
        this.sourceNode = sourceNode;
        this.logFilePath = logFilePath;
        this.checkpointRepository = checkpointRepository;
        this.ndjsonAlertIngestor = ndjsonAlertIngestor;
        this.batchSize = batchSize;
    }

    /**
     * 执行一次增量采集。
     *
     * @throws Exception 读取或入库异常
     */
    public void runOnce() throws Exception {
        String filePath = logFilePath.toString();
        long offset = checkpointRepository.getOffset(sourceNode, filePath);

        try (RandomAccessFile raf = new RandomAccessFile(filePath, "r")) {
            long fileLength = raf.length();
            if (offset > fileLength) {
                offset = 0;
            }

            raf.seek(offset);
            List<String> lines = new ArrayList<>(batchSize);
            String line;
            while ((line = raf.readLine()) != null) {
                lines.add(new String(line.getBytes(StandardCharsets.ISO_8859_1), StandardCharsets.UTF_8));
                if (lines.size() >= batchSize) {
                    ndjsonAlertIngestor.ingestLines(lines);
                    lines.clear();
                }
            }

            if (!lines.isEmpty()) {
                ndjsonAlertIngestor.ingestLines(lines);
            }

            checkpointRepository.saveOffset(sourceNode, filePath, 0L, raf.getFilePointer());
        }
    }
}
