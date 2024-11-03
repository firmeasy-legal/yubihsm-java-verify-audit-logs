package pe.blobfish.yubihsm;

import com.yubico.hsm.yhdata.LogEntry;
import lombok.SneakyThrows;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.util.Arrays;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import java.util.stream.Stream;

public class Main {

    private static final int HALF_LOG_ENTRY_SIZE = LogEntry.LOG_ENTRY_SIZE / 2;

    public static void main(String[] args) {
        if (args.length < 1) {
            System.err.println("Usage: java -jar yubihsm-java-verify-audit-logs.jar <directory-path>");
            System.exit(1);
        }
        Path logsDir = Paths.get(args[0]);
        try {
            byte[] logBytes = readLogFiles(logsDir);
            List<LogEntry> logEntries = verifyLogEntries(logBytes);
            printLogEntries(logEntries);
        } catch (Exception e) {
            System.err.println("Log entries verification failed: " + e.getMessage());
            System.exit(1);
        }
    }

    private static byte[] readLogFiles(Path logsDir) throws IOException {
        ByteArrayOutputStream logBytesBOS = new ByteArrayOutputStream();
        try (Stream<Path> stream = Files.list(logsDir)) {
            System.out.println("Log files will be processed in the following order:");
            stream.filter(Files::isRegularFile)
                    .sorted()
                    .forEach(new LogFileProcessor(logBytesBOS));
        }
        return logBytesBOS.toByteArray();
    }

    private static List<LogEntry> verifyLogEntries(byte[] logBytes) throws Exception {
        int logSize = logBytes.length / LogEntry.LOG_ENTRY_SIZE;
        List<LogEntry> logEntries = new ArrayList<>();
        LogEntry previousLogEntry = null;

        for (int i = 0; i < logSize; i++) {
            byte[] currentLogEntryBytes = Arrays.copyOfRange(logBytes, i * LogEntry.LOG_ENTRY_SIZE, (i + 1) * LogEntry.LOG_ENTRY_SIZE);
            LogEntry currentLogEntry = new LogEntry(currentLogEntryBytes);
            byte[] currentLogEntryDataBytes = Arrays.copyOf(currentLogEntryBytes, HALF_LOG_ENTRY_SIZE);

            if (i == 0) {
                verifyFirstLogEntry(currentLogEntry, currentLogEntryDataBytes);
            } else {
                verifyConsecutiveLogEntry(previousLogEntry, currentLogEntry, currentLogEntryDataBytes);
            }

            logEntries.add(currentLogEntry);
            previousLogEntry = currentLogEntry;
        }
        return logEntries;
    }

    private static void verifyFirstLogEntry(LogEntry currentLogEntry, byte[] currentLogEntryDataBytes) throws Exception {
        if (currentLogEntry.getItemNumber() != 1) {
            throw new Exception("First log entry doesn't have item number 1");
        }
        byte[] expectedFirstLogEntryData = new byte[HALF_LOG_ENTRY_SIZE];
        expectedFirstLogEntryData[0] = 0x00;
        expectedFirstLogEntryData[1] = 0x01;
        for (int j = 2; j < HALF_LOG_ENTRY_SIZE; j++) {
            expectedFirstLogEntryData[j] = (byte) 0xff;
        }
        if (!ByteUtils.equals(currentLogEntryDataBytes, expectedFirstLogEntryData)) {
            throw new Exception("First log entry doesn't match the expected value of 0x00, 0x01, 0xff, 0xff...");
        }
    }

    private static void verifyConsecutiveLogEntry(LogEntry previousLogEntry, LogEntry currentLogEntry, byte[] currentLogEntryDataBytes) throws Exception {
        if (previousLogEntry.getItemNumber() != currentLogEntry.getItemNumber() - 1) {
            throw new Exception("Log entries are not consecutive. Expected previous item number " + (currentLogEntry.getItemNumber() - 1) + " but got " + previousLogEntry.getItemNumber());
        }
        byte[] previousLogEntryDigest = previousLogEntry.getEntryDigest();
        byte[] calculatedDigest = MessageDigest.getInstance("SHA-256").digest(Arrays.concatenate(currentLogEntryDataBytes, previousLogEntryDigest));
        byte[] calculatedDigestTruncated = Arrays.copyOfRange(calculatedDigest, 0, HALF_LOG_ENTRY_SIZE);
        if (!ByteUtils.equals(calculatedDigestTruncated, currentLogEntry.getEntryDigest())) {
            throw new Exception("Digests don't match for entry " + (currentLogEntry.getItemNumber()));
        }
    }

    private static void printLogEntries(List<LogEntry> logEntries) {
        System.out.println("Log entries verification successful.");
        System.out.println("Verified log entries:");
        for (LogEntry logEntry : logEntries) {
            System.out.println(logEntry.toString().trim());
        }
    }

    private static class LogFileProcessor implements Consumer<Path> {
        private final ByteArrayOutputStream logBytesBOS;

        LogFileProcessor(ByteArrayOutputStream logBytesBOS) {
            this.logBytesBOS = logBytesBOS;
        }

        @SneakyThrows
        @Override
        public void accept(Path path) {
            System.out.println(" - " + path.getFileName());
            byte[] logFileBytes = ByteUtils.fromHexString(FileUtils.readFileToString(path.toFile()));
            logBytesBOS.write(logFileBytes, 4, logFileBytes.length - 4);
        }
    }
}