/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.plugin.offlinedata;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.dependencytrack.plugin.api.offline.OfflineDataImportResult;
import org.dependencytrack.plugin.api.offline.OfflineDataManager;
import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.Jdbi;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.sql.SQLException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.StringJoiner;
import java.util.zip.Deflater;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

import static java.util.Objects.requireNonNull;

/**
 * Default {@link OfflineDataManager} implementation.
 * <p>
 * Data is exchanged as JSON Lines ({@code .jsonl}) entries within a ZIP package.
 * All values are serialized as strings; PostgreSQL casts them to the appropriate
 * column types on import. This keeps the package format human-readable and
 * independent of internal database types.
 */
public final class OfflineDataManagerImpl implements OfflineDataManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(OfflineDataManagerImpl.class);

    private static final TypeReference<Map<String, Object>> ROW_TYPE_REF = new TypeReference<>() {};
    private static final int FETCH_SIZE = 1000;
    private static final int BATCH_SIZE = 500;

    private static final String MAVEN_KV_EXTENSION_POINT = "package-metadata-resolver";
    private static final String MAVEN_KV_EXTENSION = "maven";
    private static final String MAVEN_KV_KEY_PREFIX = "purl:";

    private final Jdbi jdbi;
    private final OfflineDataAvailability availability;
    private final ObjectMapper objectMapper;

    public OfflineDataManagerImpl(Jdbi jdbi, OfflineDataAvailability availability) {
        this.jdbi = requireNonNull(jdbi, "jdbi must not be null");
        this.availability = requireNonNull(availability, "availability must not be null");
        this.objectMapper = JsonMappers.newObjectMapper();
    }

    @Override
    public boolean isDataAvailable() {
        return availability.isAvailable();
    }

    @Override
    public void exportTo(OutputStream outputStream) throws IOException, InterruptedException {
        requireNonNull(outputStream, "outputStream must not be null");

        LOGGER.info("Exporting offline data package");
        final var counts = new LinkedHashMap<String, Integer>();

        try (var zipOutputStream = new ZipOutputStream(outputStream)) {
            zipOutputStream.setLevel(Deflater.BEST_SPEED);

            counts.put(
                    "vulnerabilities",
                    exportTable(
                            zipOutputStream,
                            OfflineDataPackage.VULNERABILITIES_ENTRY,
                            "VULNERABILITY",
                            OfflineDataPackage.VULNERABILITY_COLUMNS));
            checkInterrupted();
            counts.put(
                    "vulnerableSoftware",
                    exportTable(
                            zipOutputStream,
                            OfflineDataPackage.VULNERABLE_SOFTWARE_ENTRY,
                            "VULNERABLESOFTWARE",
                            OfflineDataPackage.VULNERABLE_SOFTWARE_COLUMNS));
            checkInterrupted();
            counts.put("vulnerabilityLinks", exportVulnerabilityLinks(zipOutputStream));
            checkInterrupted();
            counts.put(
                    "kevAssertions",
                    exportTable(
                            zipOutputStream,
                            OfflineDataPackage.KEV_ASSERTIONS_ENTRY,
                            "KEV_ASSERTION",
                            OfflineDataPackage.KEV_ASSERTION_COLUMNS));
            checkInterrupted();
            counts.put("packageMetadata", exportPomMetadata(zipOutputStream));
            checkInterrupted();

            writeManifest(zipOutputStream, counts);
        }

        LOGGER.info("Exported offline data package: {}", counts);
    }

    @Override
    public OfflineDataImportResult importFrom(InputStream inputStream) throws IOException, InterruptedException {
        requireNonNull(inputStream, "inputStream must not be null");

        final Path tempFile = Files.createTempFile("dependency-track-offline-data-", ".zip");
        try {
            Files.copy(inputStream, tempFile, StandardCopyOption.REPLACE_EXISTING);
            final OfflineDataImportResult result = importFromPackageFile(tempFile);

            // Persist the package in the plugin directory, so it is considered
            // available after restarts, and other extensions of this plugin can
            // prefer offline data over network access.
            final Path dataFile = availability.dataFile();
            if (dataFile.getParent() != null) {
                Files.createDirectories(dataFile.getParent());
            }
            Files.move(tempFile, dataFile, StandardCopyOption.REPLACE_EXISTING);
            LOGGER.info("Stored offline data package at {}", dataFile);

            return result;
        } finally {
            Files.deleteIfExists(tempFile);
        }
    }

    private OfflineDataImportResult importFromPackageFile(Path packageFile) throws IOException, InterruptedException {
        LOGGER.info("Importing offline data package from {}", packageFile);

        final int vulnerabilities;
        final int vulnerableSoftware;
        final int vulnerabilityLinks;
        final int kevAssertions;
        final int packageMetadata;

        try (var zipFile = new ZipFile(packageFile.toFile())) {
            validatePackage(zipFile);

            vulnerabilities = importJsonl(
                    zipFile,
                    OfflineDataPackage.VULNERABILITIES_ENTRY,
                    buildUpsertSql("VULNERABILITY", OfflineDataPackage.VULNERABILITY_COLUMNS, List.of("UUID")));
            checkInterrupted();
            vulnerableSoftware = importJsonl(
                    zipFile,
                    OfflineDataPackage.VULNERABLE_SOFTWARE_ENTRY,
                    buildUpsertSql(
                            "VULNERABLESOFTWARE", OfflineDataPackage.VULNERABLE_SOFTWARE_COLUMNS, List.of("UUID")));
            checkInterrupted();
            vulnerabilityLinks = importVulnerabilityLinks(zipFile);
            checkInterrupted();
            kevAssertions = importJsonl(
                    zipFile,
                    OfflineDataPackage.KEV_ASSERTIONS_ENTRY,
                    buildUpsertSql(
                            "KEV_ASSERTION",
                            OfflineDataPackage.KEV_ASSERTION_COLUMNS,
                            List.of("ASSERTER", "VULN_SOURCE", "VULN_ID")));
            checkInterrupted();
            packageMetadata = importPomMetadata(zipFile);
            checkInterrupted();
        }

        final var result = new OfflineDataImportResult(
                vulnerabilities, vulnerableSoftware, vulnerabilityLinks, kevAssertions, packageMetadata);
        LOGGER.info(
                "Imported offline data package: vulnerabilities={}, vulnerableSoftware={}, "
                        + "vulnerabilityLinks={}, kevAssertions={}, packageMetadata={}",
                result.vulnerabilities(),
                result.vulnerableSoftware(),
                result.vulnerabilityLinks(),
                result.kevAssertions(),
                result.packageMetadata());

        return result;
    }

    private void validatePackage(ZipFile zipFile) throws IOException {
        final ZipEntry manifestEntry = zipFile.getEntry(OfflineDataPackage.MANIFEST_ENTRY);
        if (manifestEntry == null) {
            LOGGER.warn("Offline data package does not contain a manifest; Proceeding anyway");
            return;
        }

        try (var inputStream = zipFile.getInputStream(manifestEntry)) {
            final Map<String, Object> manifest = objectMapper.readValue(inputStream, ROW_TYPE_REF);
            if (manifest.get("formatVersion") instanceof Number formatVersion
                    && formatVersion.intValue() > OfflineDataPackage.FORMAT_VERSION) {
                throw new IOException("""
                        Unsupported offline data package format version %d; \
                        This instance supports version %d or lower""".formatted(formatVersion.intValue(), OfflineDataPackage.FORMAT_VERSION));
            }
        }
    }

    private int exportTable(
            ZipOutputStream zipOutputStream, String entryName, String tableName, Map<String, String> columns)
            throws IOException, InterruptedException {
        final String sql = "SELECT %s FROM \"%s\"".formatted(selectColumnList(columns), tableName);

        return exportRows(
                zipOutputStream,
                entryName,
                handle -> handle.createQuery(sql).setFetchSize(FETCH_SIZE).mapToMap());
    }

    private int exportVulnerabilityLinks(ZipOutputStream zipOutputStream) throws IOException, InterruptedException {
        final String sql = """
                SELECT CAST(v."UUID" AS text) AS "vulnUuid"
                     , CAST(s."UUID" AS text) AS "softwareUuid"
                  FROM "VULNERABLESOFTWARE_VULNERABILITIES" AS x
                  JOIN "VULNERABILITY" AS v
                    ON v."ID" = x."VULNERABILITY_ID"
                  JOIN "VULNERABLESOFTWARE" AS s
                    ON s."ID" = x."VULNERABLESOFTWARE_ID"
                """;

        return exportRows(
                zipOutputStream,
                OfflineDataPackage.VULNERABLE_SOFTWARE_LINKS_ENTRY,
                handle -> handle.createQuery(sql).setFetchSize(FETCH_SIZE).mapToMap());
    }

    private int exportPomMetadata(ZipOutputStream zipOutputStream) throws IOException, InterruptedException {
        final String sql = """
                SELECT "KEY"
                     , "VALUE"
                  FROM "EXTENSION_KV_STORE"
                 WHERE "EXTENSION_POINT" = :extensionPoint
                   AND "EXTENSION" = :extension
                   AND "KEY" LIKE :keyPrefix
                """;

        return exportRows(
                zipOutputStream,
                OfflineDataPackage.POM_METADATA_ENTRY,
                handle -> handle.createQuery(sql)
                        .bind("extensionPoint", MAVEN_KV_EXTENSION_POINT)
                        .bind("extension", MAVEN_KV_EXTENSION)
                        .bind("keyPrefix", MAVEN_KV_KEY_PREFIX + "%")
                        .setFetchSize(FETCH_SIZE)
                        .mapToMap());
    }

    private interface RowIterableProvider {
        Iterable<Map<String, Object>> rows(Handle handle);
    }

    private int exportRows(ZipOutputStream zipOutputStream, String entryName, RowIterableProvider rowProvider)
            throws IOException, InterruptedException {
        zipOutputStream.putNextEntry(new ZipEntry(entryName));
        final var writer = new BufferedWriter(new OutputStreamWriter(zipOutputStream, StandardCharsets.UTF_8));

        final var rowsWritten = new int[1];
        try (var handle = jdbi.open()) {
            // The transaction is required for PostgreSQL to actually stream rows
            // using the configured fetch size, instead of fetching them all at once.
            final var connection = handle.getConnection();
            try {
                connection.setAutoCommit(false);
            } catch (SQLException e) {
                throw new IOException("Failed to start transaction for export of " + entryName, e);
            }
            try {
                final var rowIterator = rowProvider.rows(handle).iterator();
                while (rowIterator.hasNext()) {
                    final Map<String, Object> row = rowIterator.next();
                    objectMapper.writeValue(writer, row);
                    writer.write("\n");
                    rowsWritten[0]++;

                    if (rowsWritten[0] % FETCH_SIZE == 0) {
                        writer.flush();
                        checkInterrupted();
                    }
                }
            } finally {
                // Restoring auto-commit ends the transaction. Uncommitted changes
                // are rolled back, releasing server-side cursors and snapshots.
                try {
                    connection.setAutoCommit(true);
                } catch (SQLException e) {
                    LOGGER.warn("Failed to end transaction for export of {}", entryName, e);
                }
            }
        } finally {
            // The entry must be closed even when an exception occurred, as the
            // underlying stream is shared and entries are closed sequentially.
            try {
                zipOutputStream.closeEntry();
            } catch (IOException e) {
                LOGGER.debug("Failed to close ZIP entry {}", entryName, e);
            }
        }

        return rowsWritten[0];
    }

    private void writeManifest(ZipOutputStream zipOutputStream, Map<String, Integer> counts) throws IOException {
        final var manifest = new LinkedHashMap<String, Object>();
        manifest.put("formatVersion", OfflineDataPackage.FORMAT_VERSION);
        manifest.put("createdAt", Instant.now().toString());
        manifest.put("counts", counts);

        zipOutputStream.putNextEntry(new ZipEntry(OfflineDataPackage.MANIFEST_ENTRY));
        objectMapper.writeValue(zipOutputStream, manifest);
        zipOutputStream.closeEntry();
    }

    private int importJsonl(ZipFile zipFile, String entryName, String upsertSql)
            throws IOException, InterruptedException {
        final ZipEntry entry = zipFile.getEntry(entryName);
        if (entry == null) {
            LOGGER.warn("Offline data package does not contain {}; Skipping", entryName);
            return 0;
        }

        int rowsImported = 0;
        try (var handle = jdbi.open();
                var reader = new BufferedReader(
                        new InputStreamReader(zipFile.getInputStream(entry), StandardCharsets.UTF_8))) {
            final List<Map<String, Object>> batch = new ArrayList<>(BATCH_SIZE);
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.isBlank()) {
                    continue;
                }

                batch.add(objectMapper.readValue(line, ROW_TYPE_REF));
                if (batch.size() >= BATCH_SIZE) {
                    executeBatch(handle, upsertSql, batch);
                    rowsImported += batch.size();
                    batch.clear();
                    checkInterrupted();
                }
            }

            if (!batch.isEmpty()) {
                executeBatch(handle, upsertSql, batch);
                rowsImported += batch.size();
            }
        }

        return rowsImported;
    }

    private int importVulnerabilityLinks(ZipFile zipFile) throws IOException, InterruptedException {
        final String sql = """
                INSERT INTO "VULNERABLESOFTWARE_VULNERABILITIES" ("VULNERABILITY_ID", "VULNERABLESOFTWARE_ID")
                SELECT v."ID", s."ID"
                  FROM "VULNERABILITY" AS v
                  JOIN "VULNERABLESOFTWARE" AS s
                    ON TRUE
                 WHERE CAST(v."UUID" AS uuid) = :vulnUuid
                   AND CAST(s."UUID" AS uuid) = :softwareUuid
                   AND NOT EXISTS (
                       SELECT 1
                         FROM "VULNERABLESOFTWARE_VULNERABILITIES" AS x
                        WHERE x."VULNERABILITY_ID" = v."ID"
                          AND x."VULNERABLESOFTWARE_ID" = s."ID")
                """;

        final ZipEntry entry = zipFile.getEntry(OfflineDataPackage.VULNERABLE_SOFTWARE_LINKS_ENTRY);
        if (entry == null) {
            LOGGER.warn(
                    "Offline data package does not contain {}; Skipping",
                    OfflineDataPackage.VULNERABLE_SOFTWARE_LINKS_ENTRY);
            return 0;
        }

        int rowsImported = 0;
        try (var handle = jdbi.open();
                var reader = new BufferedReader(
                        new InputStreamReader(zipFile.getInputStream(entry), StandardCharsets.UTF_8))) {
            final List<Map<String, Object>> batch = new ArrayList<>(BATCH_SIZE);
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.isBlank()) {
                    continue;
                }

                batch.add(objectMapper.readValue(line, ROW_TYPE_REF));
                if (batch.size() >= BATCH_SIZE) {
                    executeBatch(handle, sql, batch);
                    rowsImported += batch.size();
                    batch.clear();
                    checkInterrupted();
                }
            }

            if (!batch.isEmpty()) {
                executeBatch(handle, sql, batch);
                rowsImported += batch.size();
            }
        }

        return rowsImported;
    }

    private int importPomMetadata(ZipFile zipFile) throws IOException, InterruptedException {
        final String sql = """
                INSERT INTO "EXTENSION_KV_STORE" (
                    "EXTENSION_POINT", "EXTENSION", "KEY", "VALUE", "CREATED_AT", "VERSION")
                VALUES (:extensionPoint, :extension, :KEY, :VALUE, NOW(), 0)
                ON CONFLICT ("EXTENSION_POINT", "EXTENSION", "KEY")
                DO UPDATE
                SET "VALUE" = EXCLUDED."VALUE"
                  , "UPDATED_AT" = NOW()
                  , "VERSION" = "EXTENSION_KV_STORE"."VERSION" + 1
                """;

        final ZipEntry entry = zipFile.getEntry(OfflineDataPackage.POM_METADATA_ENTRY);
        if (entry == null) {
            LOGGER.warn("Offline data package does not contain {}; Skipping", OfflineDataPackage.POM_METADATA_ENTRY);
            return 0;
        }

        int rowsImported = 0;
        try (var handle = jdbi.open();
                var reader = new BufferedReader(
                        new InputStreamReader(zipFile.getInputStream(entry), StandardCharsets.UTF_8))) {
            final List<Map<String, Object>> batch = new ArrayList<>(BATCH_SIZE);
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.isBlank()) {
                    continue;
                }

                final Map<String, Object> row = objectMapper.readValue(line, ROW_TYPE_REF);
                row.put("extensionPoint", MAVEN_KV_EXTENSION_POINT);
                row.put("extension", MAVEN_KV_EXTENSION);
                batch.add(row);
                if (batch.size() >= BATCH_SIZE) {
                    executeBatch(handle, sql, batch);
                    rowsImported += batch.size();
                    batch.clear();
                    checkInterrupted();
                }
            }

            if (!batch.isEmpty()) {
                executeBatch(handle, sql, batch);
                rowsImported += batch.size();
            }
        }

        return rowsImported;
    }

    private void executeBatch(Handle handle, String sql, List<Map<String, Object>> rows) {
        final var preparedBatch = handle.prepareBatch(sql);
        for (final Map<String, Object> row : rows) {
            preparedBatch.bindMap(row).add();
        }
        preparedBatch.execute();
    }

    private void checkInterrupted() throws InterruptedException {
        if (Thread.interrupted()) {
            throw new InterruptedException();
        }
    }

    private static String selectColumnList(Map<String, String> columns) {
        final StringJoiner joiner = new StringJoiner(", ");
        for (final Map.Entry<String, String> column : columns.entrySet()) {
            // Values are cast to text for a stable, human-readable representation.
            // CAST() is used instead of the "::" shorthand, which JDBI would
            // misinterpret as named parameters.
            joiner.add("CAST(\"%s\" AS text) AS \"%s\"".formatted(column.getKey(), column.getKey()));
        }
        return joiner.toString();
    }

    private static String buildUpsertSql(String tableName, Map<String, String> columns, List<String> conflictColumns) {
        final StringJoiner columnList = new StringJoiner(", ");
        final StringJoiner valueList = new StringJoiner(", ");
        final StringJoiner updateList = new StringJoiner(", ");

        for (final Map.Entry<String, String> column : columns.entrySet()) {
            final String name = column.getKey();
            final String type = column.getValue();

            columnList.add("\"" + name + "\"");
            valueList.add(castBind(name, type));
            updateList.add("\"%s\" = EXCLUDED.\"%s\"".formatted(name, name));
        }

        final StringJoiner conflictList = new StringJoiner(", ");
        for (final String conflictColumn : conflictColumns) {
            conflictList.add("\"" + conflictColumn + "\"");
        }

        return """
                INSERT INTO "%s" (%s)
                VALUES (%s)
                ON CONFLICT (%s)
                DO UPDATE
                SET %s
                """.formatted(tableName, columnList, valueList, conflictList, updateList);
    }

    private static String castBind(String columnName, String columnType) {
        return switch (columnType) {
            case "text" -> ":" + columnName;
            case "timestamptz" -> "CAST(:" + columnName + " AS timestamptz)";
            case "numeric" -> "CAST(:" + columnName + " AS numeric)";
            case "uuid" -> "CAST(:" + columnName + " AS uuid)";
            case "severity" -> "CAST(:" + columnName + " AS severity)";
            case "boolean" -> "CAST(:" + columnName + " AS boolean)";
            case "jsonb" -> "CAST(:" + columnName + " AS JSONB)";
            default -> throw new IllegalArgumentException("Unsupported column type: " + columnType);
        };
    }
}
