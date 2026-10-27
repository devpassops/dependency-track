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

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Layout and table mappings of offline data packages.
 * <p>
 * All values are exchanged as strings, which PostgreSQL casts to the
 * appropriate column types on import, and from the appropriate column
 * types on export. This keeps the package format stable and human-readable.
 */
final class OfflineDataPackage {

    static final int FORMAT_VERSION = 1;

    static final String MANIFEST_ENTRY = "manifest.json";

    static final String VULNERABILITIES_ENTRY = "vulnerabilities/vulnerability.jsonl";
    static final String VULNERABLE_SOFTWARE_ENTRY = "vulnerabilities/vulnerable-software.jsonl";
    static final String VULNERABLE_SOFTWARE_LINKS_ENTRY = "vulnerabilities/vulnerable-software-links.jsonl";
    static final String KEV_ASSERTIONS_ENTRY = "security/kev-assertions.jsonl";
    static final String POM_METADATA_ENTRY = "pom-metadata/maven.jsonl";

    private OfflineDataPackage() {}

    /**
     * Columns of the {@code VULNERABILITY} table, mapped to their PostgreSQL type.
     * {@code ID} is excluded, as it is a database-local identity column.
     */
    static final Map<String, String> VULNERABILITY_COLUMNS = buildColumns(
            "CREATED", "timestamptz",
            "CREDITS", "text",
            "CVSSV2BASESCORE", "numeric",
            "CVSSV2EXPLOITSCORE", "numeric",
            "CVSSV2IMPACTSCORE", "numeric",
            "CVSSV2VECTOR", "text",
            "CVSSV3BASESCORE", "numeric",
            "CVSSV3EXPLOITSCORE", "numeric",
            "CVSSV3IMPACTSCORE", "numeric",
            "CVSSV3VECTOR", "text",
            "CVSSV4SCORE", "numeric",
            "CVSSV4VECTOR", "text",
            "CWES", "text",
            "DESCRIPTION", "text",
            "DETAIL", "text",
            "FRIENDLYVULNID", "text",
            "OWASPRRBUSINESSIMPACTSCORE", "numeric",
            "OWASPRRLIKELIHOODSCORE", "numeric",
            "OWASPRRTECHNICALIMPACTSCORE", "numeric",
            "OWASPRRVECTOR", "text",
            "PATCHEDVERSIONS", "text",
            "PUBLISHED", "timestamptz",
            "RECOMMENDATION", "text",
            "REFERENCES", "text",
            "REJECTED", "timestamptz",
            "SEVERITY", "severity",
            "SOURCE", "text",
            "SUBTITLE", "text",
            "TITLE", "text",
            "UPDATED", "timestamptz",
            "UUID", "uuid",
            "VULNID", "text",
            "VULNERABLEVERSIONS", "text");

    /**
     * Columns of the {@code VULNERABLESOFTWARE} table, mapped to their PostgreSQL type.
     * {@code ID} is excluded, as it is a database-local identity column.
     */
    static final Map<String, String> VULNERABLE_SOFTWARE_COLUMNS = buildColumns(
            "CPE22", "text",
            "CPE23", "text",
            "EDITION", "text",
            "LANGUAGE", "text",
            "OTHER", "text",
            "PART", "text",
            "PRODUCT", "text",
            "PURL", "text",
            "PURL_NAME", "text",
            "PURL_NAMESPACE", "text",
            "PURL_QUALIFIERS", "text",
            "PURL_SUBPATH", "text",
            "PURL_TYPE", "text",
            "PURL_VERSION", "text",
            "SWEDITION", "text",
            "TARGETHW", "text",
            "TARGETSW", "text",
            "UPDATE", "text",
            "UUID", "uuid",
            "VENDOR", "text",
            "VERSION", "text",
            "VERSIONENDEXCLUDING", "text",
            "VERSIONENDINCLUDING", "text",
            "VERSIONSTARTEXCLUDING", "text",
            "VERSIONSTARTINCLUDING", "text",
            "VULNERABLE", "boolean");

    /**
     * Columns of the {@code KEV_ASSERTION} table, mapped to their PostgreSQL type.
     * {@code ID} is excluded, as it is a database-local identity column.
     */
    static final Map<String, String> KEV_ASSERTION_COLUMNS = buildColumns(
            "ASSERTER", "text",
            "VULN_SOURCE", "text",
            "VULN_ID", "text",
            "PUBLISHED_AT", "timestamptz",
            "REQUIRED_ACTION", "text",
            "KNOWN_RANSOMWARE", "boolean",
            "DESCRIPTION", "text",
            "RAW", "jsonb");

    private static Map<String, String> buildColumns(String... namesAndTypes) {
        if (namesAndTypes.length % 2 != 0) {
            throw new IllegalArgumentException("Expected name-type pairs");
        }

        final var columns = new LinkedHashMap<String, String>();
        for (int i = 0; i < namesAndTypes.length; i += 2) {
            columns.put(namesAndTypes[i], namesAndTypes[i + 1]);
        }
        return columns;
    }
}
