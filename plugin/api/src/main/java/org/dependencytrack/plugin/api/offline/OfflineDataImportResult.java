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
package org.dependencytrack.plugin.api.offline;

/**
 * Statistics about an offline data package import.
 *
 * @param vulnerabilities      Number of vulnerabilities imported (including updates).
 * @param vulnerableSoftware   Number of vulnerable software entries imported (including updates).
 * @param vulnerabilityLinks   Number of links between vulnerabilities and vulnerable software imported.
 * @param kevAssertions        Number of KEV assertions imported (including updates).
 * @param packageMetadata      Number of package metadata entries imported (including updates).
 * @since 5.3.0
 */
public record OfflineDataImportResult(
        int vulnerabilities, int vulnerableSoftware, int vulnerabilityLinks, int kevAssertions, int packageMetadata) {}
