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

import org.dependencytrack.plugin.api.ExtensionPoint;
import org.dependencytrack.plugin.api.ExtensionPointSpec;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * An {@link ExtensionPoint} for managing offline data packages.
 * <p>
 * Offline data packages bundle cached vulnerability intelligence, security data,
 * and package metadata (such as Maven POM relationships), so they can be exported
 * from one instance, transferred without network access, and imported into
 * another instance.
 * <p>
 * Implementations of this extension point are expected to work together with
 * other extensions (for example data sources and resolvers) to prefer offline
 * data when it is available, and fall back to network access otherwise.
 *
 * @since 5.3.0
 */
@ExtensionPointSpec(name = "offline-data-manager")
public interface OfflineDataManager extends ExtensionPoint {

    /**
     * @return Whether offline data is available for analysis.
     */
    boolean isDataAvailable();

    /**
     * Exports all cached data as offline data package.
     *
     * @param outputStream Stream to write the package (ZIP) to. The stream is not
     *                     closed by the implementation.
     * @throws IOException         If writing the package failed.
     * @throws InterruptedException If the thread was interrupted while exporting.
     */
    void exportTo(OutputStream outputStream) throws IOException, InterruptedException;

    /**
     * Imports an offline data package.
     * <p>
     * Imported data is merged into the local cache, preferring data from the
     * package over local data in case of conflicts.
     *
     * @param inputStream Stream to read the package (ZIP) from. The stream is not
     *                    closed by the implementation.
     * @return Statistics about the imported data.
     * @throws IOException         If reading or importing the package failed.
     * @throws InterruptedException If the thread was interrupted while importing.
     */
    OfflineDataImportResult importFrom(InputStream inputStream) throws IOException, InterruptedException;
}
