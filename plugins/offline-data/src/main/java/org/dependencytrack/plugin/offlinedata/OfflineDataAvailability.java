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

import org.eclipse.microprofile.config.ConfigProvider;

import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Determines whether an offline data package is available locally.
 * <p>
 * The package is expected to be located in the plugin directory, under the name
 * configured via {@code dtrack.plugins.offline-data.file}. When the package is
 * available, extensions of this plugin prefer offline data and refrain from
 * accessing the network.
 */
public final class OfflineDataAvailability {

    static final String CONFIG_PROPERTY_PLUGINS_DIR = "dtrack.plugins.dir";
    static final String CONFIG_PROPERTY_DATA_FILE = "dtrack.plugins.offline-data.file";

    static final String DEFAULT_PLUGINS_DIR = "./plugins";
    static final String DEFAULT_DATA_FILE_NAME = "offline-data.zip";

    private final Path dataFile;

    OfflineDataAvailability() {
        final var config = ConfigProvider.getConfig();
        final String pluginsDir = config.getOptionalValue(CONFIG_PROPERTY_PLUGINS_DIR, String.class)
                .orElse(DEFAULT_PLUGINS_DIR);
        final String dataFileName =
                config.getOptionalValue(CONFIG_PROPERTY_DATA_FILE, String.class).orElse(DEFAULT_DATA_FILE_NAME);
        this.dataFile = Path.of(pluginsDir).resolve(dataFileName);
    }

    OfflineDataAvailability(Path dataFile) {
        this.dataFile = dataFile;
    }

    public boolean isAvailable() {
        return Files.isRegularFile(dataFile);
    }

    public Path dataFile() {
        return dataFile;
    }
}
