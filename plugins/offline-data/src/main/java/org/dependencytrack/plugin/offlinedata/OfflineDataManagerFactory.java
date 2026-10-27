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

import org.dependencytrack.plugin.api.ExtensionContext;
import org.dependencytrack.plugin.api.ExtensionFactory;
import org.dependencytrack.plugin.api.offline.OfflineDataManager;
import org.jdbi.v3.core.Jdbi;
import org.jspecify.annotations.Nullable;

import static org.dependencytrack.plugin.api.ExtensionFactory.PRIORITY_HIGHEST;

/**
 * Factory for the default {@link OfflineDataManager} implementation.
 */
public final class OfflineDataManagerFactory implements ExtensionFactory<OfflineDataManager> {

    private final OfflineDataAvailability availability;
    private @Nullable Jdbi jdbi;

    public OfflineDataManagerFactory(OfflineDataAvailability availability) {
        this.availability = availability;
    }

    @Override
    public String extensionName() {
        return "default";
    }

    @Override
    public String displayName() {
        return "Offline Data Manager";
    }

    @Override
    public Class<? extends OfflineDataManager> extensionClass() {
        return OfflineDataManagerImpl.class;
    }

    @Override
    public int priority() {
        return PRIORITY_HIGHEST;
    }

    @Override
    public void init(ExtensionContext context) {
        this.jdbi = context.jdbi();
    }

    @Override
    public OfflineDataManager create() {
        if (jdbi == null) {
            throw new IllegalStateException("Factory has not been initialized");
        }

        return new OfflineDataManagerImpl(jdbi, availability);
    }
}
