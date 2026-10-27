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
package org.dependencytrack.plugin.offlinedata.datasource;

import org.dependencytrack.kevdatasource.api.KevDataSource;
import org.dependencytrack.kevdatasource.api.KevDataSourceFactory;
import org.dependencytrack.plugin.api.ExtensionContext;
import org.dependencytrack.plugin.offlinedata.OfflineDataAvailability;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.plugin.api.ExtensionFactory.PRIORITY_HIGHEST;

/**
 * {@link KevDataSourceFactory} that takes precedence over a built-in KEV data source
 * with the same extension identity.
 * <p>
 * When an offline data package is available, the data source is reported as disabled,
 * causing the platform to skip network synchronization with it. KEV assertions
 * imported from the offline package are used instead. When no offline data package
 * is available, all functionality is delegated to the built-in factory.
 */
public final class OfflineFirstKevDataSourceFactory implements KevDataSourceFactory {

    private final String extensionName;
    private final String displayName;
    private final KevDataSourceFactory delegateFactory;
    private final OfflineDataAvailability availability;

    public OfflineFirstKevDataSourceFactory(
            String extensionName,
            String displayName,
            KevDataSourceFactory delegateFactory,
            OfflineDataAvailability availability) {
        this.extensionName = requireNonNull(extensionName, "extensionName must not be null");
        this.displayName = requireNonNull(displayName, "displayName must not be null");
        this.delegateFactory = requireNonNull(delegateFactory, "delegateFactory must not be null");
        this.availability = requireNonNull(availability, "availability must not be null");
    }

    @Override
    public String extensionName() {
        return extensionName;
    }

    @Override
    public String displayName() {
        return displayName;
    }

    @Override
    public Class<? extends KevDataSource> extensionClass() {
        return delegateFactory.extensionClass();
    }

    @Override
    public int priority() {
        return PRIORITY_HIGHEST;
    }

    @Override
    public boolean isEnabled() {
        if (availability.isAvailable()) {
            return false;
        }

        return delegateFactory.isEnabled();
    }

    @Override
    public void init(ExtensionContext extensionContext) {
        delegateFactory.init(extensionContext);
    }

    @Override
    public KevDataSource create() {
        return delegateFactory.create();
    }

    @Override
    public void close() {
        delegateFactory.close();
    }
}
