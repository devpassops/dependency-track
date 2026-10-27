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

import org.dependencytrack.plugin.api.ExtensionContext;
import org.dependencytrack.plugin.api.ExtensionTestResult;
import org.dependencytrack.plugin.api.RuntimeConfigurable;
import org.dependencytrack.plugin.api.Testable;
import org.dependencytrack.plugin.api.config.RuntimeConfig;
import org.dependencytrack.plugin.api.config.RuntimeConfigSpec;
import org.dependencytrack.plugin.offlinedata.OfflineDataAvailability;
import org.dependencytrack.vulndatasource.api.VulnDataSource;
import org.dependencytrack.vulndatasource.api.VulnDataSourceFactory;
import org.jspecify.annotations.Nullable;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.plugin.api.ExtensionFactory.PRIORITY_HIGHEST;

/**
 * {@link VulnDataSourceFactory} that takes precedence over a built-in data source
 * with the same extension identity.
 * <p>
 * When an offline data package is available, the data source is reported as disabled,
 * causing the platform to skip network synchronization with it. Vulnerability data
 * imported from the offline package is used for analysis instead. When no offline
 * data package is available, all functionality is delegated to the built-in factory,
 * which retains full network access.
 */
public final class OfflineFirstVulnDataSourceFactory implements VulnDataSourceFactory, RuntimeConfigurable, Testable {

    private final String extensionName;
    private final String displayName;
    private final String builtinFactoryClassName;
    private final OfflineDataAvailability availability;
    private @Nullable ExtensionContext extensionContext;
    private @Nullable VulnDataSourceFactory delegateFactory;

    public OfflineFirstVulnDataSourceFactory(
            String extensionName,
            String displayName,
            String builtinFactoryClassName,
            OfflineDataAvailability availability) {
        this.extensionName = requireNonNull(extensionName, "extensionName must not be null");
        this.displayName = requireNonNull(displayName, "displayName must not be null");
        this.builtinFactoryClassName =
                requireNonNull(builtinFactoryClassName, "builtinFactoryClassName must not be null");
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
    public Class<? extends VulnDataSource> extensionClass() {
        return delegate().extensionClass();
    }

    @Override
    public int priority() {
        return PRIORITY_HIGHEST;
    }

    @Override
    public RuntimeConfigSpec runtimeConfigSpec() {
        return ((RuntimeConfigurable) delegate()).runtimeConfigSpec();
    }

    @Override
    public boolean isDataSourceEnabled() {
        if (availability.isAvailable()) {
            return false;
        }

        return delegate().isDataSourceEnabled();
    }

    @Override
    public void init(ExtensionContext extensionContext) {
        this.extensionContext = extensionContext;
    }

    @Override
    public VulnDataSource create() {
        return delegate().create();
    }

    @Override
    public ExtensionTestResult test(@Nullable RuntimeConfig runtimeConfig) {
        return ((Testable) delegate()).test(runtimeConfig);
    }

    @Override
    public void close() {
        if (delegateFactory != null) {
            delegateFactory.close();
        }
    }

    private VulnDataSourceFactory delegate() {
        if (delegateFactory == null) {
            if (extensionContext == null) {
                throw new IllegalStateException("Factory has not been initialized");
            }

            delegateFactory = BuiltinFactories.newVulnDataSourceFactory(builtinFactoryClassName, extensionContext);
        }

        return delegateFactory;
    }
}
