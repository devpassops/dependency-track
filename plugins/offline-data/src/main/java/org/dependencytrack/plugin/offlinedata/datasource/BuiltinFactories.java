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
import org.dependencytrack.vulndatasource.api.VulnDataSourceFactory;

/**
 * Instantiates factories of built-in plugins, which are not accessible to
 * external plugins through normal means (e.g. because they are package-private).
 * <p>
 * Built-in factories are used as fallback when no offline data is available.
 */
final class BuiltinFactories {

    private BuiltinFactories() {}

    static VulnDataSourceFactory newVulnDataSourceFactory(String className, ExtensionContext extensionContext) {
        final VulnDataSourceFactory factory = instantiate(className, VulnDataSourceFactory.class);
        factory.init(extensionContext);
        return factory;
    }

    private static <T> T instantiate(String className, Class<T> type) {
        final ClassLoader hostClassLoader = hostClassLoader();
        try {
            final Class<?> clazz = Class.forName(className, true, hostClassLoader);
            final var constructor = clazz.getDeclaredConstructor();
            constructor.setAccessible(true);
            return type.cast(constructor.newInstance());
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("Failed to instantiate built-in factory " + className, e);
        }
    }

    private static ClassLoader hostClassLoader() {
        // When loaded as external plugin, the parent of the plugin's class loader
        // is the class loader of the host application.
        final ClassLoader hostClassLoader =
                BuiltinFactories.class.getClassLoader().getParent();
        if (hostClassLoader != null) {
            return hostClassLoader;
        }

        final var contextClassLoader = Thread.currentThread().getContextClassLoader();
        if (contextClassLoader != null) {
            return contextClassLoader;
        }

        return BuiltinFactories.class.getClassLoader();
    }
}
