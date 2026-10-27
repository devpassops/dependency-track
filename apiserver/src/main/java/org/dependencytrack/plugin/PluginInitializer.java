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
package org.dependencytrack.plugin;

import org.dependencytrack.cache.api.CacheManager;
import org.dependencytrack.common.HttpClient;
import org.dependencytrack.kevdatasource.api.KevDataSource;
import org.dependencytrack.notification.api.publishing.NotificationPublisher;
import org.dependencytrack.persistence.jdbi.JdbiFactory;
import org.dependencytrack.pkgmetadata.resolution.api.PackageMetadataResolver;
import org.dependencytrack.plugin.api.Plugin;
import org.dependencytrack.plugin.api.offline.OfflineDataManager;
import org.dependencytrack.plugin.runtime.PluginManager;
import org.dependencytrack.secret.management.SecretManager;
import org.dependencytrack.vulnanalysis.api.VulnAnalyzer;
import org.dependencytrack.vulndatasource.api.VulnDataSource;
import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;

import java.io.IOException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.ServiceLoader;

import static java.util.Objects.requireNonNull;

/**
 * @since 5.0.0
 */
public class PluginInitializer implements ServletContextListener {

    private static final Logger LOGGER = LoggerFactory.getLogger(PluginInitializer.class);

    private static final String PLUGINS_DIR_CONFIG_PROPERTY = "dtrack.plugins.dir";
    private static final String DEFAULT_PLUGINS_DIR = "./plugins";

    private final Config config;
    private @Nullable PluginManager pluginManager;
    private @Nullable URLClassLoader externalPluginClassLoader;

    PluginInitializer(Config config) {
        this.config = config;
    }

    @SuppressWarnings("unused") // Used by servlet container.
    public PluginInitializer() {
        this(ConfigProvider.getConfig());
    }

    @Override
    public void contextInitialized(ServletContextEvent event) {
        LOGGER.info("Initializing plugin system");

        final var cacheManager = (CacheManager) event.getServletContext().getAttribute(CacheManager.class.getName());
        requireNonNull(cacheManager, "cacheManager has not been initialized");

        final var secretManager = (SecretManager) event.getServletContext().getAttribute(SecretManager.class.getName());
        requireNonNull(secretManager, "secretManager has not been initialized");

        final var extensionPoints = List.of(
                KevDataSource.class,
                NotificationPublisher.class,
                OfflineDataManager.class,
                PackageMetadataResolver.class,
                VulnAnalyzer.class,
                VulnDataSource.class);

        pluginManager = new PluginManager(
                config,
                cacheManager,
                secretManager::getSecretValue,
                JdbiFactory.createJdbi(),
                HttpClient.INSTANCE,
                HttpClient.INSTANCE.outboundConnectionPolicy(),
                extensionPoints);

        LOGGER.info("Discovering plugins");
        final Collection<Plugin> plugins = ServiceLoader.load(Plugin.class).stream()
                .map(ServiceLoader.Provider::get)
                .toList();
        for (final Plugin plugin : plugins) {
            LOGGER.debug("Discovered plugin {}", plugin.getClass().getName());
        }

        final Collection<Plugin> externalPlugins = discoverExternalPlugins();
        for (final Plugin externalPlugin : externalPlugins) {
            LOGGER.info(
                    "Discovered external plugin {}", externalPlugin.getClass().getName());
        }

        LOGGER.info("Loading plugins");
        pluginManager.loadPlugins(plugins);

        if (!externalPlugins.isEmpty()) {
            LOGGER.info("Loading external plugins; They take precedence over built-in functionality");
            pluginManager.loadPlugins(externalPlugins, true);
        }

        event.getServletContext().setAttribute(PluginManager.class.getName(), pluginManager);
    }

    /**
     * Discovers plugins in JAR files located in the directory configured via
     * {@code dtrack.plugins.dir}. The directory is scanned for {@code *.jar} files,
     * each of which is made available through a dedicated {@link URLClassLoader}.
     * Plugins bundled in those JARs are discovered using {@link ServiceLoader}.
     * <p>
     * External plugins are loaded <em>after</em> built-in plugins and take
     * precedence over them when they provide an extension with the same identity.
     *
     * @return Plugins discovered in the plugin directory.
     * @since 5.3.0
     */
    private List<Plugin> discoverExternalPlugins() {
        final String pluginsDirValue = config.getOptionalValue(PLUGINS_DIR_CONFIG_PROPERTY, String.class)
                .orElse(DEFAULT_PLUGINS_DIR);
        final Path pluginsDir = Path.of(pluginsDirValue);

        if (!Files.isDirectory(pluginsDir)) {
            LOGGER.debug("Plugin directory {} does not exist; Skipping discovery of external plugins", pluginsDir);
            return List.of();
        }

        final List<URL> pluginJarUrls = new ArrayList<>();
        try (DirectoryStream<Path> dirStream = Files.newDirectoryStream(pluginsDir, "*.jar")) {
            for (final Path pluginJar : dirStream) {
                LOGGER.debug("Discovered plugin JAR {}", pluginJar);
                pluginJarUrls.add(pluginJar.toUri().toURL());
            }
        } catch (IOException e) {
            LOGGER.error("Failed to list plugin directory {}", pluginsDir, e);
            return List.of();
        }

        if (pluginJarUrls.isEmpty()) {
            LOGGER.debug("No plugin JARs found in {}", pluginsDir);
            return List.of();
        }

        final var pluginClassLoader =
                new URLClassLoader(pluginJarUrls.toArray(URL[]::new), PluginInitializer.class.getClassLoader());
        this.externalPluginClassLoader = pluginClassLoader;

        return ServiceLoader.load(Plugin.class, pluginClassLoader).stream()
                .map(ServiceLoader.Provider::get)
                .toList();
    }

    @Override
    public void contextDestroyed(ServletContextEvent event) {
        if (pluginManager != null) {
            LOGGER.info("Closing plugin manager");
            pluginManager.close();
        }

        if (externalPluginClassLoader != null) {
            try {
                externalPluginClassLoader.close();
            } catch (IOException e) {
                LOGGER.warn("Failed to close plugin class loader", e);
            }
        }

        event.getServletContext().removeAttribute(PluginManager.class.getName());
    }
}
