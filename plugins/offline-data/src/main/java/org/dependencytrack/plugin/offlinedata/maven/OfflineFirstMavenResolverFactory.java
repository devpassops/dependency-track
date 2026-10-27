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
package org.dependencytrack.plugin.offlinedata.maven;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import com.github.packageurl.PackageURLBuilder;
import org.dependencytrack.pkgmetadata.resolution.api.PackageMetadataResolver;
import org.dependencytrack.pkgmetadata.resolution.api.PackageMetadataResolverFactory;
import org.dependencytrack.pkgmetadata.resolution.maven.MavenPackageMetadataResolverFactory;
import org.dependencytrack.plugin.api.ExtensionContext;
import org.dependencytrack.plugin.api.storage.KeyValueStore;
import org.jspecify.annotations.Nullable;

import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Replacement for the built-in Maven {@link PackageMetadataResolver}, preferring
 * the network, and falling back to locally cached metadata when it is unavailable.
 * <p>
 * Note that this factory uses the same extension identity ({@code maven}) as the
 * built-in resolver, and takes precedence over it when loaded as external plugin.
 */
public final class OfflineFirstMavenResolverFactory implements PackageMetadataResolverFactory {

    private final MavenPackageMetadataResolverFactory delegateFactory;
    private @Nullable KeyValueStore keyValueStore;
    private @Nullable ExecutorService executor;

    public OfflineFirstMavenResolverFactory() {
        this.delegateFactory = new MavenPackageMetadataResolverFactory();
    }

    @Override
    public String extensionName() {
        return "maven";
    }

    @Override
    public String displayName() {
        return "Maven (offline-first)";
    }

    @Override
    public Class<? extends PackageMetadataResolver> extensionClass() {
        return OfflineFirstMavenResolver.class;
    }

    @Override
    public int priority() {
        return PRIORITY_HIGHEST;
    }

    @Override
    public @Nullable PackageURL normalize(PackageURL purl) {
        if (!PackageURL.StandardTypes.MAVEN.equals(purl.getType())
                || purl.getNamespace() == null
                || purl.getName() == null
                || purl.getVersion() == null) {
            return null;
        }

        try {
            final Map<String, String> origQualifiers = purl.getQualifiers();
            final String type = origQualifiers != null ? origQualifiers.getOrDefault("type", "jar") : "jar";
            final String classifier = origQualifiers != null ? origQualifiers.get("classifier") : null;
            final var builder = PackageURLBuilder.aPackageURL()
                    .withType(purl.getType())
                    .withNamespace(purl.getNamespace())
                    .withName(purl.getName())
                    .withVersion(purl.getVersion())
                    .withQualifier("type", type);
            if (classifier != null) {
                builder.withQualifier("classifier", classifier);
            }
            return builder.build();
        } catch (MalformedPackageURLException e) {
            return null;
        }
    }

    @Override
    public boolean requiresRepository() {
        return true;
    }

    @Override
    public void init(ExtensionContext context) {
        this.keyValueStore = context.keyValueStore();
        this.executor = Executors.newVirtualThreadPerTaskExecutor();
        delegateFactory.init(context);
    }

    @Override
    public PackageMetadataResolver create() {
        return new OfflineFirstMavenResolver(requireKeyValueStore(), delegateFactory.create(), requireExecutor());
    }

    @Override
    public void close() {
        if (executor != null) {
            executor.shutdown();
        }
        delegateFactory.close();
    }

    private KeyValueStore requireKeyValueStore() {
        if (keyValueStore == null) {
            throw new IllegalStateException("Factory has not been initialized");
        }
        return keyValueStore;
    }

    private ExecutorService requireExecutor() {
        if (executor == null) {
            throw new IllegalStateException("Factory has not been initialized");
        }
        return executor;
    }
}
