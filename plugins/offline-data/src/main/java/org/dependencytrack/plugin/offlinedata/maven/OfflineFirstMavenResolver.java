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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.packageurl.PackageURL;
import org.dependencytrack.pkgmetadata.resolution.api.PackageArtifactMetadata;
import org.dependencytrack.pkgmetadata.resolution.api.PackageMetadata;
import org.dependencytrack.pkgmetadata.resolution.api.PackageMetadataResolver;
import org.dependencytrack.pkgmetadata.resolution.api.PackageRepository;
import org.dependencytrack.plugin.api.storage.KeyValueStore;
import org.dependencytrack.plugin.offlinedata.JsonMappers;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * {@link PackageMetadataResolver} that prefers the network, and falls back to the
 * local cache when network access is unavailable.
 * <p>
 * Resolution requests are first delegated to the network-based resolver. If the
 * request does not complete within {@link #NETWORK_TIMEOUT}, or fails, metadata
 * that was resolved earlier (or imported via an offline data package) is served
 * from the local cache instead. Successful network results are written back to
 * the cache, keeping it up to date.
 */
final class OfflineFirstMavenResolver implements PackageMetadataResolver {

    private static final Logger LOGGER = LoggerFactory.getLogger(OfflineFirstMavenResolver.class);
    private static final ObjectMapper OBJECT_MAPPER = JsonMappers.newObjectMapper();

    /**
     * Maximum duration of a network resolution attempt, before falling back
     * to the local cache.
     */
    static final Duration NETWORK_TIMEOUT = Duration.ofSeconds(20);

    static final String KV_KEY_PREFIX = "purl:";

    private final KeyValueStore keyValueStore;
    private final PackageMetadataResolver delegate;
    private final ExecutorService executor;

    OfflineFirstMavenResolver(KeyValueStore keyValueStore, PackageMetadataResolver delegate, ExecutorService executor) {
        this.keyValueStore = keyValueStore;
        this.delegate = delegate;
        this.executor = executor;
    }

    @Override
    public @Nullable PackageMetadata resolve(
            PackageURL purl, PackageRepository repository, PackageArtifactMetadata prior) throws InterruptedException {
        final String cacheKey = KV_KEY_PREFIX + repository.url() + ":" + purl;

        LOGGER.debug("Resolving metadata for {} via network", purl);
        final PackageMetadata networkMetadata = resolveViaNetwork(purl, repository, prior);
        if (networkMetadata != null) {
            LOGGER.debug("Resolved metadata for {} via network", purl);
            writeToCache(cacheKey, networkMetadata, purl);
            return networkMetadata;
        }

        LOGGER.debug("Network resolution for {} unavailable; Falling back to local cache", purl);
        final PackageMetadata cachedMetadata = readFromCache(cacheKey, purl);
        if (cachedMetadata != null) {
            LOGGER.debug("Resolved metadata for {} from local cache", purl);
            return cachedMetadata;
        }

        return null;
    }

    private @Nullable PackageMetadata resolveViaNetwork(
            PackageURL purl, PackageRepository repository, PackageArtifactMetadata prior) throws InterruptedException {
        final Future<PackageMetadata> future = executor.submit(() -> delegate.resolve(purl, repository, prior));

        try {
            return future.get(NETWORK_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            // Interrupt the network request, freeing up the thread.
            future.cancel(true);
            LOGGER.warn(
                    "Network resolution for {} timed out after {}; Falling back to local cache", purl, NETWORK_TIMEOUT);
            return null;
        } catch (ExecutionException e) {
            final Throwable cause = e.getCause();
            if (cause instanceof InterruptedException) {
                throw (InterruptedException) cause;
            }

            LOGGER.warn("Network resolution for {} failed; Falling back to local cache", purl, cause);
            return null;
        }
    }

    private @Nullable PackageMetadata readFromCache(String cacheKey, PackageURL purl) {
        final KeyValueStore.Entry entry = keyValueStore.get(cacheKey);
        if (entry == null) {
            return null;
        }

        try {
            return OBJECT_MAPPER.readValue(entry.value(), PackageMetadata.class);
        } catch (Exception e) {
            LOGGER.warn("Failed to deserialize cached metadata for {}; Removing it from the cache", purl, e);
            keyValueStore.delete(cacheKey);
            return null;
        }
    }

    private void writeToCache(String cacheKey, PackageMetadata metadata, PackageURL purl) {
        try {
            keyValueStore.put(cacheKey, OBJECT_MAPPER.writeValueAsString(metadata));
        } catch (Exception e) {
            LOGGER.warn("Failed to cache metadata for {}", purl, e);
        }
    }

    @Override
    public void close() {
        try {
            delegate.close();
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to close delegate resolver", e);
        }
    }
}
