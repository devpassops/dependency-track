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
package org.dependencytrack.resources.v2;

import alpine.server.auth.PermissionRequired;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.plugin.api.ExtensionFactory;
import org.dependencytrack.plugin.api.offline.OfflineDataImportResult;
import org.dependencytrack.plugin.api.offline.OfflineDataManager;
import org.dependencytrack.plugin.runtime.PluginManager;
import org.dependencytrack.resources.AbstractApiResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.inject.Inject;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.StreamingOutput;
import jakarta.ws.rs.ext.Provider;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.SequencedCollection;

/**
 * @since 5.3.0
 */
@Provider
@Path("plugins/offline-data")
public class OfflineDataResource extends AbstractApiResource {

    private static final Logger LOGGER = LoggerFactory.getLogger(OfflineDataResource.class);

    private final PluginManager pluginManager;

    @Inject
    OfflineDataResource(PluginManager pluginManager) {
        this.pluginManager = pluginManager;
    }

    @GET
    @Path("status")
    @Produces(MediaType.APPLICATION_JSON)
    @PermissionRequired(Permissions.Constants.SYSTEM_CONFIGURATION)
    public Response getStatus() {
        final var managerFactories = pluginManager.getFactories(OfflineDataManager.class);

        final Map<String, Object> status = new LinkedHashMap<>();
        status.put("available", !managerFactories.isEmpty());
        status.put(
                "dataAvailable",
                !managerFactories.isEmpty()
                        && managerFactories.getFirst().create().isDataAvailable());
        return Response.ok(status).build();
    }

    @GET
    @Path("export")
    @Produces("application/zip")
    @PermissionRequired(Permissions.Constants.SYSTEM_CONFIGURATION)
    public Response exportOfflineData() {
        final OfflineDataManager dataManager = getDataManager();

        final StreamingOutput streamingOutput = (OutputStream outputStream) -> {
            try {
                dataManager.exportTo(outputStream);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new WebApplicationException("Export was interrupted", Response.Status.SERVICE_UNAVAILABLE);
            }
        };

        return Response.ok(streamingOutput)
                .header("Content-Disposition", "attachment; filename=\"dependency-track-offline-data.zip\"")
                .build();
    }

    @POST
    @Path("import")
    @Consumes({"application/zip", "application/octet-stream"})
    @Produces(MediaType.APPLICATION_JSON)
    @PermissionRequired(Permissions.Constants.SYSTEM_CONFIGURATION)
    public Response importOfflineData(InputStream inputStream) {
        if (inputStream == null) {
            throw new BadRequestException("No offline data package provided");
        }

        final OfflineDataManager dataManager = getDataManager();

        final OfflineDataImportResult result;
        try {
            result = dataManager.importFrom(inputStream);
        } catch (IOException e) {
            LOGGER.error("Failed to import offline data package", e);
            throw new BadRequestException("Failed to import offline data package: " + e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new WebApplicationException("Import was interrupted", Response.Status.SERVICE_UNAVAILABLE);
        }

        final Map<String, Object> response = new LinkedHashMap<>();
        response.put("vulnerabilities", result.vulnerabilities());
        response.put("vulnerableSoftware", result.vulnerableSoftware());
        response.put("vulnerabilityLinks", result.vulnerabilityLinks());
        response.put("kevAssertions", result.kevAssertions());
        response.put("packageMetadata", result.packageMetadata());

        return Response.ok(response).build();
    }

    private OfflineDataManager getDataManager() {
        final SequencedCollection<ExtensionFactory<OfflineDataManager>> factories =
                pluginManager.getFactories(OfflineDataManager.class);
        if (factories.isEmpty()) {
            throw new NotFoundException("""
                    No offline data manager available; \
                    Make sure the offline-data plugin is installed""");
        }

        return factories.getFirst().create();
    }
}
