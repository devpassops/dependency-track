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

import org.dependencytrack.kevdatasource.cisa.CisaKevDataSourceFactory;
import org.dependencytrack.kevdatasource.enisa.EnisaKevDataSourceFactory;
import org.dependencytrack.plugin.api.ExtensionFactory;
import org.dependencytrack.plugin.api.ExtensionPoint;
import org.dependencytrack.plugin.api.Plugin;
import org.dependencytrack.plugin.offlinedata.datasource.OfflineFirstKevDataSourceFactory;
import org.dependencytrack.plugin.offlinedata.datasource.OfflineFirstVulnDataSourceFactory;
import org.dependencytrack.plugin.offlinedata.maven.OfflineFirstMavenResolverFactory;

import java.util.Collection;
import java.util.List;

/**
 * Plugin providing export and import of offline data packages, and preference
 * of offline data over network access during analysis.
 * <p>
 * When loaded as external plugin (i.e. from the plugin directory), this plugin
 * takes precedence over the built-in extensions it shares an identity with:
 * <ul>
 *     <li>{@code package-metadata-resolver#maven}: Prefers the network, and falls
 *     back to locally cached metadata (resolved earlier, or imported via an offline
 *     data package) when network access is unavailable, i.e. requests time out
 *     after 20 seconds or fail. Successful network results are written back to
 *     the cache, keeping it up to date for offline use.</li>
 *     <li>{@code vuln-data-source#nvd}, {@code vuln-data-source#github},
 *     {@code vuln-data-source#osv}: Disabled while an offline data package is
 *     available, so vulnerability data imported from it is used for analysis
 *     without background network synchronization. Falls back to the built-in
 *     data sources otherwise.</li>
 *     <li>{@code kev-data-source#cisa}, {@code kev-data-source#enisa}: Same
 *     behavior as the vulnerability data sources above.</li>
 * </ul>
 */
public final class OfflineDataPlugin implements Plugin {

    private static final String NVD_FACTORY_CLASS = "org.dependencytrack.vulndatasource.nvd.NvdVulnDataSourceFactory";
    private static final String GITHUB_FACTORY_CLASS =
            "org.dependencytrack.vulndatasource.github.GitHubVulnDataSourceFactory";
    private static final String OSV_FACTORY_CLASS = "org.dependencytrack.vulndatasource.osv.OsvVulnDataSourceFactory";

    private final OfflineDataAvailability availability = new OfflineDataAvailability();

    @Override
    public Collection<? extends ExtensionFactory<? extends ExtensionPoint>> extensionFactories() {
        return List.of(
                new OfflineDataManagerFactory(availability),
                new OfflineFirstMavenResolverFactory(),
                new OfflineFirstVulnDataSourceFactory("nvd", "NVD (offline-first)", NVD_FACTORY_CLASS, availability),
                new OfflineFirstVulnDataSourceFactory(
                        "github", "GitHub Advisories (offline-first)", GITHUB_FACTORY_CLASS, availability),
                new OfflineFirstVulnDataSourceFactory("osv", "OSV (offline-first)", OSV_FACTORY_CLASS, availability),
                new OfflineFirstKevDataSourceFactory(
                        "cisa", "CISA KEV (offline-first)", new CisaKevDataSourceFactory(), availability),
                new OfflineFirstKevDataSourceFactory(
                        "enisa", "ENISA KEV (offline-first)", new EnisaKevDataSourceFactory(), availability));
    }
}
