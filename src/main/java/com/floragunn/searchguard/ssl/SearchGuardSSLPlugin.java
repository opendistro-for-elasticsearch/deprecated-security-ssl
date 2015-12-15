/*
 * Copyright 2015 floragunn UG (haftungsbeschränkt)
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */

package com.floragunn.searchguard.ssl;

import java.util.Collection;

import org.elasticsearch.common.inject.Module;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.env.Environment;
import org.elasticsearch.env.EnvironmentModule;
import org.elasticsearch.http.HttpServerModule;
import org.elasticsearch.plugins.Plugin;
import org.elasticsearch.rest.RestModule;
import org.elasticsearch.transport.TransportModule;

import com.floragunn.searchguard.ssl.http.netty.SearchGuardSSLNettyHttpServerTransport;
import com.floragunn.searchguard.ssl.rest.SearchGuardSSLInfoAction;
import com.floragunn.searchguard.ssl.transport.SearchGuardSSLNettyTransport;
import com.floragunn.searchguard.ssl.util.ConfigConstants;
import com.google.common.collect.ImmutableList;

public final class SearchGuardSSLPlugin extends Plugin {

    private final ESLogger log = Loggers.getLogger(this.getClass());
    static final String CLIENT_TYPE = "client.type";
    private final boolean client;
    private final boolean httpSSLEnabled;
    private final boolean transportSSLEnabled;
    private final Settings settings;

    public SearchGuardSSLPlugin(final Settings settings) {
        this.settings = settings;
        client = !"node".equals(this.settings.get(SearchGuardSSLPlugin.CLIENT_TYPE));
        httpSSLEnabled = settings.getAsBoolean(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_HTTP_ENABLED,
                ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_HTTP_ENABLED_DEFAULT);
        transportSSLEnabled = settings.getAsBoolean(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_NODE_ENABLED,
                ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_NODE_ENABLED_DEFAULT);

        if (!httpSSLEnabled && !transportSSLEnabled) {
            log.error("SSL not activated for http and/or transport.");
            System.out.println("SSL not activated for http and/or transport.");
        }

    }

    public void onModule(final RestModule module) {
        if (!client) {
            module.addRestAction(SearchGuardSSLInfoAction.class);
        }
    }

    public void onModule(final HttpServerModule module) {
        if (!client && httpSSLEnabled) {
            module.setHttpServerTransport(SearchGuardSSLNettyHttpServerTransport.class, name());
        }
    }

    public void onModule(final TransportModule module) {
        if (transportSSLEnabled) {
            module.setTransport(SearchGuardSSLNettyTransport.class, name());
        }
    }

    @Override
    public Collection<Module> nodeModules() {
        if (!client) {
            return ImmutableList.<Module> of(new SearchGuardSSLModule(settings));

        } else {
            return ImmutableList.<Module> of(new SearchGuardSSLModule(settings), new EnvironmentModule(new Environment(settings)));
        }
    }

    @Override
    public String description() {
        return "Search Guard SSL";
    }

    @Override
    public String name() {
        return "search-guard-ssl";
    }
}
