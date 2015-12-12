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

import java.nio.file.Files;
import java.util.Collection;

import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.common.inject.Module;
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
import com.floragunn.searchguard.ssl.util.EnabledSSLCiphers;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;

public final class SearchGuardSSLPlugin extends Plugin {

    private static final String CLIENT_TYPE = "client.type";
    private final boolean client;
    private final boolean httpSSLEnabled;
    private final boolean transportSSLEnabled;
    private final Settings settings;

    public SearchGuardSSLPlugin(final Settings settings) {
        EnabledSSLCiphers.init();
        this.settings = settings;
        client = !"node".equals(this.settings.get(SearchGuardSSLPlugin.CLIENT_TYPE));
        httpSSLEnabled = settings.getAsBoolean(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_HTTP_ENABLED, false);
        transportSSLEnabled = settings.getAsBoolean(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_NODE_ENABLED, true);
        checkSSLConfig();

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
            return ImmutableList.<Module> of(new SearchGuardSSLModule());

        } else {
            return ImmutableList.<Module> of(new SearchGuardSSLModule(), new EnvironmentModule(new Environment(settings)));
        }
    }

    private void checkSSLConfig() {

        Environment env = new Environment(settings);
        
        if (transportSSLEnabled) {
            final String keystoreFilePath = settings.get(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_NODE_KEYSTORE_FILEPATH);
            final String truststoreFilePath = settings.get(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_NODE_TRUSTSTORE_FILEPATH);

            if (Strings.isNullOrEmpty(keystoreFilePath)) {
                throw new ElasticsearchException(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_NODE_KEYSTORE_FILEPATH + " must be set if transport ssl is reqested.");
            }

            if(!Files.isReadable(env.configFile().resolve(keystoreFilePath))) {
                throw new ElasticsearchException("No such file "+env.configFile().resolve(keystoreFilePath).toAbsolutePath().toString());
            }
            
            if(!Strings.isNullOrEmpty(truststoreFilePath) && !Files.isReadable(env.configFile().resolve(truststoreFilePath))) {
                throw new ElasticsearchException("No such file "+env.configFile().resolve(truststoreFilePath).toAbsolutePath().toString());
            }
        }

        if (!client && httpSSLEnabled) {
            final String keystoreFilePath = settings.get(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_HTTP_KEYSTORE_FILEPATH);
            final String truststoreFilePath = settings.get(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_HTTP_TRUSTSTORE_FILEPATH);

            if (Strings.isNullOrEmpty(keystoreFilePath)) {
                throw new ElasticsearchException(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_HTTP_KEYSTORE_FILEPATH + " must be set if https is reqested.");
            }
            
            if(!Files.isReadable(env.configFile().resolve(keystoreFilePath))) {
                throw new ElasticsearchException("No such file "+env.configFile().resolve(keystoreFilePath).toAbsolutePath().toString());
            }
            
            if(!Strings.isNullOrEmpty(truststoreFilePath) && !Files.isReadable(env.configFile().resolve(truststoreFilePath))) {
                throw new ElasticsearchException("No such file "+env.configFile().resolve(truststoreFilePath).toAbsolutePath().toString());
            }
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
