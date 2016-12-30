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

import io.netty.handler.ssl.OpenSsl;
import io.netty.util.internal.PlatformDependent;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.SpecialPermission;
import org.elasticsearch.common.inject.Module;
import org.elasticsearch.common.io.stream.NamedWriteableRegistry;
import org.elasticsearch.common.network.NetworkModule;
import org.elasticsearch.common.network.NetworkService;
import org.elasticsearch.common.settings.Setting;
import org.elasticsearch.common.settings.Setting.Property;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.BigArrays;
import org.elasticsearch.http.HttpServerTransport;
import org.elasticsearch.indices.breaker.CircuitBreakerService;
import org.elasticsearch.plugins.ActionPlugin;
import org.elasticsearch.plugins.NetworkPlugin;
import org.elasticsearch.plugins.Plugin;
import org.elasticsearch.rest.RestHandler;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.Transport;
import org.elasticsearch.transport.TransportInterceptor;

import com.floragunn.searchguard.ssl.http.netty.SearchGuardSSLNettyHttpServerTransport;
import com.floragunn.searchguard.ssl.rest.SearchGuardSSLInfoAction;
import com.floragunn.searchguard.ssl.transport.SearchGuardSSLNettyTransport;
import com.floragunn.searchguard.ssl.transport.SearchGuardSSLTransportInterceptor;
import com.floragunn.searchguard.ssl.util.SSLConfigConstants;

//For ES5 this class has only effect when SSL only plugin is installed
public final class SearchGuardSSLPlugin extends Plugin implements ActionPlugin, NetworkPlugin {

    private final Logger log = LogManager.getLogger(this.getClass());
    static final String CLIENT_TYPE = "client.type";
    private final boolean client;
    private final boolean httpSSLEnabled;
    private final boolean transportSSLEnabled;
    private final Settings settings;
    private final SearchGuardKeyStore sgks;

    public SearchGuardSSLPlugin(final Settings settings) {
        
        String rejectClientInitiatedRenegotiation = System.getProperty("jdk.tls.rejectClientInitiatedRenegotiation");
        
        if(!Boolean.parseBoolean(rejectClientInitiatedRenegotiation)) {
            log.info("Consider setting -Djdk.tls.rejectClientInitiatedRenegotiation=true to prevent DoS attacks through client side initiated TLS renegotiation.");
        } else {
            log.debug("Client side initiated TLS renegotiation disabled. This can prevent DoS attacks. (jdk.tls.rejectClientInitiatedRenegotiation is true).");
        }

        final SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }

        //TODO check initialize native netty open ssl libs still neccessary
        AccessController.doPrivileged(new PrivilegedAction<Object>() {
            @Override
            public Object run() {
                PlatformDependent.newFixedMpscQueue(1);
                OpenSsl.isAvailable();
                return null;
            }
        });

        this.settings = settings;
        client = !"node".equals(this.settings.get(SearchGuardSSLPlugin.CLIENT_TYPE));
        
        httpSSLEnabled = settings.getAsBoolean(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLED,
                SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLED_DEFAULT);
        transportSSLEnabled = settings.getAsBoolean(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLED,
                SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLED_DEFAULT);

        if (!httpSSLEnabled && !transportSSLEnabled) {
            log.error("SSL not activated for http and/or transport.");
            System.out.println("SSL not activated for http and/or transport.");
        }
        
        if(ExternalSearchGuardKeyStore.hasExternalSslContext(settings)) {
            this.sgks = new ExternalSearchGuardKeyStore(settings);
        } else {
            this.sgks = new DefaultSearchGuardKeyStore(settings);
        }
    }
    
    

    @Override
    public List<Class<? extends RestHandler>> getRestHandlers() {
        List<Class<? extends RestHandler>> handlers = new ArrayList<Class<? extends RestHandler>>(1);
        if (!client) {
            handlers.add(SearchGuardSSLInfoAction.class);
        }
        return handlers;
    }

    
    
    @Override
    public List<TransportInterceptor> getTransportInterceptors() {
        List<TransportInterceptor> interceptors = new ArrayList<TransportInterceptor>(1);
        
        if(transportSSLEnabled && !client) {
            interceptors.add(new SearchGuardSSLTransportInterceptor(settings, null, null));
        }
        
        return interceptors;
    }



    @Override
    public Map<String, Supplier<Transport>> getTransports(Settings settings, ThreadPool threadPool, BigArrays bigArrays,
            CircuitBreakerService circuitBreakerService, NamedWriteableRegistry namedWriteableRegistry, NetworkService networkService) {

        Map<String, Supplier<Transport>> transports = new HashMap<String, Supplier<Transport>>();
        if (transportSSLEnabled) {
            transports.put("com.floragunn.searchguard.ssl.http.netty.SearchGuardSSLNettyTransport", 
                    () -> new SearchGuardSSLNettyTransport(settings, threadPool, networkService, bigArrays, namedWriteableRegistry, circuitBreakerService, sgks));
        }
        return transports;

    }



    @Override
    public Map<String, Supplier<HttpServerTransport>> getHttpTransports(Settings settings, ThreadPool threadPool, BigArrays bigArrays,
            CircuitBreakerService circuitBreakerService, NamedWriteableRegistry namedWriteableRegistry, NetworkService networkService) {

        Map<String, Supplier<HttpServerTransport>> httpTransports = new HashMap<String, Supplier<HttpServerTransport>>(1);
        if (!client && httpSSLEnabled) {
            httpTransports.put("com.floragunn.searchguard.ssl.http.netty.SearchGuardSSLNettyHttpServerTransport", 
                    () -> new SearchGuardSSLNettyHttpServerTransport(settings, networkService, bigArrays, threadPool, sgks));
        }
        return httpTransports;
        
    }

    @Override
    public Collection<Module> createGuiceModules() {
        List<Module> modules = new ArrayList<Module>(1);
        modules.add(new SearchGuardSSLModule(settings, sgks));     
        return modules;
    }
    
    @Override
    public List<Setting<?>> getSettings() {
        List<Setting<?>> settings = new ArrayList<Setting<?>>();
        settings.add(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_CLIENTAUTH_MODE, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_KEYSTORE_ALIAS, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_KEYSTORE_FILEPATH, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_KEYSTORE_PASSWORD, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_KEYSTORE_TYPE, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_TRUSTSTORE_ALIAS, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_TRUSTSTORE_FILEPATH, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_TRUSTSTORE_PASSWORD, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_TRUSTSTORE_TYPE, Property.NodeScope, Property.Filtered));
        settings.add(Setting.boolSetting(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, true, Property.NodeScope, Property.Filtered));
        settings.add(Setting.boolSetting(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLED, SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLED_DEFAULT, Property.NodeScope, Property.Filtered));
        settings.add(Setting.boolSetting(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, true,Property.NodeScope, Property.Filtered));
        settings.add(Setting.boolSetting(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLED, SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLED_DEFAULT, Property.NodeScope, Property.Filtered));
        settings.add(Setting.boolSetting(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION, true, Property.NodeScope, Property.Filtered));
        settings.add(Setting.boolSetting(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION_RESOLVE_HOST_NAME, true, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_FILEPATH, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_PASSWORD, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_TYPE, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_TRUSTSTORE_ALIAS, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_TRUSTSTORE_FILEPATH, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_TRUSTSTORE_PASSWORD, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_TRUSTSTORE_TYPE, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLED_CIPHERS, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLED_PROTOCOLS, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLED_CIPHERS, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLED_PROTOCOLS, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_CLIENT_EXTERNAL_CONTEXT_ID, Property.NodeScope, Property.Filtered));
        settings.add(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_PRINCIPAL_EXTRACTOR_CLASS, Property.NodeScope, Property.Filtered));


        settings.add(Setting.simpleString("node.client", Property.NodeScope));
        settings.add(Setting.simpleString("node.local", Property.NodeScope));
        return settings;
    }

    
    @Override
    public Settings additionalSettings() {
       final Settings.Builder builder = Settings.builder();
        
       if(!client && httpSSLEnabled) {
           builder.put(NetworkModule.HTTP_TYPE_KEY, "com.floragunn.searchguard.ssl.http.netty.SearchGuardSSLNettyHttpServerTransport");
       }
        
       if (transportSSLEnabled) {
           builder.put(NetworkModule.TRANSPORT_TYPE_KEY, "com.floragunn.searchguard.ssl.http.netty.SearchGuardSSLNettyTransport");
       }
        
        return builder.build();
    }
    
    @Override
    public List<String> getSettingsFilter() {
        List<String> settingsFilter = new ArrayList<>();
        settingsFilter.add("searchguard.*");
        return settingsFilter;
    }
}
