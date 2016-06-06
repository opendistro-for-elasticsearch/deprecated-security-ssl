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
import java.util.Arrays;
import java.util.Collection;

import org.elasticsearch.SpecialPermission;
import org.elasticsearch.common.inject.Module;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.network.NetworkModule;
import org.elasticsearch.common.settings.Setting;
import org.elasticsearch.common.settings.Setting.Property;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.settings.SettingsModule;
import org.elasticsearch.env.Environment;
import org.elasticsearch.env.EnvironmentModule;
import org.elasticsearch.plugins.Plugin;

import com.floragunn.searchguard.ssl.http.netty.SearchGuardSSLNettyHttpServerTransport;
import com.floragunn.searchguard.ssl.rest.SearchGuardSSLInfoAction;
import com.floragunn.searchguard.ssl.transport.SearchGuardSSLNettyTransport;
import com.floragunn.searchguard.ssl.transport.SearchGuardSSLTransportService;
import com.floragunn.searchguard.ssl.util.SSLConfigConstants;

public final class SearchGuardSSLPlugin extends Plugin {

    private final ESLogger log = Loggers.getLogger(this.getClass());
    static final String CLIENT_TYPE = "client.type";
    private final boolean client;
    private final boolean httpSSLEnabled;
    private final boolean transportSSLEnabled;
    private boolean searchGuardPluginAvailable;
    private final Settings settings;

    public SearchGuardSSLPlugin(final Settings settings) {

        final SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }

        // initialize native netty open ssl libs

        AccessController.doPrivileged(new PrivilegedAction<Object>() {
            @Override
            public Object run() {
                PlatformDependent.hasUnsafe();
                OpenSsl.isAvailable();
                return null;
            }
        });
        
        try {
            getClass().getClassLoader().loadClass("com.floragunn.searchguard.SearchGuardPlugin");
            searchGuardPluginAvailable = settings.getAsArray("searchguard.authcz.admin_dn", new String[0]).length > 0;
        } catch (final ClassNotFoundException cnfe) {
            searchGuardPluginAvailable = false;
        }
        
        if(searchGuardPluginAvailable) {
            log.info("Search Guard 2 plugin also available");
        } else {
            log.info("Search Guard 2 plugin not available");
        }

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
        
    }

    public void onModule(final NetworkModule module) {
        if (!client && httpSSLEnabled) {
            module.registerRestHandler(SearchGuardSSLInfoAction.class);
            module.registerHttpTransport(SearchGuardSSLNettyHttpServerTransport.class.toString(), SearchGuardSSLNettyHttpServerTransport.class);
        }
        
        if (transportSSLEnabled) {
            module.registerTransport(SearchGuardSSLNettyTransport.class.toString(), SearchGuardSSLNettyTransport.class);
            if (!client && !searchGuardPluginAvailable) {
                module.registerTransportService(SearchGuardSSLTransportService.class.toString(), SearchGuardSSLTransportService.class);
            }
        }
    }

    @Override
    public Collection<Module> nodeModules() {
        if (!client) {
            return Arrays.asList(new Module[]{new SearchGuardSSLModule(settings)});
        } else {
            return Arrays.asList(new Module[]{new SearchGuardSSLModule(settings), new EnvironmentModule(new Environment(settings))});
        }
    }
    
    public void onModule(SettingsModule module)
    {              
      module.registerSetting(Setting.boolSetting(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENFORCE_CLIENTAUTH, false, Property.NodeScope, Property.Filtered));
      module.registerSetting(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_CLIENTAUTH_MODE, Property.NodeScope, Property.Filtered));
      module.registerSetting(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_KEYSTORE_ALIAS, Property.NodeScope, Property.Filtered));
      module.registerSetting(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_KEYSTORE_FILEPATH, Property.NodeScope, Property.Filtered));
      module.registerSetting(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_KEYSTORE_PASSWORD, Property.NodeScope, Property.Filtered));
      module.registerSetting(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_KEYSTORE_TYPE, Property.NodeScope, Property.Filtered));
      module.registerSetting(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_TRUSTSTORE_ALIAS, Property.NodeScope, Property.Filtered));
      module.registerSetting(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_TRUSTSTORE_FILEPATH, Property.NodeScope, Property.Filtered));
      module.registerSetting(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_TRUSTSTORE_PASSWORD, Property.NodeScope, Property.Filtered));
      module.registerSetting(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_TRUSTSTORE_TYPE, Property.NodeScope, Property.Filtered));
      module.registerSetting(Setting.boolSetting(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, true, Property.NodeScope, Property.Filtered));
      module.registerSetting(Setting.boolSetting(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLED, false, Property.NodeScope, Property.Filtered));
      module.registerSetting(Setting.boolSetting(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, true,Property.NodeScope, Property.Filtered));
      module.registerSetting(Setting.boolSetting(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLED, true, Property.NodeScope, Property.Filtered));
      //module.registerSetting(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLED_DEFAULT));
      module.registerSetting(Setting.boolSetting(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION, true, Property.NodeScope, Property.Filtered));
      module.registerSetting(Setting.boolSetting(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION_RESOLVE_HOST_NAME, true, Property.NodeScope, Property.Filtered));
      module.registerSetting(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS, Property.NodeScope, Property.Filtered));
      module.registerSetting(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_FILEPATH, Property.NodeScope, Property.Filtered));
      module.registerSetting(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_PASSWORD, Property.NodeScope, Property.Filtered));
      module.registerSetting(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_TYPE, Property.NodeScope, Property.Filtered));
      module.registerSetting(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_TRUSTSTORE_ALIAS, Property.NodeScope, Property.Filtered));
      module.registerSetting(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_TRUSTSTORE_FILEPATH, Property.NodeScope, Property.Filtered));
      module.registerSetting(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_TRUSTSTORE_PASSWORD, Property.NodeScope, Property.Filtered));
      module.registerSetting(Setting.simpleString(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_TRUSTSTORE_TYPE, Property.NodeScope, Property.Filtered));

      module.registerSetting(Setting.simpleString("node.client", Property.NodeScope));

    }

    @Override
    public String description() {
        return "Search Guard SSL";
    }

    @Override
    public String name() {
        return "search-guard-ssl";
    }

    @Override
    public Settings additionalSettings() {
       final Settings.Builder builder = Settings.builder();
        
       if(!client && httpSSLEnabled) {
           builder.put(NetworkModule.HTTP_TYPE_KEY, SearchGuardSSLNettyHttpServerTransport.class.toString());
       }
        
       if (transportSSLEnabled) {
           builder.put(NetworkModule.TRANSPORT_TYPE_KEY, SearchGuardSSLNettyTransport.class.toString());
           if (!client && !searchGuardPluginAvailable) {
               builder.put(NetworkModule.TRANSPORT_SERVICE_TYPE_KEY, SearchGuardSSLTransportService.class.toString());
           }
       }
        
        return builder.build();
    }
}
