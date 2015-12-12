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

package com.floragunn.searchguard.ssl.http.netty;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;

import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.network.NetworkService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.BigArrays;
import org.elasticsearch.env.Environment;
import org.elasticsearch.http.netty.NettyHttpServerTransport;
import org.jboss.netty.channel.ChannelPipeline;
import org.jboss.netty.channel.ChannelPipelineFactory;
import org.jboss.netty.handler.ssl.SslHandler;

import com.floragunn.searchguard.ssl.util.ConfigConstants;
import com.floragunn.searchguard.ssl.util.EnabledSSLCiphers;

public class SearchGuardSSLNettyHttpServerTransport extends NettyHttpServerTransport {

    private final Environment env;

    @Inject
    public SearchGuardSSLNettyHttpServerTransport(final Settings settings, final NetworkService networkService, final BigArrays bigArrays,
            final Environment env) {
        super(settings, networkService, bigArrays);
        this.env = env;
    }

    @Override
    public ChannelPipelineFactory configureServerChannelPipelineFactory() {
        return new SSLHttpChannelPipelineFactory(this, this.settings, this.detailedErrorsEnabled, env);
    }

    protected static class SSLHttpChannelPipelineFactory extends HttpChannelPipelineFactory {

        protected final ESLogger log = Loggers.getLogger(this.getClass());

        private final String keystoreType;
        private final String keystoreFilePath;
        private final String keystorePassword;
        private final boolean enforceClientAuth;

        private final String truststoreType;
        private final String truststoreFilePath;
        private final String truststorePassword;

        public SSLHttpChannelPipelineFactory(final NettyHttpServerTransport transport, final Settings settings,
                final boolean detailedErrorsEnabled, final Environment env) {
            super(transport, detailedErrorsEnabled);
            keystoreType = settings.get(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_HTTP_KEYSTORE_TYPE, "JKS");
            keystoreFilePath = env.configFile()
                    .resolve(settings.get(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_HTTP_KEYSTORE_FILEPATH, null)).toAbsolutePath()
                    .toString();
            keystorePassword = settings.get(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_HTTP_KEYSTORE_PASSWORD, "changeit");
            enforceClientAuth = settings.getAsBoolean(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_HTTP_ENFORCE_CLIENTAUTH, false);
            truststoreType = settings.get(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_HTTP_TRUSTSTORE_TYPE, "JKS");
            truststoreFilePath = env.configFile()
                    .resolve(settings.get(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_HTTP_TRUSTSTORE_FILEPATH, "")).toAbsolutePath()
                    .toString();
            
            
            truststorePassword = settings.get(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_HTTP_TRUSTSTORE_PASSWORD, "changeit");
        }

        @Override
        public ChannelPipeline getPipeline() throws Exception {

            log.trace("SslHandler configured and added to netty pipeline");

            final ChannelPipeline pipeline = super.getPipeline();
            TrustManagerFactory tmf = null;

            if (enforceClientAuth) {

                final KeyStore ts = KeyStore.getInstance(truststoreType);
                ts.load(new FileInputStream(new File(truststoreFilePath)), truststorePassword.toCharArray());

                tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                tmf.init(ts);
                log.debug("Enforce client auth enabled");
            }

            final KeyStore ks = KeyStore.getInstance(keystoreType);
            ks.load(new FileInputStream(new File(keystoreFilePath)), keystorePassword.toCharArray());

            final KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(ks, keystorePassword.toCharArray());

            final SSLContext serverContext = SSLContext.getInstance("TLS");
            serverContext.init(kmf.getKeyManagers(), tmf == null ? null : tmf.getTrustManagers(), null);
            final SSLEngine engine = serverContext.createSSLEngine();
            final SSLParameters sslParams = new SSLParameters();
            sslParams.setCipherSuites(EnabledSSLCiphers.getEbabledSSLCiphers());
            sslParams.setProtocols(EnabledSSLCiphers.getEnabledSSLProtocols());
            sslParams.setNeedClientAuth(enforceClientAuth);
            engine.setSSLParameters(sslParams);
            engine.setUseClientMode(false);

            final SslHandler sslHandler = new SslHandler(engine);
            sslHandler.setEnableRenegotiation(false);
            pipeline.addFirst("ssl_http", sslHandler);
            pipeline.addBefore("handler", "mutual_ssl", new SearchGuardMutualSSLHandler());
            return pipeline;
        }
    }

}
