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

package com.floragunn.searchguard.ssl.transport;

import java.io.File;
import java.io.FileInputStream;
import java.net.InetSocketAddress;
import java.security.KeyStore;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;

import org.elasticsearch.Version;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.io.stream.NamedWriteableRegistry;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.network.NetworkService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.BigArrays;
import org.elasticsearch.env.Environment;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.netty.NettyTransport;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.ChannelPipeline;
import org.jboss.netty.channel.ChannelPipelineFactory;
import org.jboss.netty.channel.ChannelStateEvent;
import org.jboss.netty.channel.SimpleChannelHandler;
import org.jboss.netty.handler.ssl.SslHandler;

import com.floragunn.searchguard.ssl.util.ConfigConstants;
import com.floragunn.searchguard.ssl.util.EnabledSSLCiphers;

public class SearchGuardSSLNettyTransport extends NettyTransport {

    private final Environment env;

    @Inject
    public SearchGuardSSLNettyTransport(final Settings settings, final ThreadPool threadPool, final NetworkService networkService,
            final BigArrays bigArrays, final Version version, final NamedWriteableRegistry namedWriteableRegistry, final Environment env) {
        super(settings, threadPool, networkService, bigArrays, version, namedWriteableRegistry);
        this.env = env;

    }

    @Override
    public ChannelPipelineFactory configureClientChannelPipelineFactory() {
        logger.debug("Node client configured for SSL");
        return new SSLClientChannelPipelineFactory(this, this.settings, this.logger, env);
    }

    @Override
    public ChannelPipelineFactory configureServerChannelPipelineFactory(final String name, final Settings settings) {
        logger.debug("Node server configured for SSL");
        return new SSLServerChannelPipelineFactory(this, name, settings, this.settings, this.logger, env);
    }

    protected static class SSLServerChannelPipelineFactory extends ServerChannelPipelineFactory {

        private final String keystoreType;
        private final String keystoreFilePath;
        private final String keystorePassword;
        private final boolean enforceClientAuth;

        private final String truststoreType;
        private final String truststoreFilePath;
        private final String truststorePassword;
        private final ESLogger nettyLogger;

        public SSLServerChannelPipelineFactory(final NettyTransport nettyTransport, final String name, final Settings sslsettings,
                final Settings essettings, final ESLogger nettyLogger, final Environment env) {
            super(nettyTransport, name, sslsettings);

            keystoreType = essettings.get(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_NODE_KEYSTORE_TYPE, "JKS");
            keystoreFilePath = env.configFile()
                    .resolve(essettings.get(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_NODE_KEYSTORE_FILEPATH, null)).toAbsolutePath()
                    .toString();
            keystorePassword = essettings.get(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_NODE_KEYSTORE_PASSWORD, "changeit");
            enforceClientAuth = essettings.getAsBoolean(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_NODE_ENFORCE_CLIENTAUTH, true);
            truststoreType = essettings.get(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_NODE_TRUSTSTORE_TYPE, "JKS");
            truststoreFilePath = env.configFile()
                    .resolve(essettings.get(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_NODE_TRUSTSTORE_FILEPATH, "")).toAbsolutePath()
                    .toString();
            truststorePassword = essettings.get(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_NODE_TRUSTSTORE_PASSWORD, "changeit");
            this.nettyLogger = nettyLogger;
            
        }

        @Override
        public ChannelPipeline getPipeline() throws Exception {
            final ChannelPipeline pipeline = super.getPipeline();

            TrustManagerFactory tmf = null;

            if (enforceClientAuth) {

                final KeyStore ts = KeyStore.getInstance(truststoreType);
                ts.load(new FileInputStream(new File(truststoreFilePath)), truststorePassword.toCharArray());

                tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                tmf.init(ts);

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
            pipeline.addFirst("ssl_server", sslHandler);
            pipeline.replace("dispatcher", "dispatcher", new SearchGuardMessageChannelHandler(nettyTransport, nettyLogger));

            return pipeline;
        }

    }

    protected static class ClientSSLHandler extends SimpleChannelHandler {
        private final SSLContext serverContext;
        private final boolean hostnameVerificationEnabled;
        private final boolean hostnameVerificationResovleHostName;

        private ClientSSLHandler(final SSLContext serverContext, final boolean hostnameVerificationEnabled,
                final boolean hostnameVerificationResovleHostName) {
            this.hostnameVerificationEnabled = hostnameVerificationEnabled;
            this.hostnameVerificationResovleHostName = hostnameVerificationResovleHostName;
            this.serverContext = serverContext;
        }

        @Override
        public void connectRequested(final ChannelHandlerContext ctx, final ChannelStateEvent event) {
            SSLEngine engine = null;
            final SSLParameters sslParams = new SSLParameters();
            sslParams.setCipherSuites(EnabledSSLCiphers.getEbabledSSLCiphers());
            sslParams.setProtocols(EnabledSSLCiphers.getEnabledSSLProtocols());

            if (hostnameVerificationEnabled) {

                final InetSocketAddress inetSocketAddress = (InetSocketAddress) event.getValue();

                String hostname = null;
                if (hostnameVerificationResovleHostName) {
                    hostname = inetSocketAddress.getHostName();
                } else {
                    hostname = inetSocketAddress.getHostString();
                }

                engine = serverContext.createSSLEngine(hostname, inetSocketAddress.getPort());
                sslParams.setEndpointIdentificationAlgorithm("HTTPS");
            } else {
                engine = serverContext.createSSLEngine();
            }

            engine.setSSLParameters(sslParams);
            engine.setUseClientMode(true);

            final SslHandler sslHandler = new SslHandler(engine);
            sslHandler.setEnableRenegotiation(false);
            ctx.getPipeline().replace(this, "ssl_client", sslHandler);

            ctx.sendDownstream(event);
        }
    }

    protected static class SSLClientChannelPipelineFactory extends ClientChannelPipelineFactory {

        private final String keystoreType;
        private final String keystoreFilePath;
        private final String keystorePassword;
        private final boolean hostnameVerificationEnabled;
        private final boolean hostnameVerificationResovleHostName;
        private final String truststoreType;
        private final String truststoreFilePath;
        private final String truststorePassword;
        private final ESLogger nettyLogger;

        public SSLClientChannelPipelineFactory(final NettyTransport nettyTransport, final Settings settings, final ESLogger nettyLogger,
                final Environment env) {
            super(nettyTransport);

            keystoreType = settings.get(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_NODE_KEYSTORE_TYPE, "JKS");
            keystoreFilePath = env.configFile()
                    .resolve(settings.get(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_NODE_KEYSTORE_FILEPATH, null)).toAbsolutePath()
                    .toString();
            keystorePassword = settings.get(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_NODE_KEYSTORE_PASSWORD, "changeit");
            truststoreType = settings.get(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_NODE_TRUSTSTORE_TYPE, "JKS");
            truststoreFilePath = env.configFile()
                    .resolve(settings.get(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_NODE_TRUSTSTORE_FILEPATH, "")).toAbsolutePath()
                    .toString();
            truststorePassword = settings.get(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_NODE_TRUSTSTORE_PASSWORD, "changeit");
            hostnameVerificationEnabled = settings.getAsBoolean(
                    ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_NODE_ENCFORCE_HOSTNAME_VERIFICATION, true);
            hostnameVerificationResovleHostName = settings.getAsBoolean(
                    ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_NODE_ENCFORCE_HOSTNAME_VERIFICATION_RESOLVE_HOST_NAME, true);

            this.nettyLogger = nettyLogger;
        }

        @Override
        public ChannelPipeline getPipeline() throws Exception {
            final ChannelPipeline pipeline = super.getPipeline();

            // ## Truststore ##
            final KeyStore ts = KeyStore.getInstance(truststoreType);
            ts.load(new FileInputStream(new File(truststoreFilePath)), truststorePassword.toCharArray());

            final TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ts);

            // ## Keystore ##
            final KeyStore ks = KeyStore.getInstance(keystoreType);
            ks.load(new FileInputStream(new File(keystoreFilePath)), keystorePassword.toCharArray());

            final KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(ks, keystorePassword.toCharArray());

            final SSLContext serverContext = SSLContext.getInstance("TLS");
            serverContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

            pipeline.addFirst("client_ssl_handler", new ClientSSLHandler(serverContext, hostnameVerificationEnabled,
                    hostnameVerificationResovleHostName));

            pipeline.replace("dispatcher", "dispatcher", new SearchGuardMessageChannelHandler(nettyTransport, nettyLogger));

            return pipeline;
        }

    }
}
