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

import java.net.InetSocketAddress;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;

import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.Version;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.io.stream.NamedWriteableRegistry;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.network.NetworkService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.BigArrays;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.netty.NettyTransport;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.ChannelPipeline;
import org.jboss.netty.channel.ChannelPipelineFactory;
import org.jboss.netty.channel.ChannelStateEvent;
import org.jboss.netty.channel.ExceptionEvent;
import org.jboss.netty.channel.SimpleChannelHandler;
import org.jboss.netty.handler.ssl.NotSslRecordException;
import org.jboss.netty.handler.ssl.SslHandler;

import com.floragunn.searchguard.ssl.SearchGuardKeyStore;
import com.floragunn.searchguard.ssl.util.SSLConfigConstants;

public class SearchGuardSSLNettyTransport extends NettyTransport {

    @Override
    protected void exceptionCaught(ChannelHandlerContext ctx, ExceptionEvent e) throws Exception {
        if(this.lifecycle.started()) {
            
            final Throwable cause = e.getCause();
            if(cause instanceof NotSslRecordException) {
                logger.warn("Someone speaks plaintext instead of ssl, will close the channel");
                ctx.getChannel().close();
                disconnectFromNodeChannel(ctx.getChannel(), e.getCause());
                return;
            } else if (cause instanceof SSLException) {
                logger.error("SSL Problem "+cause.getMessage(),cause);
                ctx.getChannel().close();
                disconnectFromNodeChannel(ctx.getChannel(), e.getCause());
                return;
            } else if (cause instanceof SSLHandshakeException) {
                logger.error("Problem during handshake "+cause.getMessage());
                ctx.getChannel().close();
                disconnectFromNodeChannel(ctx.getChannel(), e.getCause());
                return;
            }
        }
        
        super.exceptionCaught(ctx, e);
    }

    private final SearchGuardKeyStore sgks;

    @Inject
    public SearchGuardSSLNettyTransport(final Settings settings, final ThreadPool threadPool, final NetworkService networkService,
            final BigArrays bigArrays, final Version version, final NamedWriteableRegistry namedWriteableRegistry,
            final SearchGuardKeyStore sgks) {
        super(settings, threadPool, networkService, bigArrays, version, namedWriteableRegistry);
        this.sgks = sgks;
    }

    @Override
    public ChannelPipelineFactory configureClientChannelPipelineFactory() {
        logger.debug("Node client configured for SSL");
        return new SSLClientChannelPipelineFactory(this, this.settings, this.logger, sgks);
    }

    @Override
    public ChannelPipelineFactory configureServerChannelPipelineFactory(final String name, final Settings settings) {
        logger.debug("Node server configured for SSL");
        return new SSLServerChannelPipelineFactory(this, name, settings, this.settings, this.logger, sgks);
    }

    protected static class SSLServerChannelPipelineFactory extends ServerChannelPipelineFactory {

        private final ESLogger nettyLogger;
        private final SearchGuardKeyStore sgks;

        public SSLServerChannelPipelineFactory(final NettyTransport nettyTransport, final String name, final Settings sslsettings,
                final Settings essettings, final ESLogger nettyLogger, final SearchGuardKeyStore sgks) {
            super(nettyTransport, name, sslsettings);
            this.sgks = sgks;
            this.nettyLogger = nettyLogger;

        }

        @Override
        public ChannelPipeline getPipeline() throws Exception {
            final ChannelPipeline pipeline = super.getPipeline();
            final SslHandler sslHandler = new SslHandler(sgks.createServerTransportSSLEngine());
            sslHandler.setEnableRenegotiation(false);
            pipeline.addFirst("ssl_server", sslHandler);
            pipeline.replace("dispatcher", "dispatcher", new SearchGuardMessageChannelHandler(nettyTransport, nettyLogger));

            return pipeline;
        }

    }

    protected static class ClientSSLHandler extends SimpleChannelHandler {
        private final ESLogger log = Loggers.getLogger(this.getClass());
        private final boolean hostnameVerificationEnabled;
        private final boolean hostnameVerificationResovleHostName;
        private final SearchGuardKeyStore sgks;

        private ClientSSLHandler(final SearchGuardKeyStore sgks, final boolean hostnameVerificationEnabled,
                final boolean hostnameVerificationResovleHostName) {
            this.sgks = sgks;
            this.hostnameVerificationEnabled = hostnameVerificationEnabled;
            this.hostnameVerificationResovleHostName = hostnameVerificationResovleHostName;
        }

        //TODO check if we need to implement these:
        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, ExceptionEvent e) throws Exception {            
            super.exceptionCaught(ctx, e);
        }

        @Override
        public void connectRequested(final ChannelHandlerContext ctx, final ChannelStateEvent event) {
            SSLEngine engine = null;
            try {
                if (hostnameVerificationEnabled) {
                    final InetSocketAddress inetSocketAddress = (InetSocketAddress) event.getValue();
                    String hostname = null;
                    if (hostnameVerificationResovleHostName) {
                        hostname = inetSocketAddress.getHostName();
                    } else {
                        hostname = inetSocketAddress.getHostString();
                    }

                    if(log.isDebugEnabled()) {
                        log.debug("Hostname of peer is {} ({}/{}) with hostnameVerificationResovleHostName: {}", hostname, inetSocketAddress.getHostName(), inetSocketAddress.getHostString(), hostnameVerificationResovleHostName);
                    }
                    
                    engine = sgks.createClientTransportSSLEngine(hostname, inetSocketAddress.getPort());
                } else {
                    engine = sgks.createClientTransportSSLEngine(null, -1);
                }
            } catch (final SSLException e) {
                throw ExceptionsHelper.convertToElastic(e);
            }

            final SslHandler sslHandler = new SslHandler(engine);
            sslHandler.setEnableRenegotiation(false);
            ctx.getPipeline().replace(this, "ssl_client", sslHandler);
            ctx.sendDownstream(event);
        }
    }

    protected static class SSLClientChannelPipelineFactory extends ClientChannelPipelineFactory {
        private final boolean hostnameVerificationEnabled;
        private final boolean hostnameVerificationResovleHostName;
        private final ESLogger nettyLogger;
        private final SearchGuardKeyStore sgks;

        public SSLClientChannelPipelineFactory(final NettyTransport nettyTransport, final Settings settings, final ESLogger nettyLogger,
                final SearchGuardKeyStore sgks) {
            super(nettyTransport);
            this.sgks = sgks;

            hostnameVerificationEnabled = settings.getAsBoolean(
                    SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION, true);
            hostnameVerificationResovleHostName = settings.getAsBoolean(
                    SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION_RESOLVE_HOST_NAME, true);

            this.nettyLogger = nettyLogger;
        }

        @Override
        public ChannelPipeline getPipeline() throws Exception {
            final ChannelPipeline pipeline = super.getPipeline();
            pipeline.addFirst("client_ssl_handler", new ClientSSLHandler(sgks, hostnameVerificationEnabled,
                    hostnameVerificationResovleHostName));
            pipeline.replace("dispatcher", "dispatcher", new SearchGuardMessageChannelHandler(nettyTransport, nettyLogger));
            return pipeline;
        }

    }
}
