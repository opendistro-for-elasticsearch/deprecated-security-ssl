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

import io.netty.channel.Channel;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelOutboundHandlerAdapter;
import io.netty.channel.ChannelPromise;
import io.netty.handler.ssl.NotSslRecordException;
import io.netty.handler.ssl.SslHandler;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.common.io.stream.NamedWriteableRegistry;
import org.elasticsearch.common.network.NetworkService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.BigArrays;
import org.elasticsearch.indices.breaker.CircuitBreakerService;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.netty4.Netty4Transport;

import com.floragunn.searchguard.ssl.SearchGuardKeyStore;
import com.floragunn.searchguard.ssl.util.SSLConfigConstants;

public class SearchGuardSSLNettyTransport extends Netty4Transport {

    private final SearchGuardKeyStore sgks;

    public SearchGuardSSLNettyTransport(final Settings settings, final ThreadPool threadPool, final NetworkService networkService,
            final BigArrays bigArrays, final NamedWriteableRegistry namedWriteableRegistry,
            final CircuitBreakerService circuitBreakerService, final SearchGuardKeyStore sgks) {
        super(settings, threadPool, networkService, bigArrays, namedWriteableRegistry, circuitBreakerService);
        this.sgks = sgks;
    }
    
    @Override
    protected void onException(Channel channel, Exception e) throws IOException {
        if (lifecycle.started()) {
            final Throwable cause = e.getCause();
            if(cause instanceof NotSslRecordException) {
                logger.warn("Someone ({}) speaks transport plaintext instead of ssl, will close the channel", channel.remoteAddress());
                disconnectFromNodeChannel(channel, e);
                return;
            } else if (cause instanceof SSLException) {
                logger.error("SSL Problem "+cause.getMessage(),cause);
                disconnectFromNodeChannel(channel, e);
                return;
            } else if (cause instanceof SSLHandshakeException) {
                logger.error("Problem during handshake "+cause.getMessage());
                disconnectFromNodeChannel(channel, e);
                return;
            }
        }
        super.onException(channel, e);
    }

    @Override
    protected ChannelHandler getServerChannelInitializer(String name, Settings remoteAddress) {
        return new SSLServerChannelInitializer(name, remoteAddress);
    }

    @Override
    protected ChannelHandler getClientChannelInitializer() {
        return new SSLClientChannelInitializer();
    }

    protected class SSLServerChannelInitializer extends Netty4Transport.ServerChannelInitializer {

        public SSLServerChannelInitializer(String name, Settings profileSettings) {
            super(name, profileSettings);
        }

        @Override
        protected void initChannel(Channel ch) throws Exception {
            super.initChannel(ch);
            final SslHandler sslHandler = new SslHandler(sgks.createServerTransportSSLEngine());
            ch.pipeline().addFirst("ssl_server", sslHandler);
        }
        
        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
            if(SearchGuardSSLNettyTransport.this.lifecycle.started()) {
                
                if(cause instanceof NotSslRecordException) {
                    logger.warn("Someone ({}) speaks transport plaintext instead of ssl, will close the channel", ctx.channel().remoteAddress());
                    ctx.channel().close();
                    return;
                } else if (cause instanceof SSLException) {
                    logger.error("SSL Problem "+cause.getMessage(),cause);
                    ctx.channel().close();
                    return;
                } else if (cause instanceof SSLHandshakeException) {
                    logger.error("Problem during handshake "+cause.getMessage());
                    ctx.channel().close();
                    return;
                }
            }
            
            super.exceptionCaught(ctx, cause);
        }
    }

    protected static class ClientSSLHandler extends ChannelOutboundHandlerAdapter {
        private final Logger log = LogManager.getLogger(this.getClass());
        private final SearchGuardKeyStore sgks;
        private final boolean hostnameVerificationEnabled;
        private final boolean hostnameVerificationResovleHostName;
        

        private ClientSSLHandler(final SearchGuardKeyStore sgks, final boolean hostnameVerificationEnabled,
                final boolean hostnameVerificationResovleHostName) {
            this.sgks = sgks;
            this.hostnameVerificationEnabled = hostnameVerificationEnabled;
            this.hostnameVerificationResovleHostName = hostnameVerificationResovleHostName;
        }

        @Override
        public void connect(ChannelHandlerContext ctx, SocketAddress remoteAddress, SocketAddress localAddress, ChannelPromise promise) throws Exception {
            SSLEngine engine = null;
            try {
                if (hostnameVerificationEnabled) {
                    final InetSocketAddress inetSocketAddress = (InetSocketAddress) remoteAddress;
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
            ctx.pipeline().replace(this, "ssl_client", sslHandler);
            super.connect(ctx, remoteAddress, localAddress, promise);
        }
    }

    protected class SSLClientChannelInitializer extends Netty4Transport.ClientChannelInitializer {
        private final boolean hostnameVerificationEnabled;
        private final boolean hostnameVerificationResovleHostName;

        public SSLClientChannelInitializer() {
            hostnameVerificationEnabled = settings.getAsBoolean(
                    SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION, true);
            hostnameVerificationResovleHostName = settings.getAsBoolean(
                    SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION_RESOLVE_HOST_NAME, true);
        }

        @Override
        protected void initChannel(Channel ch) throws Exception {
            super.initChannel(ch);
            ch.pipeline().addFirst("client_ssl_handler", new ClientSSLHandler(sgks, hostnameVerificationEnabled,
                    hostnameVerificationResovleHostName));
        }
        
        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
            if(SearchGuardSSLNettyTransport.this.lifecycle.started()) {
                
                if(cause instanceof NotSslRecordException) {
                    logger.warn("Someone ({}) speaks transport plaintext instead of ssl, will close the channel", ctx.channel().remoteAddress());
                    ctx.channel().close();
                    return;
                } else if (cause instanceof SSLException) {
                    logger.error("SSL Problem "+cause.getMessage(),cause);
                    ctx.channel().close();
                    return;
                } else if (cause instanceof SSLHandshakeException) {
                    logger.error("Problem during handshake "+cause.getMessage());
                    ctx.channel().close();
                    return;
                }
            }
            
            super.exceptionCaught(ctx, cause);
        }
    }
}
