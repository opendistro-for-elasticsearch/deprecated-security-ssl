/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Portions Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package com.amazon.opendistrosecurity.ssl.transport;

import io.netty.channel.Channel;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelOutboundHandlerAdapter;
import io.netty.channel.ChannelPromise;
import io.netty.handler.codec.DecoderException;
import io.netty.handler.ssl.NotSslRecordException;
import io.netty.handler.ssl.SslHandler;

import java.net.InetSocketAddress;
import java.net.SocketAddress;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.cluster.node.DiscoveryNode;
import org.elasticsearch.common.io.stream.NamedWriteableRegistry;
import org.elasticsearch.common.network.NetworkService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.BigArrays;
import org.elasticsearch.indices.breaker.CircuitBreakerService;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.TcpChannel;
import org.elasticsearch.transport.netty4.Netty4Transport;

import com.amazon.opendistrosecurity.ssl.OpenDistroSecurityKeyStore;
import com.amazon.opendistrosecurity.ssl.SslExceptionHandler;
import com.amazon.opendistrosecurity.ssl.util.SSLConfigConstants;

public class OpenDistroSecuritySSLNettyTransport extends Netty4Transport {

    private final OpenDistroSecurityKeyStore sgks;
    private final SslExceptionHandler errorHandler;

    public OpenDistroSecuritySSLNettyTransport(final Settings settings, final ThreadPool threadPool, final NetworkService networkService,
            final BigArrays bigArrays, final NamedWriteableRegistry namedWriteableRegistry,
            final CircuitBreakerService circuitBreakerService, final OpenDistroSecurityKeyStore sgks, final SslExceptionHandler errorHandler) {
        super(settings, threadPool, networkService, bigArrays, namedWriteableRegistry, circuitBreakerService);
        this.sgks = sgks;
        this.errorHandler = errorHandler;
    }

    @Override
    protected void onException(TcpChannel channel, Exception e) {
        
        
        if (lifecycle.started()) {
            
            Throwable cause = e;
            
            if(e instanceof DecoderException && e != null) {
                cause = e.getCause();
            }
            
            errorHandler.logError(cause, false);
            
            if(cause instanceof NotSslRecordException) {
                logger.warn("Someone ({}) speaks transport plaintext instead of ssl, will close the channel", channel.getLocalAddress());
                TcpChannel.closeChannel(channel, false);
                return;
            } else if (cause instanceof SSLException) {
                logger.error("SSL Problem "+cause.getMessage(),cause);
                TcpChannel.closeChannel(channel, false);
                return;
            } else if (cause instanceof SSLHandshakeException) {
                logger.error("Problem during handshake "+cause.getMessage());
                TcpChannel.closeChannel(channel, false);
                return;
            }
        }
        super.onException(channel, e);
    }

    @Override
    protected ChannelHandler getServerChannelInitializer(String name) {
        return new SSLServerChannelInitializer(name);
    }
    
    @Override
    protected ChannelHandler getClientChannelInitializer(DiscoveryNode node) {
        return new SSLClientChannelInitializer(node);
    }

    protected class SSLServerChannelInitializer extends Netty4Transport.ServerChannelInitializer {

        public SSLServerChannelInitializer(String name) {
            super(name);
        }

        @Override
        protected void initChannel(Channel ch) throws Exception {
            super.initChannel(ch);
            final SslHandler sslHandler = new SslHandler(sgks.createServerTransportSSLEngine());
            ch.pipeline().addFirst("ssl_server", sslHandler);
        }
        
        @Override
        public final void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
            if(OpenDistroSecuritySSLNettyTransport.this.lifecycle.started()) {
                
                if(cause instanceof DecoderException && cause != null) {
                    cause = cause.getCause();
                }
                
                errorHandler.logError(cause, false);
                
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
        private final OpenDistroSecurityKeyStore sgks;
        private final boolean hostnameVerificationEnabled;
        private final boolean hostnameVerificationResovleHostName;
        private final SslExceptionHandler errorHandler;
        

        private ClientSSLHandler(final OpenDistroSecurityKeyStore sgks, final boolean hostnameVerificationEnabled,
                final boolean hostnameVerificationResovleHostName, final SslExceptionHandler errorHandler) {
            this.sgks = sgks;
            this.hostnameVerificationEnabled = hostnameVerificationEnabled;
            this.hostnameVerificationResovleHostName = hostnameVerificationResovleHostName;
            this.errorHandler = errorHandler;
        }
        

        @Override
        public final void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
            if(cause instanceof DecoderException && cause != null) {
                cause = cause.getCause();
            }
            
            errorHandler.logError(cause, false);
            
            if(cause instanceof NotSslRecordException) {
                log.warn("Someone ({}) speaks transport plaintext instead of ssl, will close the channel", ctx.channel().remoteAddress());
                ctx.channel().close();
                return;
            } else if (cause instanceof SSLException) {
                log.error("SSL Problem "+cause.getMessage(),cause);
                ctx.channel().close();
                return;
            } else if (cause instanceof SSLHandshakeException) {
                log.error("Problem during handshake "+cause.getMessage());
                ctx.channel().close();
                return;
            }

            super.exceptionCaught(ctx, cause);
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

        public SSLClientChannelInitializer(DiscoveryNode node) {
            hostnameVerificationEnabled = settings.getAsBoolean(
                    SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION, true);
            hostnameVerificationResovleHostName = settings.getAsBoolean(
                    SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION_RESOLVE_HOST_NAME, true);
        }

        @Override
        protected void initChannel(Channel ch) throws Exception {
            super.initChannel(ch);
            ch.pipeline().addFirst("client_ssl_handler", new ClientSSLHandler(sgks, hostnameVerificationEnabled,
                    hostnameVerificationResovleHostName, errorHandler));
        }
        
        @Override
        public final void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
            if(OpenDistroSecuritySSLNettyTransport.this.lifecycle.started()) {
                
                if(cause instanceof DecoderException && cause != null) {
                    cause = cause.getCause();
                }
                
                errorHandler.logError(cause, false);
                
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
