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

import io.netty.channel.Channel;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.ssl.NotSslRecordException;
import io.netty.handler.ssl.SslHandler;

import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLPeerUnverifiedException;

import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.common.network.NetworkService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.BigArrays;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.http.netty4.Netty4HttpServerTransport;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.threadpool.ThreadPool;

import com.floragunn.searchguard.ssl.SearchGuardKeyStore;
import com.floragunn.searchguard.ssl.util.SSLRequestHelper;

public class SearchGuardSSLNettyHttpServerTransport extends Netty4HttpServerTransport {

    private final SearchGuardKeyStore sgks;
    private final ThreadContext threadContext;
    
    public SearchGuardSSLNettyHttpServerTransport(final Settings settings, final NetworkService networkService, final BigArrays bigArrays,
            ThreadPool threadPool, final SearchGuardKeyStore sgks, NamedXContentRegistry namedXContentRegistry) {
        super(settings, networkService, bigArrays, threadPool, namedXContentRegistry);
        this.sgks = sgks;
        this.threadContext = threadPool.getThreadContext();
    }

    @Override
    public ChannelHandler configureServerChannelHandler() {
        return new SSLHttpChannelHandler(this, sgks);
    }

    @Override
    protected void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        if(this.lifecycle.started()) {
            
            if(cause instanceof NotSslRecordException) {
                logger.warn("Someone ({}) speaks http plaintext instead of ssl, will close the channel", ctx.channel().remoteAddress());
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

    protected class SSLHttpChannelHandler extends Netty4HttpServerTransport.HttpChannelHandler {
        
        protected SSLHttpChannelHandler(Netty4HttpServerTransport transport, final SearchGuardKeyStore sgks) {
            super(transport, SearchGuardSSLNettyHttpServerTransport.this.detailedErrorsEnabled, SearchGuardSSLNettyHttpServerTransport.this.threadContext);
        }

        @Override
        protected void initChannel(Channel ch) throws Exception {
            super.initChannel(ch);
            final SslHandler sslHandler = new SslHandler(SearchGuardSSLNettyHttpServerTransport.this.sgks.createHTTPSSLEngine());
            ch.pipeline().addFirst("ssl_http", sslHandler);
        }
    }

    @Override
    protected void dispatchRequest(final RestRequest request, final RestChannel channel) {
        
        if(SSLRequestHelper.containsBadHeader(threadContext, "_sg_ssl_")) {
            final ElasticsearchException exception = new ElasticsearchException("bad header found");
            errorThrown(exception, request);
            //channel.sendResponse();
            throw exception;
        }
        
        try {
            if(SSLRequestHelper.getSSLInfo(request, null) == null) {
                logger.error("Not an SSL request");
                throw new ElasticsearchSecurityException("Not an SSL request", RestStatus.INTERNAL_SERVER_ERROR);
            }
        } catch (SSLPeerUnverifiedException e) {
            logger.error("No client certificates found but such are needed (SG 8).");
            errorThrown(e, request);
          //channel.sendResponse();
            throw ExceptionsHelper.convertToElastic(e);
        }
        super.dispatchRequest(request, channel);
    }
    
    protected void errorThrown(Throwable t, final RestRequest request) {
        // no-op
    }

}
