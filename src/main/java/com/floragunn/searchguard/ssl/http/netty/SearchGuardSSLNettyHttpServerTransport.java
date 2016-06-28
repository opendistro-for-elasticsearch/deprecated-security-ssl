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

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.security.auth.x500.X500Principal;

import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.network.NetworkService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.BigArrays;
import org.elasticsearch.http.HttpChannel;
import org.elasticsearch.http.HttpRequest;
import org.elasticsearch.http.netty.NettyHttpRequest;
import org.elasticsearch.http.netty.NettyHttpServerTransport;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.ChannelPipeline;
import org.jboss.netty.channel.ChannelPipelineFactory;
import org.jboss.netty.channel.ExceptionEvent;
import org.jboss.netty.handler.ssl.NotSslRecordException;
import org.jboss.netty.handler.ssl.SslHandler;

import com.floragunn.searchguard.ssl.SearchGuardKeyStore;
import com.floragunn.searchguard.ssl.util.HeaderHelper;

public class SearchGuardSSLNettyHttpServerTransport extends NettyHttpServerTransport {

    private final SearchGuardKeyStore sgks;

    @Inject
    public SearchGuardSSLNettyHttpServerTransport(final Settings settings, final NetworkService networkService, final BigArrays bigArrays,
            final SearchGuardKeyStore sgks) {
        super(settings, networkService, bigArrays);
        this.sgks = sgks;
    }

    @Override
    public ChannelPipelineFactory configureServerChannelPipelineFactory() {
        return new SSLHttpChannelPipelineFactory(this, this.settings, this.detailedErrorsEnabled, sgks);
    }

    @Override
    protected void exceptionCaught(ChannelHandlerContext ctx, ExceptionEvent e) throws Exception {
        if(this.lifecycle.started()) {
            
            final Throwable cause = e.getCause();
            if(cause instanceof NotSslRecordException) {
                logger.warn("Someone speaks plaintext instead of ssl, will close the channel");
                ctx.getChannel().close();
                return;
            } else if (cause instanceof SSLException) {
                logger.error("SSL Problem "+cause.getMessage(),cause);
                ctx.getChannel().close();
                return;
            } else if (cause instanceof SSLHandshakeException) {
                logger.error("Problem during handshake "+cause.getMessage());
                ctx.getChannel().close();
                return;
            }
        }
        
        super.exceptionCaught(ctx, e);
    }

    protected static class SSLHttpChannelPipelineFactory extends HttpChannelPipelineFactory {

        protected final ESLogger log = Loggers.getLogger(this.getClass());
        private final SearchGuardKeyStore sgks;

        public SSLHttpChannelPipelineFactory(final NettyHttpServerTransport transport, final Settings settings,
                final boolean detailedErrorsEnabled, final SearchGuardKeyStore sgks) {
            super(transport, detailedErrorsEnabled);
            this.sgks = sgks;
        }

        @Override
        public ChannelPipeline getPipeline() throws Exception {
            log.trace("SslHandler configured and added to netty pipeline");

            final ChannelPipeline pipeline = super.getPipeline();
            final SslHandler sslHandler = new SslHandler(sgks.createHTTPSSLEngine());
            sslHandler.setEnableRenegotiation(false);
            pipeline.addFirst("ssl_http", sslHandler);
            return pipeline;
        }
    }

    @Override
    protected void dispatchRequest(final HttpRequest request, final HttpChannel channel) {

        HeaderHelper.checkSGHeader(request);
        
        final NettyHttpRequest nettyHttpRequest = (NettyHttpRequest) request;
        final SslHandler sslhandler = (SslHandler) nettyHttpRequest.getChannel().getPipeline().get("ssl_http");
        final SSLEngine engine = sslhandler.getEngine();

        if(engine.getNeedClientAuth() || engine.getWantClientAuth()) {
        
            try {
                final Certificate[] certs = sslhandler.getEngine().getSession().getPeerCertificates();

                if (certs != null && certs.length > 0 && certs[0] instanceof X509Certificate) {
                    X509Certificate[] x509Certs = Arrays.copyOf(certs, certs.length, X509Certificate[].class);
                    X500Principal principal =  x509Certs[0].getSubjectX500Principal();
                    request.putInContext("_sg_ssl_principal", principal == null ? null : principal.getName());
                    request.putInContext("_sg_ssl_peer_certificates", x509Certs);
                } else if(engine.getNeedClientAuth()) {
                    ElasticsearchException ex = new ElasticsearchException("No client certificates found but such are needed (SG 9).");
                    errorThrown(ex, nettyHttpRequest);
                    throw ex;
                }

            } catch(SSLPeerUnverifiedException e) {
                if(engine.getNeedClientAuth()) {
                    logger.error("No client certificates found but such are needed (SG 8).");
                    errorThrown(e, nettyHttpRequest);
                    throw ExceptionsHelper.convertToElastic(e);
                }
            }
            catch (final Exception e) {
                logger.error("Unknow error (SG 8) : "+e,e);
                errorThrown(e, nettyHttpRequest);
                throw ExceptionsHelper.convertToElastic(e);
            }
           
        } else {
            request.putInContext("_sg_ssl_client_auth_none", true);
        }
        
        request.putInContext("_sg_ssl_protocol", sslhandler.getEngine().getSession().getProtocol());
        request.putInContext("_sg_ssl_cipher", sslhandler.getEngine().getSession().getCipherSuite());

        super.dispatchRequest(request, channel);
    }
    
    protected void errorThrown(Throwable t, final NettyHttpRequest request) {
        // no-op
    }

}
