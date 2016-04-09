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

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.concurrent.Callable;
import java.util.function.Supplier;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.security.auth.x500.X500Principal;

import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.Transport;
import org.elasticsearch.transport.TransportChannel;
import org.elasticsearch.transport.TransportRequest;
import org.elasticsearch.transport.TransportRequestHandler;
import org.elasticsearch.transport.TransportService;
import org.elasticsearch.transport.netty.NettyTransportChannel;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.handler.ssl.SslHandler;

public class SearchGuardSSLTransportService extends TransportService {

    private final ThreadContext threadContext;
    
    @Inject
    public SearchGuardSSLTransportService(final Settings settings, final Transport transport, final ThreadPool threadPool, ThreadContext threadContext) {
        super(settings, transport, threadPool);
        this.threadContext = threadContext;
    }
    
    @Override
    public <Request extends TransportRequest> void registerRequestHandler(String action, Supplier<Request> requestFactory, String executor, TransportRequestHandler<Request> handler) {
        super.registerRequestHandler(action, requestFactory, executor, new Interceptor<Request>(handler, action, threadContext));
    }

    @Override
    public <Request extends TransportRequest> void registerRequestHandler(String action, Supplier<Request> request, String executor, boolean forceExecution, TransportRequestHandler<Request> handler) {
        super.registerRequestHandler(action, request, executor, forceExecution, new Interceptor<Request>(handler, action, threadContext));
    }
    
    private class Interceptor<Request extends TransportRequest> implements TransportRequestHandler<Request> {

        private final ESLogger log = Loggers.getLogger(this.getClass());
        private final TransportRequestHandler<Request> handler;
        private final String action;
        private final ThreadContext threadContext;

        public Interceptor(final TransportRequestHandler<Request> handler, final String acion, ThreadContext threadContext) {
            super();
            this.handler = handler;
            this.action = acion;
            this.threadContext = threadContext;
        }
        
        @Override
        public void messageReceived(Request request, TransportChannel channel) throws Exception {
            messageReceived(request, channel, null);
        }

        @Override
        public void messageReceived(final Request request, final TransportChannel transportChannel, Task task) throws Exception {

            if (!(transportChannel instanceof NettyTransportChannel)) {
                messageReceivedDecorate(request, handler, transportChannel, task);
                return;
            }

            try {
                final Channel channel = ((NettyTransportChannel) transportChannel).getChannel();
                final SslHandler sslhandler = (SslHandler) channel.getPipeline().get("ssl_server");

                if (sslhandler == null) {
                    final String msg = "No ssl handler found";
                    log.error(msg);
                    final Exception exception = new ElasticsearchException(msg);
                    transportChannel.sendResponse(exception);
                    throw exception;
                }

                X500Principal principal;

                final Certificate[] certs = sslhandler.getEngine().getSession().getPeerCertificates();
                
                if (certs != null && certs.length > 0 && certs[0] instanceof X509Certificate) {
                    X509Certificate[] x509Certs = Arrays.copyOf(certs, certs.length, X509Certificate[].class);
                    addAdditionalContextValues(action, request, x509Certs);
                    principal = x509Certs[0].getSubjectX500Principal();
                    this.threadContext.putTransient("_sg_ssl_transport_principal", principal == null ? null : principal.getName());
                    this.threadContext.putTransient("_sg_ssl_transport_peer_certificates", x509Certs);
                    this.threadContext.putTransient("_sg_ssl_transport_protocol", sslhandler.getEngine().getSession().getProtocol());
                    this.threadContext.putTransient("_sg_ssl_transport_cipher", sslhandler.getEngine().getSession().getCipherSuite());
                    messageReceivedDecorate(request, handler, transportChannel, task);
                } else {
                    final String msg = "No X509 transport client certificates found (SG 12)";
                    log.error(msg);
                    final Exception exception = new ElasticsearchException(msg);
                    transportChannel.sendResponse(exception);
                    throw exception;
                }

            } catch (final SSLPeerUnverifiedException e) {
                log.error("Can not verify SSL peer (SG 13) due to {}", e, e);
                final Exception exception = ExceptionsHelper.convertToElastic(e);
                transportChannel.sendResponse(exception);
                throw exception;
            } catch (final Exception e) {
                log.error("Unexpected SSL exception (SG 14) due to {}", e, e);
                final Exception exception = ExceptionsHelper.convertToElastic(e);
                transportChannel.sendResponse(exception);
                throw exception;
            }
        }

    }

    protected void addAdditionalContextValues(final String action, final TransportRequest request, final X509Certificate[] certs)
            throws Exception {
        // no-op
    }
    
    protected void messageReceivedDecorate(final TransportRequest request, final TransportRequestHandler handler, final TransportChannel transportChannel, Task task) throws Exception {
        handler.messageReceived(request, transportChannel, task);
    }
}
