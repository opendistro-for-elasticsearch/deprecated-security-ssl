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
import java.util.concurrent.Callable;

import javax.security.auth.x500.X500Principal;

import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;
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

    @Inject
    public SearchGuardSSLTransportService(final Settings settings, final Transport transport, final ThreadPool threadPool) {
        super(settings, transport, threadPool);
    }

    @Override
    public <Request extends TransportRequest> void registerRequestHandler(final String action, final Callable<Request> requestFactory,
            final String executor, final TransportRequestHandler<Request> handler) {
        super.registerRequestHandler(action, requestFactory, executor, new Interceptor<Request>(handler));
    }

    @Override
    public <Request extends TransportRequest> void registerRequestHandler(final String action, final Class<Request> request,
            final String executor, final boolean forceExecution, final TransportRequestHandler<Request> handler) {
        super.registerRequestHandler(action, request, executor, forceExecution, new Interceptor<Request>(handler));
    }

    private static class Interceptor<Request extends TransportRequest> implements TransportRequestHandler<Request> {

        private final ESLogger log = Loggers.getLogger(this.getClass());
        TransportRequestHandler<Request> handler;

        public Interceptor(final TransportRequestHandler<Request> handler) {
            super();
            this.handler = handler;
        }

        @Override
        public void messageReceived(final Request request, final TransportChannel transportChannel) throws Exception {

            if (!(transportChannel instanceof NettyTransportChannel)) {
                this.handler.messageReceived(request, transportChannel);
                return;
            }

            try {
                final Channel channel = ((NettyTransportChannel) transportChannel).getChannel();
                final SslHandler sslhandler = (SslHandler) channel.getPipeline().get("ssl_server");
                X500Principal principal;

                final Certificate[] certs = sslhandler.getEngine().getSession().getPeerCertificates();

                if (certs != null && certs.length > 0 && certs instanceof X509Certificate[]) {
                    addAdditionalContextValues(request, (X509Certificate[]) certs);
                    principal = ((X509Certificate) certs[0]).getSubjectX500Principal();
                    request.putInContext("_sg_ssl_transport_principal", principal == null ? null : principal.getName());
                    request.putInContext("_sg_ssl_transport_peer_certificates", certs);
                    request.putInContext("_sg_ssl_transport_protocol", sslhandler.getEngine().getSession().getProtocol());
                    request.putInContext("_sg_ssl_transport_cipher", sslhandler.getEngine().getSession().getCipherSuite());
                    this.handler.messageReceived(request, transportChannel);
                } else {
                    log.error("No transport client certificates found (SG 12)");
                    transportChannel.sendResponse(new ElasticsearchException("No transport client certificates found (SG 12)"));
                }

            } catch (final Exception e) {
                log.error("Can not verify SSL peer (SG 13) {}", e, e);
                transportChannel.sendResponse(new ElasticsearchException("No transport client certificates found (SG 12)"));
            }
        }

        protected void addAdditionalContextValues(final Request request, final X509Certificate[] certs) throws Exception {
            // no-op
        }
    }
}
