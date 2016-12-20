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

package com.floragunn.searchguard.ssl.rest;

import static org.elasticsearch.rest.RestRequest.Method.GET;
import io.netty.handler.ssl.OpenSsl;

import java.io.IOException;
import java.security.cert.X509Certificate;

import org.elasticsearch.client.node.NodeClient;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.rest.BaseRestHandler;
import org.elasticsearch.rest.BytesRestResponse;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.threadpool.ThreadPool;

import com.floragunn.searchguard.ssl.SearchGuardKeyStore;
import com.floragunn.searchguard.ssl.transport.PrincipalExtractor;
import com.floragunn.searchguard.ssl.util.SSLRequestHelper;
import com.floragunn.searchguard.ssl.util.SSLRequestHelper.SSLInfo;

public class SearchGuardSSLInfoAction extends BaseRestHandler {

    private final SearchGuardKeyStore sgks;
    final PrincipalExtractor principalExtractor;

    @Inject
    public SearchGuardSSLInfoAction(final Settings settings, final RestController controller,
            ThreadPool threadPool, final SearchGuardKeyStore sgks, final PrincipalExtractor principalExtractor) {
        super(settings);
        this.sgks = sgks;
        this.principalExtractor = principalExtractor;
        controller.registerHandler(GET, "/_searchguard/sslinfo", this);
    }
    
    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        return new RestChannelConsumer() {

            @Override
            public void accept(RestChannel channel) throws Exception {
                XContentBuilder builder = channel.newBuilder();
                BytesRestResponse response = null;
                
                try {
                    
                    SSLInfo sslInfo = SSLRequestHelper.getSSLInfo(request, principalExtractor);
                    X509Certificate[] certs = sslInfo.getX509Certs();

                    builder.startObject();

                    builder.field("principal", sslInfo.getPrincipal());
                    builder.field("peer_certificates", certs != null && certs.length > 0 ? certs.length + "" : "0");
                    builder.field("ssl_protocol", sslInfo.getProtocol());
                    builder.field("ssl_cipher", sslInfo.getCipher());
                    builder.field("ssl_openssl_available", OpenSsl.isAvailable());
                    builder.field("ssl_openssl_version", OpenSsl.version());
                    builder.field("ssl_openssl_version_string", OpenSsl.versionString());
                    Throwable openSslUnavailCause = OpenSsl.unavailabilityCause();
                    builder.field("ssl_openssl_non_available_cause", openSslUnavailCause==null?"":openSslUnavailCause.toString());
                    builder.field("ssl_openssl_supports_key_manager_factory", OpenSsl.supportsKeyManagerFactory());
                    builder.field("ssl_provider_http", sgks.getHTTPProviderName());
                    builder.field("ssl_provider_transport_server", sgks.getTransportServerProviderName());
                    builder.field("ssl_provider_transport_client", sgks.getTransportClientProviderName());
                    builder.endObject();

                    response = new BytesRestResponse(RestStatus.OK, builder);
                } catch (final Exception e1) {
                    logger.error("Error handle request "+e1, e1);
                    builder = channel.newBuilder();
                    builder.startObject();
                    builder.field("error", e1.toString());
                    builder.endObject();
                    response = new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, builder);
                }
                
                channel.sendResponse(response);
            }
        };
    }
}
