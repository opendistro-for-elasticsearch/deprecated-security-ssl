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

import java.security.cert.X509Certificate;

import org.elasticsearch.client.Client;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.rest.BaseRestHandler;
import org.elasticsearch.rest.BytesRestResponse;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestStatus;

import com.floragunn.searchguard.ssl.SearchGuardKeyStore;

public class SearchGuardSSLInfoAction extends BaseRestHandler {

    private final SearchGuardKeyStore sgks;

    @Inject
    public SearchGuardSSLInfoAction(final Settings settings, final RestController controller, final Client client,
            final SearchGuardKeyStore sgks) {
        super(settings, controller, client);
        this.sgks = sgks;
        controller.registerHandler(GET, "/_searchguard/sslinfo", this);
    }

    @Override
    protected void handleRequest(final RestRequest request, final RestChannel channel, final Client client) throws Exception {

        BytesRestResponse response = null;
        XContentBuilder builder = channel.newBuilder();

        try {

            final X509Certificate[] certs = request.getFromContext("_sg_ssl_peer_certificates");
            builder.startObject();

            builder.field("principal", (String) request.getFromContext("_sg_ssl_principal"));
            builder.field("peer_certificates", certs != null && certs.length > 0 ? certs.length + "" : "0");
            builder.field("ssl_protocol", (String) request.getFromContext("_sg_ssl_protocol"));
            builder.field("ssl_cipher", (String) request.getFromContext("_sg_ssl_cipher"));
            builder.field("ssl_openssl_available", OpenSsl.isAvailable());
            builder.field("ssl_openssl_version", OpenSsl.version());
            builder.field("ssl_openssl_version_string", OpenSsl.versionString());
            Throwable openSslUnavailCause = OpenSsl.unavailabilityCause();
            builder.field("ssl_openssl_non_available_cause", openSslUnavailCause==null?"":openSslUnavailCause.toString());
            builder.field("ssl_provider_http", sgks.sslHTTPProvider);
            builder.field("ssl_provider_transport_server", sgks.sslTransportServerProvider);
            builder.field("ssl_provider_transport_client", sgks.sslTransportClientProvider);
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
}
