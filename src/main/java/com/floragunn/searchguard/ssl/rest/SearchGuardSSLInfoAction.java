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

import org.elasticsearch.client.Client;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.http.netty.NettyHttpRequest;
import org.elasticsearch.rest.BaseRestHandler;
import org.elasticsearch.rest.BytesRestResponse;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestStatus;
import org.jboss.netty.handler.codec.http.HttpRequest;

public class SearchGuardSSLInfoAction extends BaseRestHandler {

    @Inject
    public SearchGuardSSLInfoAction(final Settings settings, final RestController controller, final Client client) {
        super(settings, controller, client);
        controller.registerHandler(GET, "/_searchguard/sslinfo", this);
    }

    @Override
    protected void handleRequest(final RestRequest request, final RestChannel channel, final Client client) throws Exception {

        BytesRestResponse response = null;
        final XContentBuilder builder = channel.newBuilder();

        try {

            final NettyHttpRequest nettyRequest = (NettyHttpRequest) request;
            final HttpRequest httpRequest = nettyRequest.request();

            builder.startObject();

            builder.field("principal", httpRequest.headers().get("_sg_ssl_principal"));
            builder.field("ssl_protocol", httpRequest.headers().get("_sg_ssl_protocol"));
            builder.field("ssl_cipher", httpRequest.headers().get("_sg_ssl_cipher"));
            builder.endObject();

            response = new BytesRestResponse(RestStatus.OK, builder);
        } catch (final Exception e1) {
            builder.startObject();
            builder.field("error", e1.toString());
            builder.endObject();
            response = new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, builder);
        }

        channel.sendResponse(response);
    }
}
