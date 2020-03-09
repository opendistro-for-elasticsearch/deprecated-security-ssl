package com.amazon.opendistroforelasticsearch.security.ssl.rest;

import com.amazon.opendistroforelasticsearch.security.ssl.OpenDistroSecurityKeyStore;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.elasticsearch.client.Client;
import org.elasticsearch.client.node.NodeClient;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.rest.BaseRestHandler;
import org.elasticsearch.rest.BytesRestResponse;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.threadpool.ThreadPool;

import java.io.IOException;
import static org.elasticsearch.rest.RestRequest.Method.PUT;


/**
 * Rest API action to reload SSL certificates.
 * Can be used to reload SSL certificates that are about to expire without restarting ES node.
 * This API assumes that new certificates are in the same location specified by the security configurations in elasticsearch.yml
 * (https://opendistro.github.io/for-elasticsearch-docs/docs/security-configuration/tls/)
 * To keep sensitive certificate reload secure, this API will only allow hot reload
 * with certificates issued by the same Issuer and Subject DN and SAN with expiry dates after the current one.
 * Currently this action serves PUT request for /_opendistro/_security/ssl/http/reloadcerts or /_opendistro/_security/ssl/transport/reloadcerts endpoint
 */
public class OpenDistroSecuritySSLReloadCertsAction extends BaseRestHandler {

    private final Settings settings;
    private final OpenDistroSecurityKeyStore odsks;

    public OpenDistroSecuritySSLReloadCertsAction(final Settings settings,
                                                  final RestController restController,
                                                  final OpenDistroSecurityKeyStore odsks) {
        super(settings);
        this.settings = settings;
        this.odsks = odsks;
        restController.registerHandler(PUT, "_opendistro/_security/api/ssl/{certType}/reloadcerts/", this);
    }

    /**
     * PUT request to reload SSL Certificates.
     *
     * Sample request:
     * PUT _opendistro/_security/api/ssl/transport/reloadcerts
     * PUT _opendistro/_security/api/ssl/http/reloadcerts
     *
     * NOTE: No request body is required. We will assume new certificates are loaded in the paths specified in your elasticsearch.yml file
     * (https://opendistro.github.io/for-elasticsearch-docs/docs/security-configuration/tls/)
     *
     * Sample response:
     * { "message": "updated http certs" }
     *
     * @param request request to be served
     * @param client client
     * @throws IOException
     */
    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        return new RestChannelConsumer() {

            final String certType = request.param("certType").toLowerCase().trim();

            @Override
            public void accept(RestChannel channel) throws Exception {
                XContentBuilder builder = channel.newBuilder();
                BytesRestResponse response = null;

                try {
                    builder.startObject();
                    if (odsks != null) {
                        switch (certType) {
                            case "http":
                                odsks.initHttpSSLConfig();
                                builder.field("message", "updated http certs");
                                builder.endObject();
                                response = new BytesRestResponse(RestStatus.OK, builder);
                                break;
                            case "transport":
                                odsks.initTransportSSLConfig();
                                builder.field("message", "updated transport certs");
                                builder.endObject();
                                response = new BytesRestResponse(RestStatus.OK, builder);
                                break;
                            default:
                                builder.field("message", "invalid uri path, please use /_opendistro/_security/api/ssl/http/reload or " +
                                        "/_opendistro/_security/api/ssl/transport/reload");
                                builder.endObject();
                                response = new BytesRestResponse(RestStatus.FORBIDDEN, builder);
                                break;
                        }
                    } else {
                        builder.field("message", "keystore is not initialized");
                        builder.endObject();
                        response = new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, builder);
                    }
                } catch (final Exception e1) {
                    builder = channel.newBuilder();
                    builder.startObject();
                    builder.field("error", e1.toString());
                    builder.endObject();
                    response = new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, builder);
                } finally {
                    if (builder != null) {
                        builder.close();
                    }
                }
                channel.sendResponse(response);
            }
        };
    }

    @Override
    public String getName() {
        return "SSL Cert Reload Action";
    }
}