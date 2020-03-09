package com.amazon.opendistroforelasticsearch.security.ssl;

import com.amazon.opendistroforelasticsearch.security.ssl.helper.FileHelper;
import com.amazon.opendistroforelasticsearch.security.ssl.util.SSLConfigConstants;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import net.minidev.json.JSONObject;
import org.elasticsearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Test;

import java.util.List;
import java.util.Map;

public class OpenDistroSecuritySSLCertsInfoActionTests extends AbstractUnitTest {
    private final String ENDPOINT = "_opendistro/_security/api/ssl/certs";

    private final List<Map<String, String>> NODE_CERT_DETAILS = ImmutableList.of(
            ImmutableMap.of(
                    "issuer_dn", "CN=Example Com Inc. Signing CA,OU=Example Com Inc. Signing CA,O=Example Com Inc.,DC=example,DC=com",
                    "subject_dn", "CN=node-0.example.com,OU=SSL,O=Test,L=Test,C=DE",
                    "san", "[[2, node-0.example.com], [2, localhost], [7, 127.0.0.1], [8, 1.2.3.4.5.5]]",
                    "not_before","2018-05-05T14:37:09Z",
                    "not_after","2028-05-02T14:37:09Z"
            ));

    @Test
    public void testCertInfo() throws Exception {
        final Settings settings = initTestCluster();
        startES(settings);

        enableHTTPClientSSL = true;
        trustHTTPServerCertificate = true;
        sendHTTPClientCertificate = true;
        keystore = "kirk-keystore.jks";

        String resp = executeSimpleRequest(ENDPOINT);

        JSONObject expectedJsonResponse = new JSONObject();
        expectedJsonResponse.put("http_certificates_list", NODE_CERT_DETAILS);
        expectedJsonResponse.put("transport_certificates_list", NODE_CERT_DETAILS);

        Assert.assertEquals(expectedJsonResponse.toString(), resp);
    }

    private Settings initTestCluster() throws Exception {
        return  Settings.builder()
                .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_ENABLED, true)
                .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_PEMCERT_FILEPATH, FileHelper.getAbsoluteFilePathFromClassPath("ssl/node-0.crt.pem"))
                .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_PEMKEY_FILEPATH, FileHelper. getAbsoluteFilePathFromClassPath("ssl/node-0.key.pem"))
                .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_PEMTRUSTEDCAS_FILEPATH, FileHelper. getAbsoluteFilePathFromClassPath("ssl/root-ca.pem"))
                .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION, false)
                .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION_RESOLVE_HOST_NAME, false)
                .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_ENABLED, true)
                .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_PEMCERT_FILEPATH, FileHelper.getAbsoluteFilePathFromClassPath("ssl/node-0.crt.pem"))
                .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_PEMKEY_FILEPATH, FileHelper.getAbsoluteFilePathFromClassPath("ssl/node-0.key.pem"))
                .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_PEMTRUSTEDCAS_FILEPATH, FileHelper.getAbsoluteFilePathFromClassPath("ssl/root-ca.pem"))
                .put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_CERT_RELOAD_ENABLED, true)
                .build();
    }

}
