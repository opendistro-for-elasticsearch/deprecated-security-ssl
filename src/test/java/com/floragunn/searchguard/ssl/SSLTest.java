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

package com.floragunn.searchguard.ssl;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLHandshakeException;

import org.apache.http.NoHttpResponseException;
import org.elasticsearch.action.admin.cluster.node.info.NodesInfoRequest;
import org.elasticsearch.client.transport.NoNodeAvailableException;
import org.elasticsearch.client.transport.TransportClient;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.InetSocketTransportAddress;
import org.elasticsearch.node.Node;
import org.elasticsearch.node.PluginAwareNode;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import com.floragunn.searchguard.ssl.util.SSLConfigConstants;

public class SSLTest extends AbstractUnitTest {

    @Rule
    public final ExpectedException thrown = ExpectedException.none();

    protected boolean allowOpenSSL = false;

    @Test
    public void testHttps() throws Exception {

        enableHTTPClientSSL = true;
        trustHTTPServerCertificate = true;
        sendHTTPClientCertificate = true;

        final Settings settings = Settings.settingsBuilder().put("searchguard.ssl.transport.enabled", false)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_KEYSTORE_ALIAS, "node-0").put("searchguard.ssl.http.enabled", true)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put("searchguard.ssl.http.enforce_clientauth", true)
                .put("searchguard.ssl.http.keystore_filepath", getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.http.truststore_filepath", getAbsoluteFilePathFromClassPath("truststore.jks")).build();

        startES(settings);

        System.out.println(executeSimpleRequest("_searchguard/sslinfo?pretty"));
        Assert.assertTrue(executeSimpleRequest("_searchguard/sslinfo?pretty").contains("TLS"));
        Assert.assertTrue(executeSimpleRequest("_nodes/settings?pretty").contains(clustername));
        Assert.assertFalse(executeSimpleRequest("_nodes/settings?pretty").contains("\"searchguard\""));
        Assert.assertTrue(executeSimpleRequest("_searchguard/sslinfo?pretty").contains("CN=node-0.example.com,OU=SSL,O=Test,L=Test,C=DE"));

    }
    
    @Test
    public void testHttpsOptionalAuth() throws Exception {

        enableHTTPClientSSL = true;
        trustHTTPServerCertificate = true;
        sendHTTPClientCertificate = true;

        final Settings settings = Settings.settingsBuilder().put("searchguard.ssl.transport.enabled", false)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_KEYSTORE_ALIAS, "node-0").put("searchguard.ssl.http.enabled", true)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put("searchguard.ssl.http.keystore_filepath", getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.http.truststore_filepath", getAbsoluteFilePathFromClassPath("truststore.jks")).build();

        startES(settings);

        System.out.println(executeSimpleRequest("_searchguard/sslinfo?pretty"));
        Assert.assertTrue(executeSimpleRequest("_searchguard/sslinfo?pretty").contains("TLS"));
        Assert.assertTrue(executeSimpleRequest("_nodes/settings?pretty").contains(clustername));
        Assert.assertFalse(executeSimpleRequest("_nodes/settings?pretty").contains("\"searchguard\""));
        Assert.assertTrue(executeSimpleRequest("_searchguard/sslinfo?pretty").contains("CN=node-0.example.com,OU=SSL,O=Test,L=Test,C=DE"));
    }

    @Test
    public void testHttpsAndNodeSSL() throws Exception {

        enableHTTPClientSSL = true;
        trustHTTPServerCertificate = true;
        sendHTTPClientCertificate = true;

        final Settings settings = Settings.settingsBuilder().put("searchguard.ssl.transport.enabled", true)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS, "node-0")
                .put(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_KEYSTORE_ALIAS, "node-0")
                .put("searchguard.ssl.transport.keystore_filepath", getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.transport.truststore_filepath", getAbsoluteFilePathFromClassPath("truststore.jks"))
                .put("searchguard.ssl.transport.enforce_hostname_verification", false)
                .put("searchguard.ssl.transport.resolve_hostname", false)

                .put("searchguard.ssl.http.enabled", true).put("searchguard.ssl.http.clientauth_mode", "REQUIRE")
                .put("searchguard.ssl.http.keystore_filepath", getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.http.truststore_filepath", getAbsoluteFilePathFromClassPath("truststore.jks")).build();

        startES(settings);
        System.out.println(executeSimpleRequest("_searchguard/sslinfo?pretty"));
        Assert.assertTrue(executeSimpleRequest("_searchguard/sslinfo?pretty").contains("TLS"));
        Assert.assertTrue(executeSimpleRequest("_searchguard/sslinfo?pretty").length() > 0);
        Assert.assertTrue(executeSimpleRequest("_nodes/settings?pretty").contains(clustername));
        Assert.assertTrue(!executeSimpleRequest("_searchguard/sslinfo?pretty").contains("null"));
        Assert.assertTrue(executeSimpleRequest("_searchguard/sslinfo?pretty").contains("CN=node-0.example.com,OU=SSL,O=Test,L=Test,C=DE"));
    }

    @Test
    public void testHttpPlainFail() throws Exception {
        thrown.expect(NoHttpResponseException.class);

        enableHTTPClientSSL = false;
        trustHTTPServerCertificate = true;
        sendHTTPClientCertificate = false;

        final Settings settings = Settings.settingsBuilder().put("searchguard.ssl.transport.enabled", false)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_KEYSTORE_ALIAS, "node-0").put("searchguard.ssl.http.enabled", true)
                .put("searchguard.ssl.http.clientauth_mode", "OPTIONAL")
                .put("searchguard.ssl.http.keystore_filepath", getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.http.truststore_filepath", getAbsoluteFilePathFromClassPath("truststore.jks")).build();

        startES(settings);
        Assert.assertTrue(executeSimpleRequest("_searchguard/sslinfo?pretty").length() > 0);
        Assert.assertTrue(executeSimpleRequest("_nodes/settings?pretty").contains(clustername));
        Assert.assertTrue(executeSimpleRequest("_searchguard/sslinfo?pretty").contains("CN=node-0.example.com,OU=SSL,O=Test,L=Test,C=DE"));
    }

    @Test
    public void testHttpsNoEnforce() throws Exception {

        enableHTTPClientSSL = true;
        trustHTTPServerCertificate = true;
        sendHTTPClientCertificate = false;

        final Settings settings = Settings.settingsBuilder().put("searchguard.ssl.transport.enabled", false)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_KEYSTORE_ALIAS, "node-0").put("searchguard.ssl.http.enabled", true)
                .put("searchguard.ssl.http.clientauth_mode", "NONE")
                .put("searchguard.ssl.http.keystore_filepath", getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.http.truststore_filepath", getAbsoluteFilePathFromClassPath("truststore.jks")).build();

        startES(settings);
        Assert.assertTrue(executeSimpleRequest("_searchguard/sslinfo?pretty").length() > 0);
        Assert.assertTrue(executeSimpleRequest("_nodes/settings?pretty").contains(clustername));
        Assert.assertFalse(executeSimpleRequest("_searchguard/sslinfo?pretty").contains("CN=node-0.example.com,OU=SSL,O=Test,L=Test,C=DE"));
    }

    @Test
    public void testHttpsV3Fail() throws Exception {
        thrown.expect(SSLHandshakeException.class);

        enableHTTPClientSSL = true;
        trustHTTPServerCertificate = true;
        sendHTTPClientCertificate = false;
        enableHTTPClientSSLv3Only = true;

        final Settings settings = Settings.settingsBuilder().put("searchguard.ssl.transport.enabled", false)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_KEYSTORE_ALIAS, "node-0").put("searchguard.ssl.http.enabled", true)
                .put("searchguard.ssl.http.enforce_clientauth", false)
                .put("searchguard.ssl.http.keystore_filepath", getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.http.truststore_filepath", getAbsoluteFilePathFromClassPath("truststore.jks")).build();

        startES(settings);
        Assert.assertTrue(executeSimpleRequest("_searchguard/sslinfo?pretty").length() > 0);
        Assert.assertTrue(executeSimpleRequest("_nodes/settings?pretty").contains(clustername));
    }

    // transport
    @Test
    public void testTransportClientSSL() throws Exception {

        final Settings settings = Settings.settingsBuilder().put("searchguard.ssl.transport.enabled", true)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS, "node-0")
                .put("searchguard.ssl.transport.keystore_filepath", getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.transport.truststore_filepath", getAbsoluteFilePathFromClassPath("truststore.jks"))
                .put("searchguard.ssl.transport.enforce_hostname_verification", false)
                .put("searchguard.ssl.transport.resolve_hostname", false).build();

        startES(settings);

        final Settings tcSettings = Settings.builder().put("cluster.name", clustername).put("path.home", ".").put(settings).build();

        try (TransportClient tc = TransportClient.builder().settings(tcSettings).addPlugin(SearchGuardSSLPlugin.class).build()) {
            tc.addTransportAddress(new InetSocketTransportAddress(new InetSocketAddress(nodeHost, nodePort)));
            Assert.assertEquals(3, tc.admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().length);
        }
    }

    @Test
    public void testNodeClientSSL() throws Exception {

        final Settings settings = Settings.settingsBuilder().put("searchguard.ssl.transport.enabled", true)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS, "node-0")
                .put("searchguard.ssl.transport.keystore_filepath", getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.transport.truststore_filepath", getAbsoluteFilePathFromClassPath("truststore.jks"))
                .put("searchguard.ssl.transport.enforce_hostname_verification", false)
                .put("searchguard.ssl.transport.resolve_hostname", false).build();

        startES(settings);

        final Settings tcSettings = Settings.builder().put("cluster.name", clustername).put("node.client", true).put("path.home", ".")
                .put(settings)// -----
                .build();

        try (Node node = new PluginAwareNode(tcSettings, SearchGuardSSLPlugin.class).start()) {
            Thread.sleep(3000);
            Assert.assertEquals(4, node.client().admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().length);
        }
    }

    @Test
    public void testTransportClientSSLFail() throws Exception {
        thrown.expect(NoNodeAvailableException.class);

        final Settings settings = Settings.settingsBuilder().put("searchguard.ssl.transport.enabled", true)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS, "node-0")
                .put("searchguard.ssl.transport.keystore_filepath", getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.transport.truststore_filepath", getAbsoluteFilePathFromClassPath("truststore.jks"))
                .put("searchguard.ssl.transport.enforce_hostname_verification", false)
                .put("searchguard.ssl.transport.resolve_hostname", false).build();

        startES(settings);

        final Settings tcSettings = Settings.builder().put("cluster.name", clustername)
                .put("path.home", getAbsoluteFilePathFromClassPath("node-0-keystore.jks").getParent())
                .put("searchguard.ssl.transport.keystore_filepath", getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.transport.truststore_filepath", getAbsoluteFilePathFromClassPath("truststore_fail.jks"))
                .put("searchguard.ssl.transport.enforce_hostname_verification", false)
                .put("searchguard.ssl.transport.resolve_hostname", false).build();

        try (TransportClient tc = TransportClient.builder().settings(tcSettings).addPlugin(SearchGuardSSLPlugin.class).build()) {
            tc.addTransportAddress(new InetSocketTransportAddress(new InetSocketAddress(nodeHost, nodePort)));
            Assert.assertEquals(3, tc.admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().length);
        }
    }

    @Test
    public void testAvailCiphers() throws Exception {
        final SSLContext serverContext = SSLContext.getInstance("TLS");
        serverContext.init(null, null, null);
        final SSLEngine engine = serverContext.createSSLEngine();
        final List<String> jdkSupportedCiphers = new ArrayList<>(Arrays.asList(engine.getSupportedCipherSuites()));
        jdkSupportedCiphers.retainAll(SSLConfigConstants.SECURE_SSL_CIPHERS);
        engine.setEnabledCipherSuites(jdkSupportedCiphers.toArray(new String[0]));

        final List<String> jdkEnabledCiphers = Arrays.asList(engine.getEnabledCipherSuites());
        // example
        // TLS_RSA_WITH_AES_128_CBC_SHA256, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        // TLS_RSA_WITH_AES_128_CBC_SHA, TLS_DHE_RSA_WITH_AES_128_CBC_SHA
        System.out.println("JDK enabled ciphers: " + jdkEnabledCiphers);
        Assert.assertTrue(jdkEnabledCiphers.size() > 0);
    }
    
    @Test
    public void testUnmodifieableCipherProtocolConfig() throws Exception {
        SSLConfigConstants.getSecureSSLProtocols()[0] = "bogus";
        Assert.assertEquals("TLSv1.2", SSLConfigConstants.getSecureSSLProtocols()[0]);
        
        try {
            SSLConfigConstants.SECURE_SSL_CIPHERS.set(0, "bogus");
            Assert.fail();
        } catch (UnsupportedOperationException e) {
            //expected
        }
    }
    
}
