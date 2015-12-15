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

import com.floragunn.searchguard.ssl.util.ConfigConstants;

public class SSLTest extends AbstractUnitTest {

    @Rule
    public final ExpectedException thrown = ExpectedException.none();

    @Test
    public void testHttps() throws Exception {

        enableHTTPClientSSL = true;
        trustHTTPServerCertificate = true;
        sendHTTPClientCertificate = true;

        final Settings settings = Settings.settingsBuilder().put("searchguard.ssl.transport.node.enabled", false)
                .put(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_HTTP_KEYSTORE_ALIAS, "node-0")
                .put("searchguard.ssl.transport.http.enabled", true).put("searchguard.ssl.transport.http.enforce_clientauth", true)
                .put("searchguard.ssl.transport.http.keystore_filepath", getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.transport.http.truststore_filepath", getAbsoluteFilePathFromClassPath("truststore.jks")).build();

        startES(settings);

        Assert.assertTrue(executeSimpleRequest("_searchguard/sslinfo?pretty").contains("TLS"));
        Assert.assertTrue(executeSimpleRequest("_nodes/settings?pretty").contains(clustername));
        Assert.assertFalse(executeSimpleRequest("_nodes/settings?pretty").contains("\"searchguard\""));
    }

    @Test
    public void testHttpsAndNodeSSL() throws Exception {

        enableHTTPClientSSL = true;
        trustHTTPServerCertificate = true;
        sendHTTPClientCertificate = true;

        final Settings settings = Settings.settingsBuilder().put("searchguard.ssl.transport.node.enabled", true)
                .put(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_NODE_KEYSTORE_ALIAS, "node-0")
                .put(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_HTTP_KEYSTORE_ALIAS, "node-0")
                .put("searchguard.ssl.transport.node.keystore_filepath", getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.transport.node.truststore_filepath", getAbsoluteFilePathFromClassPath("truststore.jks"))
                .put("searchguard.ssl.transport.node.enforce_hostname_verification", false)
                .put("searchguard.ssl.transport.node.resolve_hostname", false)

                .put("searchguard.ssl.transport.http.enabled", true).put("searchguard.ssl.transport.http.enforce_clientauth", true)
                .put("searchguard.ssl.transport.http.keystore_filepath", getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.transport.http.truststore_filepath", getAbsoluteFilePathFromClassPath("truststore.jks")).build();

        startES(settings);
        System.out.println(executeSimpleRequest("_searchguard/sslinfo?pretty"));
        Assert.assertTrue(executeSimpleRequest("_searchguard/sslinfo?pretty").length() > 0);
        Assert.assertTrue(executeSimpleRequest("_nodes/settings?pretty").contains(clustername));
    }

    @Test
    public void testHttpPlainFail() throws Exception {
        thrown.expect(NoHttpResponseException.class);

        enableHTTPClientSSL = false;
        trustHTTPServerCertificate = true;
        sendHTTPClientCertificate = false;

        final Settings settings = Settings.settingsBuilder().put("searchguard.ssl.transport.node.enabled", false)
                .put(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_HTTP_KEYSTORE_ALIAS, "node-0")
                .put("searchguard.ssl.transport.http.enabled", true).put("searchguard.ssl.transport.http.enforce_clientauth", false)
                .put("searchguard.ssl.transport.http.keystore_filepath", getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.transport.http.truststore_filepath", getAbsoluteFilePathFromClassPath("truststore.jks")).build();

        startES(settings);
        Assert.assertTrue(executeSimpleRequest("_searchguard/sslinfo?pretty").length() > 0);
        Assert.assertTrue(executeSimpleRequest("_nodes/settings?pretty").contains(clustername));
    }

    @Test
    public void testHttpsNoEnforce() throws Exception {

        enableHTTPClientSSL = true;
        trustHTTPServerCertificate = true;
        sendHTTPClientCertificate = false;

        final Settings settings = Settings.settingsBuilder().put("searchguard.ssl.transport.node.enabled", false)
                .put(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_HTTP_KEYSTORE_ALIAS, "node-0")
                .put("searchguard.ssl.transport.http.enabled", true).put("searchguard.ssl.transport.http.enforce_clientauth", false)
                .put("searchguard.ssl.transport.http.keystore_filepath", getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.transport.http.truststore_filepath", getAbsoluteFilePathFromClassPath("truststore.jks")).build();

        startES(settings);
        Assert.assertTrue(executeSimpleRequest("_searchguard/sslinfo?pretty").length() > 0);
        Assert.assertTrue(executeSimpleRequest("_nodes/settings?pretty").contains(clustername));
    }

    @Test
    public void testHttpsV3Fail() throws Exception {
        thrown.expect(SSLHandshakeException.class);

        enableHTTPClientSSL = true;
        trustHTTPServerCertificate = true;
        sendHTTPClientCertificate = false;
        enableHTTPClientSSLv3Only = true;

        final Settings settings = Settings.settingsBuilder().put("searchguard.ssl.transport.node.enabled", false)
                .put(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_HTTP_KEYSTORE_ALIAS, "node-0")
                .put("searchguard.ssl.transport.http.enabled", true).put("searchguard.ssl.transport.http.enforce_clientauth", false)
                .put("searchguard.ssl.transport.http.keystore_filepath", getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.transport.http.truststore_filepath", getAbsoluteFilePathFromClassPath("truststore.jks")).build();

        startES(settings);
        Assert.assertTrue(executeSimpleRequest("_searchguard/sslinfo?pretty").length() > 0);
        Assert.assertTrue(executeSimpleRequest("_nodes/settings?pretty").contains(clustername));
    }

    // transport
    @Test
    public void testTransportClientSSL() throws Exception {

        final Settings settings = Settings.settingsBuilder().put("searchguard.ssl.transport.node.enabled", true)
                .put(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_NODE_KEYSTORE_ALIAS, "node-0")
                .put("searchguard.ssl.transport.node.keystore_filepath", getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.transport.node.truststore_filepath", getAbsoluteFilePathFromClassPath("truststore.jks"))
                .put("searchguard.ssl.transport.node.enforce_hostname_verification", false)
                .put("searchguard.ssl.transport.node.resolve_hostname", false).build();

        startES(settings);

        final Settings tcSettings = Settings.builder().put("cluster.name", clustername).put("path.home", ".").put(settings).build();

        try (TransportClient tc = TransportClient.builder().settings(tcSettings).addPlugin(SearchGuardSSLPlugin.class).build()) {
            tc.addTransportAddress(new InetSocketTransportAddress(new InetSocketAddress(nodeHost, nodePort)));

            Assert.assertEquals(3, tc.admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().length);
        }
    }

    @Test
    public void testNodeClientSSL() throws Exception {

        final Settings settings = Settings.settingsBuilder().put("searchguard.ssl.transport.node.enabled", true)
                .put(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_NODE_KEYSTORE_ALIAS, "node-0")
                .put("searchguard.ssl.transport.node.keystore_filepath", getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.transport.node.truststore_filepath", getAbsoluteFilePathFromClassPath("truststore.jks"))
                .put("searchguard.ssl.transport.node.enforce_hostname_verification", false)
                .put("searchguard.ssl.transport.node.resolve_hostname", false).build();

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

        final Settings settings = Settings.settingsBuilder().put("searchguard.ssl.transport.node.enabled", true)
                .put(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_NODE_KEYSTORE_ALIAS, "node-0")
                .put("searchguard.ssl.transport.node.keystore_filepath", getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.transport.node.truststore_filepath", getAbsoluteFilePathFromClassPath("truststore.jks"))
                .put("searchguard.ssl.transport.node.enforce_hostname_verification", false)
                .put("searchguard.ssl.transport.node.resolve_hostname", false).build();

        startES(settings);

        final Settings tcSettings = Settings.builder().put("cluster.name", clustername)
                .put("path.home", getAbsoluteFilePathFromClassPath("node-0-keystore.jks").getParent())
                .put("searchguard.ssl.transport.node.keystore_filepath", getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.transport.node.truststore_filepath", getAbsoluteFilePathFromClassPath("truststore_fail.jks"))
                .put("searchguard.ssl.transport.node.enforce_hostname_verification", false)
                .put("searchguard.ssl.transport.node.resolve_hostname", false).build();

        try (TransportClient tc = TransportClient.builder().settings(tcSettings).addPlugin(SearchGuardSSLPlugin.class).build()) {
            tc.addTransportAddress(new InetSocketTransportAddress(new InetSocketAddress(nodeHost, nodePort)));
            Assert.assertEquals(3, tc.admin().cluster().nodesInfo(new NodesInfoRequest()).actionGet().getNodes().length);
        }
    }
}
