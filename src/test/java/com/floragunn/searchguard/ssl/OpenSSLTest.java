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

import io.netty.handler.ssl.OpenSsl;

import java.util.HashSet;
import java.util.Set;

import org.elasticsearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;

import com.floragunn.searchguard.ssl.util.SSLConfigConstants;

public class OpenSSLTest extends SSLTest {

    @Before
    public void setup() {
        allowOpenSSL = true;
    }

    @Test
    public void testEnsureOpenSSLAvailability() {
        Assert.assertTrue("OpenSSL not available: "+String.valueOf(OpenSsl.unavailabilityCause()), OpenSsl.isAvailable());
                
        /*String allowOpenSSLProperty = System.getenv("SG_ALLOW_OPENSSL");
        System.out.println("SG_ALLOW_OPENSSL "+allowOpenSSLProperty);
        if(Boolean.parseBoolean(allowOpenSSLProperty)) {
            System.out.println("OpenSSL must be available");
            Assert.assertTrue(String.valueOf(OpenSsl.unavailabilityCause()), OpenSsl.isAvailable());
        } else {
            System.out.println("OpenSSL can be available");
        }*/
    }

    @Override
    @Test
    public void testHttps() throws Exception {
        Assume.assumeTrue(OpenSsl.isAvailable());
        super.testHttps();
    }

    @Override
    @Test
    public void testHttpsAndNodeSSL() throws Exception {
        Assume.assumeTrue(OpenSsl.isAvailable());
        super.testHttpsAndNodeSSL();
    }

    @Override
    @Test
    public void testHttpPlainFail() throws Exception {
        Assume.assumeTrue(OpenSsl.isAvailable());
        super.testHttpPlainFail();
    }

    @Override
    @Test
    public void testHttpsNoEnforce() throws Exception {
        Assume.assumeTrue(OpenSsl.isAvailable());
        super.testHttpsNoEnforce();
    }

    @Override
    @Test
    public void testHttpsV3Fail() throws Exception {
        Assume.assumeTrue(OpenSsl.isAvailable());
        super.testHttpsV3Fail();
    }

    @Override
    @Test(timeout=40000)
    public void testTransportClientSSL() throws Exception {
        Assume.assumeTrue(OpenSsl.isAvailable());
        super.testTransportClientSSL();
    }

    @Override
    @Test(timeout=40000)
    public void testNodeClientSSL() throws Exception {
        Assume.assumeTrue(OpenSsl.isAvailable());
        super.testNodeClientSSL();
    }

    @Override
    @Test(timeout=40000)
    public void testTransportClientSSLFail() throws Exception {
        Assume.assumeTrue(OpenSsl.isAvailable());
        super.testTransportClientSSLFail();
    }
    
    @Override
    @Test
    public void testHttpsOptionalAuth() throws Exception {
        Assume.assumeTrue(OpenSsl.isAvailable());
        super.testHttpsOptionalAuth();
    }
    
    @Test
    public void testAvailCiphersOpenSSL() throws Exception {
        Assume.assumeTrue(OpenSsl.isAvailable());

        // Set<String> openSSLAvailCiphers = new
        // HashSet<>(OpenSsl.availableCipherSuites());
        // System.out.println("OpenSSL available ciphers: "+openSSLAvailCiphers);
        // ECDHE-RSA-AES256-SHA, ECDH-ECDSA-AES256-SHA, DH-DSS-DES-CBC-SHA,
        // ADH-AES256-SHA256, ADH-CAMELLIA128-SHA

        final Set<String> openSSLSecureCiphers = new HashSet<>();
        for (final String secure : SSLConfigConstants.getSecureSSLCiphers(Settings.EMPTY, false)) {
            if (OpenSsl.isCipherSuiteAvailable(secure)) {
                openSSLSecureCiphers.add(secure);
            }
        }

        System.out.println("OpenSSL secure ciphers: " + openSSLSecureCiphers);
        Assert.assertTrue(openSSLSecureCiphers.size() > 0);
    }
    
    @Test
    public void testHttpsEnforceFail() throws Exception {
        Assume.assumeTrue(OpenSsl.isAvailable());
        super.testHttpsEnforceFail();
    }

    @Override
    public void testCipherAndProtocols() throws Exception {
        Assume.assumeTrue(OpenSsl.isAvailable());
        super.testCipherAndProtocols();
    }

    @Override
    public void testHttpsAndNodeSSLFailedCipher() throws Exception {
        Assume.assumeTrue(OpenSsl.isAvailable());
        super.testHttpsAndNodeSSLFailedCipher();
    }
    
    
}
