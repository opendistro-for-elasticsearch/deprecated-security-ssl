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

import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;

public class OpenSSLTest extends SSLTest {

    @Before
    public void setup() {
        allowOpenSSL = true;
    }
    
    @Test
    public void testHttps() throws Exception {
        Assume.assumeTrue(OpenSsl.isAvailable());
        super.testHttps();
    }

    @Test
    public void testHttpsAndNodeSSL() throws Exception {
        Assume.assumeTrue(OpenSsl.isAvailable());
        super.testHttpsAndNodeSSL();
    }

    @Test
    public void testHttpPlainFail() throws Exception {
        Assume.assumeTrue(OpenSsl.isAvailable());
        super.testHttpPlainFail();
    }

    @Test
    public void testHttpsNoEnforce() throws Exception {
        Assume.assumeTrue(OpenSsl.isAvailable());
        super.testHttpsNoEnforce();
    }

    @Test
    public void testHttpsV3Fail() throws Exception {
        Assume.assumeTrue(OpenSsl.isAvailable());
        super.testHttpsV3Fail();
    }

    @Test
    public void testTransportClientSSL() throws Exception {
        Assume.assumeTrue(OpenSsl.isAvailable());
        super.testTransportClientSSL();
    }

    @Test
    public void testNodeClientSSL() throws Exception {
        Assume.assumeTrue(OpenSsl.isAvailable());
        super.testNodeClientSSL();
    }

    @Test
    public void testTransportClientSSLFail() throws Exception {
        Assume.assumeTrue(OpenSsl.isAvailable());
        super.testTransportClientSSLFail();
    }
}
