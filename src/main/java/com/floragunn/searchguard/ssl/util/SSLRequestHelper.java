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

package com.floragunn.searchguard.ssl.util;

import io.netty.handler.ssl.SslHandler;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Map.Entry;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.security.auth.x500.X500Principal;

import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.http.netty4.Netty4HttpRequest;
import org.elasticsearch.rest.RestRequest;

import com.floragunn.searchguard.ssl.transport.PrincipalExtractor;
import com.floragunn.searchguard.ssl.transport.PrincipalExtractor.Type;

public class SSLRequestHelper {

    public static class SSLInfo {
        private final X509Certificate[] x509Certs;
        private final String principal;
        private final String protocol;
        private final String cipher;

        public SSLInfo(final X509Certificate[] x509Certs, final String principal, final String protocol, final String cipher) {
            super();
            this.x509Certs = x509Certs;
            this.principal = principal;
            this.protocol = protocol;
            this.cipher = cipher;
        }

        public X509Certificate[] getX509Certs() {
            return x509Certs == null ? null : x509Certs.clone();
        }

        public String getPrincipal() {
            return principal;
        }

        public String getProtocol() {
            return protocol;
        }

        public String getCipher() {
            return cipher;
        }

        @Override
        public String toString() {
            return "SSLInfo [x509Certs=" + Arrays.toString(x509Certs) + ", principal=" + principal + ", protocol=" + protocol + ", cipher="
                    + cipher + "]";
        }

    }

    public static SSLInfo getSSLInfo(final RestRequest request, PrincipalExtractor principalExtractor) throws SSLPeerUnverifiedException {

        if(request == null || !(request instanceof Netty4HttpRequest)) {
            return null;
        }
        
        final Netty4HttpRequest nettyHttpRequest = (Netty4HttpRequest) request;
        final SslHandler sslhandler = (SslHandler) nettyHttpRequest.getChannel().pipeline().get("ssl_http");
        
        if(sslhandler == null) {
            return null;
        }
        
        final SSLEngine engine = sslhandler.engine();
        final SSLSession session = engine.getSession();

        X509Certificate[] x509Certs = null;
        final String protocol = session.getProtocol();
        final String cipher = session.getCipherSuite();
        String principal = null;

        if (engine.getNeedClientAuth() || engine.getWantClientAuth()) {

            try {
                final Certificate[] certs = session.getPeerCertificates();

                if (certs != null && certs.length > 0 && certs[0] instanceof X509Certificate) {
                    x509Certs = Arrays.copyOf(certs, certs.length, X509Certificate[].class);
                    principal = principalExtractor == null?null: principalExtractor.extractPrincipal(x509Certs[0], Type.HTTP);
                } else if (engine.getNeedClientAuth()) {
                    final ElasticsearchException ex = new ElasticsearchException("No client certificates found but such are needed (SG 9).");
                    throw ex;
                }

            } catch (final SSLPeerUnverifiedException e) {
                if (engine.getNeedClientAuth()) {
                    throw e;
                }
            }
        }

        return new SSLInfo(x509Certs, principal, protocol, cipher);
    }
    
    public static boolean containsBadHeader(final ThreadContext context, String prefix) {
        if (context != null) {
            for (final Entry<String, String> header : context.getHeaders().entrySet()) {
                if (header != null && header.getKey() != null && header.getKey().trim().toLowerCase().startsWith(prefix)) {
                    System.out.println(header.getKey()+"="+header.getValue());
                    return true;
                }
            }
        }
        
        return false;
    }
}
