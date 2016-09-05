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

import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;

import org.elasticsearch.common.Strings;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;

public class SSLCertificateHelper {

    private static final ESLogger log = Loggers.getLogger(SSLCertificateHelper.class);
    
    public static X509Certificate[] exportCertificateChain(final KeyStore ks, final String alias) throws KeyStoreException {
        final Enumeration<String> e = ks.aliases();
        final List<String> aliases = new ArrayList<>();

        while (e.hasMoreElements()) {
            aliases.add(e.nextElement());
        }
        
        if(log.isDebugEnabled()) {
            for (String _alias: aliases) {
                log.debug("Alias {}: is a certificate entry?{}/is a key entry?{}", _alias, ks.isCertificateEntry(_alias), ks.isKeyEntry(_alias));
            }
        }
        
        List<Certificate> trustedCerts = new ArrayList<Certificate>();

        if (Strings.isNullOrEmpty(alias)) {
            log.debug("No alias given, will trust all of the certificates in the store");
            
            for (String _alias: aliases) {
                Certificate[] certs = ks.getCertificateChain(_alias);
                if(certs != null && certs.length > 0) {
                    trustedCerts.addAll(Arrays.asList(certs));
                } else {
                    Certificate cert = ks.getCertificate(_alias);
                    if(cert != null) {
                        trustedCerts.add(cert);
                    }
                }
            }
            
        } else {

            Certificate[] certs = ks.getCertificateChain(alias);
            if(certs != null && certs.length > 0) {
                trustedCerts.addAll(Arrays.asList(certs));
            } else {
                Certificate cert = ks.getCertificate(alias);
                if(cert != null) {
                    trustedCerts.add(cert);
                }
            }
        }
        
        List<X509Certificate> x509Certificates = new ArrayList<>(trustedCerts.size());
        for (Certificate c : trustedCerts) {
            if (c != null && c instanceof X509Certificate)
            {
                x509Certificates.add((X509Certificate) c);
            }
        }
        
        
        if(x509Certificates.isEmpty()) {
            throw new KeyStoreException("no certificate chain or certificate with alias: "+ alias);
        }
        
        return trustedCerts.toArray(new X509Certificate[0]);
    }

    public static PrivateKey exportDecryptedKey(final KeyStore ks, final String alias, final char[] password) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
        final Enumeration<String> e = ks.aliases();
        final List<String> aliases = new ArrayList<>();

        while (e.hasMoreElements()) {
            aliases.add(e.nextElement());
        }

        String evaluatedAlias = alias;

        if (alias == null && aliases.size() > 0) {
            evaluatedAlias = aliases.get(0);
        }

        if (evaluatedAlias == null) {
            throw new KeyStoreException("null alias, current aliases: " + aliases);
        }

        final Key key = ks.getKey(evaluatedAlias, (password == null || password.length == 0) ? null:password);

        if (key == null) {
            throw new KeyStoreException("no key alias named " + evaluatedAlias);
        }

        if (key instanceof PrivateKey) {
            return (PrivateKey) key;
        }

        return null;
    }
}
