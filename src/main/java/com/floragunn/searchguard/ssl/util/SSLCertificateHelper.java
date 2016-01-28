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

import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

public class SSLCertificateHelper {

    public static X509Certificate[] exportCertificateChain(final KeyStore ks, final String alias) throws KeyStoreException {
        final Enumeration<String> e = ks.aliases();
        final List<String> aliases = new ArrayList<>();

        while (e.hasMoreElements()) {
            aliases.add(e.nextElement());
        }

        String evaluatedAlias = alias;

        if (alias == null && aliases.size() == 1) {
            evaluatedAlias = aliases.get(0);
        }

        if (evaluatedAlias == null) {
            throw new KeyStoreException("null alias, current aliases: " + aliases);
        }

        Certificate[] certs = ks.getCertificateChain(evaluatedAlias);
        if (certs == null) {
            certs = new Certificate[]{ks.getCertificate(evaluatedAlias)};
            if (certs[0] == null) {
                throw new KeyStoreException("no certificate chain or certificate with alias named " + evaluatedAlias);
            }
        }

        List<X509Certificate> x509Certificates = new ArrayList<>();
        for (Certificate c : certs) {
            if (c == null)
                continue;
            if (c instanceof X509Certificate)
                x509Certificates.add((X509Certificate) c);
        }

        return x509Certificates.toArray(new X509Certificate[x509Certificates.size()]);
    }

    public static PrivateKey exportDecryptedKey(final KeyStore ks, final String alias, final char[] password) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
        final Enumeration<String> e = ks.aliases();
        final List<String> aliases = new ArrayList<>();

        while (e.hasMoreElements()) {
            aliases.add(e.nextElement());
        }

        String evaluatedAlias = alias;

        if (alias == null && aliases.size() == 1) {
            evaluatedAlias = aliases.get(0);
        }

        if (evaluatedAlias == null) {
            throw new KeyStoreException("null alias, current aliases: " + aliases);
        }

        final Key key = ks.getKey(evaluatedAlias, password);

        if (key == null) {
            throw new KeyStoreException("no key alias named " + evaluatedAlias);
        }

        if (key instanceof PrivateKey) {
            return (PrivateKey) key;
        }

        return null;
    }
}
