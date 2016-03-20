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

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public final class SSLConfigConstants {

    public static final String SEARCHGUARD_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE = "searchguard.ssl.http.enable_openssl_if_available";
    public static final String SEARCHGUARD_SSL_HTTP_ENABLED = "searchguard.ssl.http.enabled";
    public static final boolean SEARCHGUARD_SSL_HTTP_ENABLED_DEFAULT = false;
    @Deprecated
    public static final String SEARCHGUARD_SSL_HTTP_ENFORCE_CLIENTAUTH = "searchguard.ssl.http.enforce_clientauth";
    public static final String SEARCHGUARD_SSL_HTTP_CLIENTAUTH_MODE = "searchguard.ssl.http.clientauth_mode";
    public static final String SEARCHGUARD_SSL_HTTP_KEYSTORE_ALIAS = "searchguard.ssl.http.keystore_alias";
    public static final String SEARCHGUARD_SSL_HTTP_KEYSTORE_FILEPATH = "searchguard.ssl.http.keystore_filepath";
    public static final String SEARCHGUARD_SSL_HTTP_KEYSTORE_PASSWORD = "searchguard.ssl.http.keystore_password";
    public static final String SEARCHGUARD_SSL_HTTP_KEYSTORE_TYPE = "searchguard.ssl.http.keystore_type";
    public static final String SEARCHGUARD_SSL_HTTP_TRUSTSTORE_ALIAS = "searchguard.ssl.http.truststore_alias";
    public static final String SEARCHGUARD_SSL_HTTP_TRUSTSTORE_FILEPATH = "searchguard.ssl.http.truststore_filepath";
    public static final String SEARCHGUARD_SSL_HTTP_TRUSTSTORE_PASSWORD = "searchguard.ssl.http.truststore_password";
    public static final String SEARCHGUARD_SSL_HTTP_TRUSTSTORE_TYPE = "searchguard.ssl.http.truststore_type";
    public static final String SEARCHGUARD_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE = "searchguard.ssl.transport.enable_openssl_if_available";
    public static final String SEARCHGUARD_SSL_TRANSPORT_ENABLED = "searchguard.ssl.transport.enabled";
    public static final boolean SEARCHGUARD_SSL_TRANSPORT_ENABLED_DEFAULT = true;
    public static final String SEARCHGUARD_SSL_TRANSPORT_ENCFORCE_HOSTNAME_VERIFICATION = "searchguard.ssl.transport.enforce_hostname_verification";
    public static final String SEARCHGUARD_SSL_TRANSPORT_ENCFORCE_HOSTNAME_VERIFICATION_RESOLVE_HOST_NAME = "searchguard.ssl.transport.resolve_hostname";
    public static final String SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS = "searchguard.ssl.transport.keystore_alias";
    public static final String SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_FILEPATH = "searchguard.ssl.transport.keystore_filepath";
    public static final String SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_PASSWORD = "searchguard.ssl.transport.keystore_password";
    public static final String SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_TYPE = "searchguard.ssl.transport.keystore_type";
    public static final String SEARCHGUARD_SSL_TRANSPORT_TRUSTSTORE_ALIAS = "searchguard.ssl.transport.truststore_alias";
    public static final String SEARCHGUARD_SSL_TRANSPORT_TRUSTSTORE_FILEPATH = "searchguard.ssl.transport.truststore_filepath";
    public static final String SEARCHGUARD_SSL_TRANSPORT_TRUSTSTORE_PASSWORD = "searchguard.ssl.transport.truststore_password";
    public static final String SEARCHGUARD_SSL_TRANSPORT_TRUSTSTORE_TYPE = "searchguard.ssl.transport.truststore_type";

    private static final String[] _SECURE_SSL_PROTOCOLS = {"TLSv1.2", "TLSv1.1"};
    
    public static final String[] getSecureSSLProtocols()
    {
        return _SECURE_SSL_PROTOCOLS.clone();
    }
    
    // @formatter:off
    private static final String[] _SECURE_SSL_CIPHERS = 
        {
        //TLS_<key exchange and authentication algorithms>_WITH_<bulk cipher and message authentication algorithms>
        
        //Example (including unsafe ones)
        //Protocol: TLS, SSL
        //Key Exchange    RSA, Diffie-Hellman, ECDH, SRP, PSK
        //Authentication  RSA, DSA, ECDSA
        //Bulk Ciphers    RC4, 3DES, AES
        //Message Authentication  HMAC-SHA256, HMAC-SHA1, HMAC-MD5
        

        //thats what chrome 48 supports
        //(c0,2b)ECDHE-ECDSA-AES128-GCM-SHA256128 BitKey exchange: ECDH, encryption: AES, MAC: SHA256.
        //(c0,2f)ECDHE-RSA-AES128-GCM-SHA256128 BitKey exchange: ECDH, encryption: AES, MAC: SHA256.
        //(00,9e)DHE-RSA-AES128-GCM-SHA256128 BitKey exchange: DH, encryption: AES, MAC: SHA256.
        //(cc,14)ECDHE-ECDSA-CHACHA20-POLY1305-SHA256128 BitKey exchange: ECDH, encryption: ChaCha20 Poly1305, MAC: SHA256.
        //(cc,13)ECDHE-RSA-CHACHA20-POLY1305-SHA256128 BitKey exchange: ECDH, encryption: ChaCha20 Poly1305, MAC: SHA256.
        //(c0,0a)ECDHE-ECDSA-AES256-SHA256 BitKey exchange: ECDH, encryption: AES, MAC: SHA1.
        //(c0,14)ECDHE-RSA-AES256-SHA256 BitKey exchange: ECDH, encryption: AES, MAC: SHA1.
        //(00,39)DHE-RSA-AES256-SHA256 BitKey exchange: DH, encryption: AES, MAC: SHA1.
        //(c0,09)ECDHE-ECDSA-AES128-SHA128 BitKey exchange: ECDH, encryption: AES, MAC: SHA1.
        //(c0,13)ECDHE-RSA-AES128-SHA128 BitKey exchange: ECDH, encryption: AES, MAC: SHA1.
        //(00,33)DHE-RSA-AES128-SHA128 BitKey exchange: DH, encryption: AES, MAC: SHA1.
        //(00,9c)RSA-AES128-GCM-SHA256128 BitKey exchange: RSA, encryption: AES, MAC: SHA256.
        //(00,35)RSA-AES256-SHA256 BitKey exchange: RSA, encryption: AES, MAC: SHA1.
        //(00,2f)RSA-AES128-SHA128 BitKey exchange: RSA, encryption: AES, MAC: SHA1.
        //(00,0a)RSA-3DES-EDE-SHA168 BitKey exchange: RSA, encryption: 3DES, MAC: SHA1.
        
        
        //Mozilla modern browsers
        //https://wiki.mozilla.org/Security/Server_Side_TLS
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
        "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
        "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
        "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
        "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
        "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
        "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
        "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
        "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"
        
        //some others
        //"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        //"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
        //"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", 
        //"TLS_DHE_RSA_WITH_AES_256_CBC_SHA", 
        //"TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
        //"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", 
        //"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
        //"TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
        //"TLS_RSA_WITH_AES_128_CBC_SHA256",
        //"TLS_RSA_WITH_AES_128_GCM_SHA256",
        //"TLS_RSA_WITH_AES_128_CBC_SHA",
        //"TLS_RSA_WITH_AES_256_CBC_SHA",
        };
    // @formatter:on
    
    public static final List<String> SECURE_SSL_CIPHERS = Collections.unmodifiableList(Arrays.asList(_SECURE_SSL_CIPHERS));
    
    private SSLConfigConstants() {

    }

}
