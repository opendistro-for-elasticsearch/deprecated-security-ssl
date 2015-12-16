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

public final class ConfigConstants {

    public static final String SEARCHGUARD_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE = "searchguard.ssl.http.enable_openssl_if_available";
    public static final String SEARCHGUARD_SSL_HTTP_ENABLED = "searchguard.ssl.http.enabled";
    public static final boolean SEARCHGUARD_SSL_HTTP_ENABLED_DEFAULT = false;
    public static final String SEARCHGUARD_SSL_HTTP_ENFORCE_CLIENTAUTH = "searchguard.ssl.http.enforce_clientauth";
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

    private ConfigConstants() {

    }

}
