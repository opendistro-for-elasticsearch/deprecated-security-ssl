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

import io.netty.buffer.PooledByteBufAllocator;
import io.netty.handler.ssl.ApplicationProtocolConfig;
import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.OpenSsl;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslProvider;

import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Paths;
import java.security.AccessController;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import javax.crypto.Cipher;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;

import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.SpecialPermission;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.env.Environment;

import com.floragunn.searchguard.ssl.util.SSLCertificateHelper;
import com.floragunn.searchguard.ssl.util.SSLConfigConstants;
import com.google.common.base.Strings;

public class SearchGuardKeyStore {

    private void printJCEWarnings() {
        try {
            final int aesMaxKeyLength = Cipher.getMaxAllowedKeyLength("AES");

            if (aesMaxKeyLength < 256) {
                log.info("AES-256 not supported, max key length for AES is " + aesMaxKeyLength+" bit."
                        + ". That is not an issue, it just limits possible encryption strength. To enable AES 256 install 'Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files'");
            }
        } catch (final NoSuchAlgorithmException e) {
            log.error("AES encryption not supported. " + e);
        }
    }

    private final Settings settings;
    private final ESLogger log = Loggers.getLogger(this.getClass());
    public final SslProvider sslHTTPProvider;
    public final SslProvider sslTransportServerProvider;
    public final SslProvider sslTransportClientProvider;
    private final boolean httpSSLEnabled;
    private final boolean transportSSLEnabled;
    private X509Certificate[] trustedHTTPCertificates;
    private X509Certificate[] trustedTransportCertificates;
    private X509Certificate[] httpKeystoreCert;
    private PrivateKey httpKeystoreKey;
    private X509Certificate[] transportKeystoreCert;
    private PrivateKey transportKeystoreKey;
    private ClientAuth httpClientAuthMode;
    private List<String> enabledCiphersJDKProvider;
    private List<String> enabledCiphersOpenSSLProvider;

    @Inject
    public SearchGuardKeyStore(final Settings settings) {
        super();
        this.settings = settings;
        httpSSLEnabled = settings.getAsBoolean(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLED,
                SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLED_DEFAULT);
        transportSSLEnabled = settings.getAsBoolean(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLED,
                SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLED_DEFAULT);
        final boolean useOpenSSLForHttpIfAvailable = settings.getAsBoolean(
                SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, true);
        final boolean useOpenSSLForTransportIfAvailable = settings.getAsBoolean(
                SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, true);

        if (httpSSLEnabled && useOpenSSLForHttpIfAvailable) {
            sslHTTPProvider = SslContext.defaultServerProvider();
            logOpenSSLInfos();
        } else if (httpSSLEnabled) {
            sslHTTPProvider = SslProvider.JDK;
        } else {
            sslHTTPProvider = null;
        }

        if (transportSSLEnabled && useOpenSSLForTransportIfAvailable) {
            sslTransportClientProvider = SslContext.defaultClientProvider();
            sslTransportServerProvider = SslContext.defaultServerProvider();
            logOpenSSLInfos();
        } else if (transportSSLEnabled) {
            sslTransportClientProvider = sslTransportServerProvider = SslProvider.JDK;
        } else {
            sslTransportClientProvider = sslTransportServerProvider = null;
        }

        initSSLConfig();
        initEnabledSSLCiphers();
        printJCEWarnings();

        log.info("sslTransportClientProvider:{} with ciphers {}", sslTransportClientProvider,
                getEnabledSSLCiphers(sslTransportClientProvider));
        log.info("sslTransportServerProvider:{} with ciphers {}", sslTransportServerProvider,
                getEnabledSSLCiphers(sslTransportServerProvider));
        log.info("sslHTTPProvider:{} with ciphers {}", sslHTTPProvider, getEnabledSSLCiphers(sslHTTPProvider));

    }

    private void initSSLConfig() {
        
        final Environment env = new Environment(settings);
        log.info("Config directory is {}/, from there the key- and truststore files are resolved relatively", env.configFile().toAbsolutePath());

        StringBuilder sb = new StringBuilder();
        Map<String, String> settingsAsMap = settings.getAsMap();
        for(String key: new TreeSet<String>(settingsAsMap.keySet())) {
            sb.append(key+"="+settingsAsMap.get(key)+System.lineSeparator());
        }
        log.info("Effective settings:{}{}",System.lineSeparator(), sb);
        
        if (transportSSLEnabled) {
            
            final String keystoreFilePath = env.configFile()
                    .resolve(settings.get(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_FILEPATH, "")).toAbsolutePath().toString();
            final String keystoreType = settings.get(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_TYPE, "JKS");
            final String keystorePassword = settings.get(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_PASSWORD, "changeit");
            final String keystoreAlias = settings.get(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS, null);

            final String truststoreFilePath = env.configFile()
                    .resolve(settings.get(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_TRUSTSTORE_FILEPATH, "")).toAbsolutePath()
                    .toString();

            if(settings.get(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_FILEPATH, null) == null) {
                throw new ElasticsearchException(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_FILEPATH
                        + " must be set if transport ssl is reqested.");
            }

            checkStorePath(keystoreFilePath);
            
            if(settings.get(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_TRUSTSTORE_FILEPATH, null) == null) {
                throw new ElasticsearchException(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_TRUSTSTORE_FILEPATH
                        + " must be set if transport ssl is reqested.");
            }

            checkStorePath(truststoreFilePath);

            final String truststoreType = settings.get(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_TRUSTSTORE_TYPE, "JKS");
            final String truststorePassword = settings.get(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_TRUSTSTORE_PASSWORD, "changeit");
            final String truststoreAlias = settings.get(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_TRUSTSTORE_ALIAS, null);

            try {

                final KeyStore ks = KeyStore.getInstance(keystoreType);
                ks.load(new FileInputStream(new File(keystoreFilePath)), keystorePassword.toCharArray());

                transportKeystoreCert = SSLCertificateHelper.exportCertificateChain(ks, keystoreAlias);
                transportKeystoreKey = SSLCertificateHelper.exportDecryptedKey(ks, keystoreAlias, keystorePassword.toCharArray());

                if(transportKeystoreCert != null && transportKeystoreCert.length > 0) {
                    
                    for (int i = 0; i < transportKeystoreCert.length; i++) {
                        X509Certificate x509Certificate = transportKeystoreCert[i];
                        
                        if(x509Certificate != null) {
                            log.info("Transport keystore subject DN no. {} {}",i,x509Certificate.getSubjectX500Principal());
                        }
                    }
                }
                
                
                final KeyStore ts = KeyStore.getInstance(truststoreType);
                ts.load(new FileInputStream(new File(truststoreFilePath)), truststorePassword.toCharArray());

                trustedTransportCertificates = SSLCertificateHelper.exportCertificateChain(ts, truststoreAlias);

            } catch (final Exception e) {
                throw ExceptionsHelper.convertToElastic(e);
            }

        }

        final boolean client = !"node".equals(this.settings.get(SearchGuardSSLPlugin.CLIENT_TYPE));

        if (!client && httpSSLEnabled) {
            final String keystoreFilePath = env.configFile()
                    .resolve(settings.get(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_KEYSTORE_FILEPATH, "")).toAbsolutePath().toString();
            final String keystoreType = settings.get(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_KEYSTORE_TYPE, "JKS");
            final String keystorePassword = settings.get(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_KEYSTORE_PASSWORD, "changeit");
            final String keystoreAlias = settings.get(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_KEYSTORE_ALIAS, null);
            httpClientAuthMode = ClientAuth.valueOf(settings.get(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_CLIENTAUTH_MODE, ClientAuth.OPTIONAL.toString()));
            
            //TODO remove with next version
            String _enforceHTTPClientAuth = settings.get(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENFORCE_CLIENTAUTH);

            if(!Strings.isNullOrEmpty(_enforceHTTPClientAuth)) {
                log.warn("{} is deprecated and replaced by {}", SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENFORCE_CLIENTAUTH, SSLConfigConstants.SEARCHGUARD_SSL_HTTP_CLIENTAUTH_MODE);
                if(Boolean.parseBoolean(_enforceHTTPClientAuth)) {
                    httpClientAuthMode = ClientAuth.REQUIRE;
                }
            }

            log.info("HTTP client auth mode {}", httpClientAuthMode);
            
            final String truststoreFilePath = env.configFile()
                    .resolve(settings.get(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_TRUSTSTORE_FILEPATH, "")).toAbsolutePath().toString();

            if(settings.get(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_KEYSTORE_FILEPATH, null) == null) {
                throw new ElasticsearchException(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_KEYSTORE_FILEPATH
                        + " must be set if https is reqested.");
            }

            checkStorePath(keystoreFilePath);

            if (httpClientAuthMode == ClientAuth.REQUIRE) {
                
                if(settings.get(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_TRUSTSTORE_FILEPATH, null) == null) {
                    throw new ElasticsearchException(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_TRUSTSTORE_FILEPATH
                            + " must be set if http ssl and client auth is reqested.");
                }
                
            }

            try {

                final KeyStore ks = KeyStore.getInstance(keystoreType);
                ks.load(new FileInputStream(new File(keystoreFilePath)), keystorePassword.toCharArray());

                httpKeystoreCert = SSLCertificateHelper.exportCertificateChain(ks, keystoreAlias);
                httpKeystoreKey = SSLCertificateHelper.exportDecryptedKey(ks, keystoreAlias, keystorePassword.toCharArray());

                if(httpKeystoreCert != null && httpKeystoreCert.length > 0) {
                    
                    for (int i = 0; i < httpKeystoreCert.length; i++) {
                        X509Certificate x509Certificate = httpKeystoreCert[i];
                        
                        if(x509Certificate != null) {
                            log.info("HTTP keystore subject DN no. {} {}",i,x509Certificate.getSubjectX500Principal());
                        }
                    }
                }
                
                
                if(settings.get(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_TRUSTSTORE_FILEPATH, null) != null) {

                    checkStorePath(truststoreFilePath);
                    
                    final String truststoreType = settings.get(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_TRUSTSTORE_TYPE, "JKS");
                    final String truststorePassword = settings.get(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_TRUSTSTORE_PASSWORD, "changeit");
                    final String truststoreAlias = settings.get(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_TRUSTSTORE_ALIAS, null);

                    final KeyStore ts = KeyStore.getInstance(truststoreType);
                    ts.load(new FileInputStream(new File(truststoreFilePath)), truststorePassword.toCharArray());

                    trustedHTTPCertificates = SSLCertificateHelper.exportCertificateChain(ts, truststoreAlias);
                }
            } catch (final Exception e) {
                throw ExceptionsHelper.convertToElastic(e);
            }
        }
    }

    public SSLEngine createHTTPSSLEngine() throws SSLException {

        final SslContextBuilder sslContextBuilder = SslContextBuilder.forServer(httpKeystoreKey, httpKeystoreCert)
                .ciphers(getEnabledSSLCiphers(this.sslHTTPProvider)).applicationProtocolConfig(ApplicationProtocolConfig.DISABLED)
                .clientAuth(httpClientAuthMode) // https://github.com/netty/netty/issues/4722
                .sessionCacheSize(0).sessionTimeout(0).sslProvider(this.sslHTTPProvider);

        if (trustedHTTPCertificates != null && trustedHTTPCertificates.length > 0) {
            sslContextBuilder.trustManager(trustedHTTPCertificates);
        }
        
        final SslContext sslContext = buildSSLContext(sslContextBuilder);

        final SSLEngine engine = sslContext.newEngine(PooledByteBufAllocator.DEFAULT);
        engine.setEnabledProtocols(SSLConfigConstants.getSecureSSLProtocols());
        // engine.setNeedClientAuth(enforceHTTPClientAuth);
        return engine;

    }

    public SSLEngine createServerTransportSSLEngine() throws SSLException {

        if (trustedTransportCertificates == null) {
            throw new ElasticsearchException("No truststore configured for server");
        }

        final SslContextBuilder sslContextBuilder = SslContextBuilder.forServer(transportKeystoreKey, transportKeystoreCert)
                .ciphers(getEnabledSSLCiphers(this.sslTransportServerProvider))
                .applicationProtocolConfig(ApplicationProtocolConfig.DISABLED).clientAuth(ClientAuth.REQUIRE)
                // https://github.com/netty/netty/issues/4722
                .sessionCacheSize(0).sessionTimeout(0).sslProvider(this.sslTransportServerProvider)
                .trustManager(trustedTransportCertificates);

        final SslContext sslContext = buildSSLContext(sslContextBuilder);

        final SSLEngine engine = sslContext.newEngine(PooledByteBufAllocator.DEFAULT);
        engine.setEnabledProtocols(SSLConfigConstants.getSecureSSLProtocols());
        // engine.setNeedClientAuth(true);
        return engine;

    }

    public SSLEngine createClientTransportSSLEngine(final String peerHost, final int peerPort) throws SSLException {

        if (trustedTransportCertificates == null) {
            throw new ElasticsearchException("No truststore configured for client");
        }

        final SslContextBuilder sslContextBuilder = SslContextBuilder.forClient().ciphers(getEnabledSSLCiphers(sslTransportClientProvider))
                .applicationProtocolConfig(ApplicationProtocolConfig.DISABLED).sessionCacheSize(0).sessionTimeout(0)
                .sslProvider(sslTransportClientProvider).trustManager(trustedTransportCertificates)
                .keyManager(transportKeystoreKey, transportKeystoreCert);

        final SslContext sslContext = buildSSLContext(sslContextBuilder);

        if (peerHost != null) {
            final SSLEngine engine = sslContext.newEngine(PooledByteBufAllocator.DEFAULT, peerHost, peerPort);

            final SSLParameters sslParams = new SSLParameters();
            sslParams.setEndpointIdentificationAlgorithm("HTTPS");
            engine.setSSLParameters(sslParams);
            engine.setEnabledProtocols(SSLConfigConstants.getSecureSSLProtocols());
            return engine;
        } else {
            final SSLEngine engine = sslContext.newEngine(PooledByteBufAllocator.DEFAULT);
            engine.setEnabledProtocols(SSLConfigConstants.getSecureSSLProtocols());
            return engine;
        }

    }

    private void logOpenSSLInfos() {
        if (OpenSsl.isAvailable()) {
            log.info("Open SSL " + OpenSsl.versionString() + " available");
            log.debug("Open SSL available ciphers " + OpenSsl.availableCipherSuites());
        } else {
            log.info("Open SSL not available (this is not an error, we simply fallback to built-in JDK SSL) because of " + OpenSsl.unavailabilityCause());
        }
    }

    private List<String> getEnabledSSLCiphers(final SslProvider provider) {
        if (provider == null) {
            return Collections.emptyList();
        }

        return provider == SslProvider.JDK ? enabledCiphersJDKProvider : enabledCiphersOpenSSLProvider;
    }

    private void initEnabledSSLCiphers() {

        if (OpenSsl.isAvailable()) {
            final Set<String> openSSLSecureCiphers = new HashSet<>();
            for (final String secure : SSLConfigConstants.SECURE_SSL_CIPHERS) {
                if (OpenSsl.isCipherSuiteAvailable(secure)) {
                    openSSLSecureCiphers.add(secure);
                }
            }

            enabledCiphersOpenSSLProvider = Collections.unmodifiableList(new ArrayList<String>(openSSLSecureCiphers));
        } else {
            enabledCiphersOpenSSLProvider = Collections.emptyList();
        }

        try {
            final SSLContext serverContext = SSLContext.getInstance("TLS");
            serverContext.init(null, null, null);
            final SSLEngine engine = serverContext.createSSLEngine();
            final List<String> jdkSupportedCiphers = new ArrayList<>(Arrays.asList(engine.getSupportedCipherSuites()));
            jdkSupportedCiphers.retainAll(SSLConfigConstants.SECURE_SSL_CIPHERS);
            engine.setEnabledCipherSuites(jdkSupportedCiphers.toArray(new String[0]));

            enabledCiphersJDKProvider = Collections.unmodifiableList(Arrays.asList(engine.getEnabledCipherSuites()));
        } catch (final Exception e) {
            enabledCiphersJDKProvider = Collections.emptyList();
        }
    }

    private SslContext buildSSLContext(final SslContextBuilder sslContextBuilder) throws SSLException {

        final SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }

        SslContext sslContext = null;
        try {
            sslContext = AccessController.doPrivileged(new PrivilegedExceptionAction<SslContext>() {
                @Override
                public SslContext run() throws Exception {
                    return sslContextBuilder.build();
                }
            });
        } catch (final PrivilegedActionException e) {
            throw (SSLException) e.getCause();
        }

        return sslContext;
    }
    
    private static void checkStorePath(String keystoreFilePath) {
        if (Files.isDirectory(Paths.get(keystoreFilePath), LinkOption.NOFOLLOW_LINKS)) {
            throw new ElasticsearchException("Is a directory: " + keystoreFilePath+" Expected file!");
        }

        if(!Files.isReadable(Paths.get(keystoreFilePath))) {
            throw new ElasticsearchException("Unable to read " + keystoreFilePath + " ("+Paths.get(keystoreFilePath)+") Please make sure this files exists and is readable regarding to permissions");
        }
    }
}
