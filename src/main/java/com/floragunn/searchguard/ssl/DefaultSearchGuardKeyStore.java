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
import java.util.Objects;
import java.util.Set;

import javax.crypto.Cipher;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;

import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.SpecialPermission;
import org.elasticsearch.common.inject.Inject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.env.Environment;

import com.floragunn.searchguard.ssl.util.SSLCertificateHelper;
import com.floragunn.searchguard.ssl.util.SSLConfigConstants;

public class DefaultSearchGuardKeyStore implements SearchGuardKeyStore {

    private static final String DEFAULT_STORE_TYPE = "JKS";
    private static final String DEFAULT_STORE_PASSWORD = "changeit"; //#16

    private void printJCEWarnings() {
        try {
            final int aesMaxKeyLength = Cipher.getMaxAllowedKeyLength("AES");

            if (aesMaxKeyLength < 256) {
                log.info("AES-256 not supported, max key length for AES is " + aesMaxKeyLength+" bit."
                        + ". That is not an issue, it just limits possible encryption strength. To enable AES 256 install 'Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files'");
            }
        } catch (final NoSuchAlgorithmException e) {
            log.error("AES encryption not supported (SG 1). " + e);
        }
    }

    private final Settings settings;
    private final Logger log = LogManager.getLogger(this.getClass());
    public final SslProvider sslHTTPProvider;
    public final SslProvider sslTransportServerProvider;
    public final SslProvider sslTransportClientProvider;
    private final boolean httpSSLEnabled;
    private final boolean transportSSLEnabled;
    private List<String> enabledHttpCiphersJDKProvider;
    private List<String> enabledHttpCiphersOpenSSLProvider;
    private List<String> enabledTransportCiphersJDKProvider;
    private List<String> enabledTransportCiphersOpenSSLProvider;
    private SslContext httpSslContext;
    private SslContext transportServerSslContext;
    private SslContext transportClientSslContext;

    @Inject
    public DefaultSearchGuardKeyStore(final Settings settings) {
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
        
        log.info("java.version: {}", System.getProperty("java.version"));
        log.info("java.vendor: {}", System.getProperty("java.vendor"));
        log.info("java.vm.specification.version: {}", System.getProperty("java.vm.specification.version"));
        log.info("java.vm.specification.vendor: {}", System.getProperty("java.vm.specification.vendor"));
        log.info("java.vm.specification.name: {}", System.getProperty("java.vm.specification.name"));
        log.info("java.vm.name: {}", System.getProperty("java.vm.name"));
        log.info("java.vm.vendor: {}", System.getProperty("java.vm.vendor"));
        log.info("java.specification.version: {}", System.getProperty("java.specification.version"));
        log.info("java.specification.vendor: {}", System.getProperty("java.specification.vendor"));
        log.info("java.specification.name: {}", System.getProperty("java.specification.name"));
        log.info("os.name: {}", System.getProperty("os.name"));
        log.info("os.arch: {}", System.getProperty("os.arch"));
        log.info("os.version: {}", System.getProperty("os.version"));

        initEnabledSSLCiphers();
        initSSLConfig();
        printJCEWarnings();

        log.info("sslTransportClientProvider:{} with ciphers {}", sslTransportClientProvider,
                getEnabledSSLCiphers(sslTransportClientProvider, false));
        log.info("sslTransportServerProvider:{} with ciphers {}", sslTransportServerProvider,
                getEnabledSSLCiphers(sslTransportServerProvider, false));
        log.info("sslHTTPProvider:{} with ciphers {}", sslHTTPProvider, getEnabledSSLCiphers(sslHTTPProvider, true));
        
        log.info("sslTransport protocols {}", Arrays.asList(SSLConfigConstants.getSecureSSLProtocols(settings, false)));
        log.info("sslHTTP protocols {}", Arrays.asList(SSLConfigConstants.getSecureSSLProtocols(settings, true)));
        
        
        if(transportSSLEnabled && (getEnabledSSLCiphers(sslTransportClientProvider, false).isEmpty()
                || getEnabledSSLCiphers(sslTransportServerProvider, false).isEmpty())) {
            throw new ElasticsearchSecurityException("no valid cipher suites for transport protocol");
        }

        if(httpSSLEnabled && getEnabledSSLCiphers(sslHTTPProvider, true).isEmpty()) {
            throw new ElasticsearchSecurityException("no valid cipher suites for http");
        }
        
        if(transportSSLEnabled && SSLConfigConstants.getSecureSSLProtocols(settings, false).length == 0) {
            throw new ElasticsearchSecurityException("no ssl protocols for transport protocol");
        }
        
        if(httpSSLEnabled && SSLConfigConstants.getSecureSSLProtocols(settings, true).length == 0) {
            throw new ElasticsearchSecurityException("no ssl protocols for http");
        }
    }

    private void initSSLConfig() {
        
        final Environment env = new Environment(settings);
        log.info("Config directory is {}/, from there the key- and truststore files are resolved relatively", env.configFile().toAbsolutePath());
        
        if (transportSSLEnabled) {
   
            final String rawKeyStoreFilePath = settings.get(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_FILEPATH, null);
            final String rawPemCertFilePath = settings.get(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_PEMCERT_FILEPATH, null);
            
            if(rawKeyStoreFilePath != null) {
                
                final String keystoreFilePath = env.configFile()
                        .resolve(settings.get(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_FILEPATH, "")).toAbsolutePath().toString();
                final String keystoreType = settings.get(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_TYPE, DEFAULT_STORE_TYPE);
                final String keystorePassword = settings.get(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_PASSWORD, DEFAULT_STORE_PASSWORD);
                final String keystoreAlias = settings.get(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS, null);

                final String truststoreFilePath = env.configFile()
                        .resolve(settings.get(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_TRUSTSTORE_FILEPATH, "")).toAbsolutePath()
                        .toString();

                checkStorePath(keystoreFilePath);
                
                if(settings.get(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_TRUSTSTORE_FILEPATH, null) == null) {
                    throw new ElasticsearchException(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_TRUSTSTORE_FILEPATH
                            + " must be set if transport ssl is reqested.");
                }

                checkStorePath(truststoreFilePath);

                final String truststoreType = settings.get(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_TRUSTSTORE_TYPE, DEFAULT_STORE_TYPE);
                final String truststorePassword = settings.get(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_TRUSTSTORE_PASSWORD, DEFAULT_STORE_PASSWORD);
                final String truststoreAlias = settings.get(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_TRUSTSTORE_ALIAS, null);
                

                //if(transportKeystoreCert == null || transportKeystoreCert.length == 0) {
                //    throw new ElasticsearchException("No certificates found in "+keystoreFilePath+" with alias "+keystoreAlias);
                //}
                //====#===
                try {
                
                    final KeyStore ks = KeyStore.getInstance(keystoreType);
                    ks.load(new FileInputStream(new File(keystoreFilePath)), (keystorePassword == null || keystorePassword.length() == 0) ? null:keystorePassword.toCharArray());
    
                    final X509Certificate[] transportKeystoreCert = SSLCertificateHelper.exportServerCertChain(ks, keystoreAlias);
                    final PrivateKey transportKeystoreKey = SSLCertificateHelper.exportDecryptedKey(ks, keystoreAlias, (keystorePassword==null || keystorePassword.length() == 0) ? null:keystorePassword.toCharArray());
    
                    if(transportKeystoreKey == null) {
                        throw new ElasticsearchException("No key found in "+keystoreFilePath+" with alias "+keystoreAlias);
                    }
                    
                    if(transportKeystoreCert != null && transportKeystoreCert.length > 0) {
                        
                        //TODO create sensitive log property
                        /*for (int i = 0; i < transportKeystoreCert.length; i++) {
                            X509Certificate x509Certificate = transportKeystoreCert[i];
                            
                            if(x509Certificate != null) {
                                log.info("Transport keystore subject DN no. {} {}",i,x509Certificate.getSubjectX500Principal());
                            }
                        }*/
                    } else {
                        throw new ElasticsearchException("No certificates found in "+keystoreFilePath+" with alias "+keystoreAlias);
                    }
                    
                     
                    final KeyStore ts = KeyStore.getInstance(truststoreType);
                    ts.load(new FileInputStream(new File(truststoreFilePath)), (truststorePassword==null || truststorePassword.length() == 0) ? null:truststorePassword.toCharArray());
    
                    final X509Certificate[] trustedTransportCertificates = SSLCertificateHelper.exportRootCertificates(ts, truststoreAlias);
    
                    if (trustedTransportCertificates == null) {
                        throw new ElasticsearchException("No truststore configured for server");
                    }
                    
                    transportServerSslContext = buildSSLServerContext(transportKeystoreKey, transportKeystoreCert, trustedTransportCertificates, getEnabledSSLCiphers(this.sslTransportServerProvider, false), this.sslTransportServerProvider, ClientAuth.REQUIRE);                    
                    transportClientSslContext = buildSSLClientContext(transportKeystoreKey, transportKeystoreCert, trustedTransportCertificates, getEnabledSSLCiphers(sslTransportClientProvider, false), sslTransportClientProvider);
                
                } catch (final Exception e) {
                    throw new ElasticsearchSecurityException("Error while initializing transport SSL layer: "+e.toString(), e);
                }

            } else if(rawPemCertFilePath != null) {
                
                final String pemKey = settings.get(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_PEMKEY_FILEPATH);
                final String trustedCas = settings.get(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_PEMTRUSTEDCAS_FILEPATH, null);
                
                checkStorePath(rawPemCertFilePath);
                checkStorePath(pemKey);
                checkStorePath(trustedCas);
                
                try {
                
                    transportServerSslContext = buildSSLServerContext(new File(pemKey), new File(rawPemCertFilePath), new File(trustedCas), settings.get(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_PEMKEY_PASSWORD), getEnabledSSLCiphers(this.sslTransportServerProvider, false), this.sslTransportServerProvider, ClientAuth.REQUIRE);
                    transportClientSslContext = buildSSLClientContext(new File(pemKey), new File(rawPemCertFilePath), new File(trustedCas), settings.get(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_PEMKEY_PASSWORD), getEnabledSSLCiphers(sslTransportClientProvider, false), sslTransportClientProvider);

                } catch (final Exception e) {
                    throw new ElasticsearchSecurityException("Error while initializing transport SSL layer from PEM: "+e.toString(), e);
                }
                
            } else {
                throw new ElasticsearchException(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_FILEPATH
                        + " or "+ SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_PEMKEY_FILEPATH  +" must be set if transport ssl is reqested.");
            }
        }

        final boolean client = !"node".equals(this.settings.get(SearchGuardSSLPlugin.CLIENT_TYPE));

        if (!client && httpSSLEnabled) {
            
            final String rawKeystoreFilePath = settings.get(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_KEYSTORE_FILEPATH, null);
            final String rawPemCertFilePath = settings.get(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_PEMCERT_FILEPATH, null);
            final ClientAuth httpClientAuthMode = ClientAuth.valueOf(settings.get(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_CLIENTAUTH_MODE, ClientAuth.OPTIONAL.toString()));
            
            if(rawKeystoreFilePath != null) {
                
                final String keystoreFilePath = env.configFile()
                        .resolve(settings.get(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_KEYSTORE_FILEPATH, "")).toAbsolutePath().toString();
                final String keystoreType = settings.get(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_KEYSTORE_TYPE, DEFAULT_STORE_TYPE);
                final String keystorePassword = settings.get(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_KEYSTORE_PASSWORD, DEFAULT_STORE_PASSWORD);
                final String keystoreAlias = settings.get(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_KEYSTORE_ALIAS, null);            
                
                //TODO remove with next version
                //String _enforceHTTPClientAuth = settings.get("searchguard.ssl.http.enforce_clientauth");

                //if(_enforceHTTPClientAuth != null) {
                //    log.error("{} is deprecated and replaced by {}", "searchguard.ssl.http.enforce_clientauth", SSLConfigConstants.SEARCHGUARD_SSL_HTTP_CLIENTAUTH_MODE);
                //    throw new RuntimeException("searchguard.ssl.http.enforce_clientauth is deprecated");
                //}

                log.info("HTTPS client auth mode {}", httpClientAuthMode);
                
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
                    ks.load(new FileInputStream(new File(keystoreFilePath)), (keystorePassword == null || keystorePassword.length() == 0) ? null:keystorePassword.toCharArray());

                    final X509Certificate[] httpKeystoreCert = SSLCertificateHelper.exportServerCertChain(ks, keystoreAlias);
                    final PrivateKey httpKeystoreKey = SSLCertificateHelper.exportDecryptedKey(ks, keystoreAlias, (keystorePassword==null || keystorePassword.length() == 0) ? null:keystorePassword.toCharArray());


                    if(httpKeystoreKey == null) {
                        throw new ElasticsearchException("No key found in "+keystoreFilePath+" with alias "+keystoreAlias);
                    }
                    
                    
                    if(httpKeystoreCert != null && httpKeystoreCert.length > 0) {
                        
                        //TODO create sensitive log property
                        /*for (int i = 0; i < httpKeystoreCert.length; i++) {
                            X509Certificate x509Certificate = httpKeystoreCert[i];
                            
                            if(x509Certificate != null) {
                                log.info("HTTP keystore subject DN no. {} {}",i,x509Certificate.getSubjectX500Principal());
                            }
                        }*/
                    } else {
                        throw new ElasticsearchException("No certificates found in "+keystoreFilePath+" with alias "+keystoreAlias);
                    }
                    
                    X509Certificate[] trustedHTTPCertificates = null;
                    
                    if(settings.get(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_TRUSTSTORE_FILEPATH, null) != null) {

                        checkStorePath(truststoreFilePath);
                        
                        final String truststoreType = settings.get(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_TRUSTSTORE_TYPE, DEFAULT_STORE_TYPE);
                        final String truststorePassword = settings.get(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_TRUSTSTORE_PASSWORD, DEFAULT_STORE_PASSWORD);
                        final String truststoreAlias = settings.get(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_TRUSTSTORE_ALIAS, null);

                        final KeyStore ts = KeyStore.getInstance(truststoreType);
                        ts.load(new FileInputStream(new File(truststoreFilePath)), (truststorePassword == null || truststorePassword.length() == 0) ?null:truststorePassword.toCharArray());

                        trustedHTTPCertificates = SSLCertificateHelper.exportRootCertificates(ts, truststoreAlias);
                    }
                    
                    httpSslContext = buildSSLServerContext(httpKeystoreKey, httpKeystoreCert, trustedHTTPCertificates, getEnabledSSLCiphers(this.sslHTTPProvider, true), sslHTTPProvider, httpClientAuthMode);
                    
                } catch (final Exception e) {
                    throw new ElasticsearchSecurityException("Error while initializing HTTP SSL layer: "+e.toString(), e);
                }
                
            } else if (rawPemCertFilePath != null) {
                
                final String trustedCas = settings.get(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_PEMTRUSTEDCAS_FILEPATH, null);
                
                if (httpClientAuthMode == ClientAuth.REQUIRE) {
                    
                    if(trustedCas == null) {
                        throw new ElasticsearchException(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_PEMTRUSTEDCAS_FILEPATH
                                + " must be set if http ssl and client auth is reqested.");
                    }
                    
                    checkStorePath(trustedCas);
                    
                }
                
                final String pemKey = settings.get(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_PEMKEY_FILEPATH);

                checkStorePath(rawPemCertFilePath);
                checkStorePath(pemKey);
                
                try {
                    httpSslContext = buildSSLServerContext(new File(pemKey), new File(rawPemCertFilePath), trustedCas == null?null:new File(trustedCas), settings.get(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_PEMKEY_PASSWORD), getEnabledSSLCiphers(this.sslHTTPProvider, true), sslHTTPProvider, httpClientAuthMode);
                } catch (final Exception e) {
                    throw new ElasticsearchSecurityException("Error while initializing http SSL layer from PEM: "+e.toString(), e);
                }
                
            } else {
                throw new ElasticsearchException(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_KEYSTORE_FILEPATH
                        + " or "+ SSLConfigConstants.SEARCHGUARD_SSL_HTTP_PEMKEY_FILEPATH  +" must be set if http ssl is reqested.");
            }
            
            
        }
    }

    public SSLEngine createHTTPSSLEngine() throws SSLException {
        final SSLEngine engine = httpSslContext.newEngine(PooledByteBufAllocator.DEFAULT);
        engine.setEnabledProtocols(SSLConfigConstants.getSecureSSLProtocols(settings, true));
        return engine;

    }

    public SSLEngine createServerTransportSSLEngine() throws SSLException {
        
        final SSLEngine engine = transportServerSslContext.newEngine(PooledByteBufAllocator.DEFAULT);
        engine.setEnabledProtocols(SSLConfigConstants.getSecureSSLProtocols(settings, false));
        return engine;

    }

    public SSLEngine createClientTransportSSLEngine(final String peerHost, final int peerPort) throws SSLException {

        if (peerHost != null) {
            final SSLEngine engine = transportClientSslContext.newEngine(PooledByteBufAllocator.DEFAULT, peerHost, peerPort);

            final SSLParameters sslParams = new SSLParameters();
            sslParams.setEndpointIdentificationAlgorithm("HTTPS");
            engine.setSSLParameters(sslParams);
            engine.setEnabledProtocols(SSLConfigConstants.getSecureSSLProtocols(settings, false));
            return engine;
        } else {
            final SSLEngine engine = transportClientSslContext.newEngine(PooledByteBufAllocator.DEFAULT);
            engine.setEnabledProtocols(SSLConfigConstants.getSecureSSLProtocols(settings, false));
            return engine;
        }

    }
    
    @Override
    public String getHTTPProviderName() {
        return sslHTTPProvider==null?null:sslHTTPProvider.toString();
    }

    @Override
    public String getTransportServerProviderName() {
        return sslTransportServerProvider==null?null:sslTransportServerProvider.toString();
    }

    @Override
    public String getTransportClientProviderName() {
        return sslTransportClientProvider==null?null:sslTransportClientProvider.toString();
    }

    private void logOpenSSLInfos() {
        if (OpenSsl.isAvailable()) {
            log.info("Open SSL " + OpenSsl.versionString() + " available");
            log.debug("Open SSL available ciphers " + OpenSsl.availableOpenSslCipherSuites());
        } else {
            log.info("Open SSL not available (this is not an error, we simply fallback to built-in JDK SSL) because of " + OpenSsl.unavailabilityCause());
        }
    }

    private List<String> getEnabledSSLCiphers(final SslProvider provider, boolean http) {
        if (provider == null) {
            return Collections.emptyList();
        }

        if(http) {
            return provider == SslProvider.JDK ? enabledHttpCiphersJDKProvider : enabledHttpCiphersOpenSSLProvider;
        } else {
            return provider == SslProvider.JDK ? enabledTransportCiphersJDKProvider : enabledTransportCiphersOpenSSLProvider;
        }
        
    }

    private void initEnabledSSLCiphers() {
        
        List<String> secureSSLCiphers = SSLConfigConstants.getSecureSSLCiphers(settings, true);

        if (OpenSsl.isAvailable()) {
            final Set<String> openSSLSecureCiphers = new HashSet<>();
            for (final String secure : secureSSLCiphers) {
                if (OpenSsl.isCipherSuiteAvailable(secure)) {
                    openSSLSecureCiphers.add(secure);
                }
            }

            enabledHttpCiphersOpenSSLProvider = Collections.unmodifiableList(new ArrayList<String>(openSSLSecureCiphers));
        } else {
            enabledHttpCiphersOpenSSLProvider = Collections.emptyList();
        }

        SSLEngine engine = null;
        try {
            final SSLContext serverContext = SSLContext.getInstance("TLS");
            serverContext.init(null, null, null);
            engine = serverContext.createSSLEngine();
            final List<String> jdkSupportedCiphers = new ArrayList<>(Arrays.asList(engine.getSupportedCipherSuites()));
            log.info("JVM supports the following {} ciphers for https {}", jdkSupportedCiphers.size(), jdkSupportedCiphers);
            jdkSupportedCiphers.retainAll(secureSSLCiphers);
            engine.setEnabledCipherSuites(jdkSupportedCiphers.toArray(new String[0]));

            enabledHttpCiphersJDKProvider = Collections.unmodifiableList(Arrays.asList(engine.getEnabledCipherSuites()));
        } catch (final Throwable e) {
            log.error("Unable to determine supported ciphers due to "+ExceptionsHelper.stackTrace(e));
            enabledHttpCiphersJDKProvider = secureSSLCiphers;
        } finally {
            if(engine != null) {
                try {
                    engine.closeInbound();
                } catch (SSLException e) {
                    log.debug("Unable to close inbound ssl engine", e);
                }
                engine.closeOutbound();
            }
        }
        
        
        
        secureSSLCiphers = SSLConfigConstants.getSecureSSLCiphers(settings, false);

        if (OpenSsl.isAvailable()) {
            final Set<String> openSSLSecureCiphers = new HashSet<>();
            for (final String secure : secureSSLCiphers) {
                if (OpenSsl.isCipherSuiteAvailable(secure)) {
                    openSSLSecureCiphers.add(secure);
                }
            }

            enabledTransportCiphersOpenSSLProvider = Collections.unmodifiableList(new ArrayList<String>(openSSLSecureCiphers));
        } else {
            enabledTransportCiphersOpenSSLProvider = Collections.emptyList();
        }

        try {
            final SSLContext serverContext = SSLContext.getInstance("TLS");
            serverContext.init(null, null, null);
            engine = serverContext.createSSLEngine();
            final List<String> jdkSupportedCiphers = new ArrayList<>(Arrays.asList(engine.getSupportedCipherSuites()));
            log.info("JVM supports the following {} ciphers for transport {}", jdkSupportedCiphers.size(), jdkSupportedCiphers);
            jdkSupportedCiphers.retainAll(secureSSLCiphers);
            engine.setEnabledCipherSuites(jdkSupportedCiphers.toArray(new String[0]));

            enabledTransportCiphersJDKProvider = Collections.unmodifiableList(Arrays.asList(engine.getEnabledCipherSuites()));
        } catch (final Throwable e) {
            log.error("Unable to determine supported ciphers due to "+ExceptionsHelper.stackTrace(e));
            enabledTransportCiphersJDKProvider = secureSSLCiphers;
        } finally {
            if(engine != null) {
                try {
                    engine.closeInbound();
                } catch (SSLException e) {
                    log.debug("Unable to close inbound ssl engine", e);
                }
                engine.closeOutbound();
            }
        }
    }
    
    private SslContext buildSSLServerContext(final PrivateKey _key, final X509Certificate[] _cert, final X509Certificate[] _trustedCerts, final Iterable<String> ciphers, final SslProvider sslProvider, final ClientAuth authMode) throws SSLException {

        final SslContextBuilder _sslContextBuilder = 
                SslContextBuilder
                .forServer(_key, _cert)
                .ciphers(ciphers)
                .applicationProtocolConfig(ApplicationProtocolConfig.DISABLED)
                .clientAuth(Objects.requireNonNull(authMode)) // https://github.com/netty/netty/issues/4722
                .sessionCacheSize(0)
                .sessionTimeout(0)
                .sslProvider(sslProvider);
        
        if(_trustedCerts != null && _trustedCerts.length > 0) {
            _sslContextBuilder.trustManager(_trustedCerts);
        }
        
        return buildSSLContext0(_sslContextBuilder);
    }
    
    private SslContext buildSSLServerContext(final File _key, final File _cert, final File _trustedCerts, final String pwd, final Iterable<String> ciphers, final SslProvider sslProvider, final ClientAuth authMode) throws SSLException {

        final SslContextBuilder _sslContextBuilder = 
                SslContextBuilder
                .forServer(_cert, _key, pwd)
                .ciphers(ciphers)
                .applicationProtocolConfig(ApplicationProtocolConfig.DISABLED)
                .clientAuth(Objects.requireNonNull(authMode)) // https://github.com/netty/netty/issues/4722
                .sessionCacheSize(0)
                .sessionTimeout(0)
                .sslProvider(sslProvider);
        
        if(_trustedCerts != null) {
            _sslContextBuilder.trustManager(_trustedCerts);
        }
        
        return buildSSLContext0(_sslContextBuilder);
    }
    
    private SslContext buildSSLClientContext(final PrivateKey _key, final X509Certificate[] _cert, final X509Certificate[] _trustedCerts, final Iterable<String> ciphers, final SslProvider sslProvider) throws SSLException {

        final SslContextBuilder _sslClientContextBuilder = 
                SslContextBuilder
                .forClient()
                .ciphers(ciphers)
                .applicationProtocolConfig(ApplicationProtocolConfig.DISABLED)
                .sessionCacheSize(0)
                .sessionTimeout(0)
                .sslProvider(sslProvider)
                .trustManager(_trustedCerts)
                .keyManager(_key, _cert);
        
        return buildSSLContext0(_sslClientContextBuilder);

    }
    
    private SslContext buildSSLClientContext(final File _key, final File _cert, final File _trustedCerts, final String pwd, final Iterable<String> ciphers, final SslProvider sslProvider) throws SSLException {

        final SslContextBuilder _sslClientContextBuilder = 
                SslContextBuilder
                .forClient()
                .ciphers(ciphers)
                .applicationProtocolConfig(ApplicationProtocolConfig.DISABLED)
                .sessionCacheSize(0)
                .sessionTimeout(0)
                .sslProvider(sslProvider)
                .trustManager(_trustedCerts)
                .keyManager(_cert, _key, pwd);
        
        return buildSSLContext0(_sslClientContextBuilder);

    }

    private SslContext buildSSLContext0(final SslContextBuilder sslContextBuilder) throws SSLException {

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
        
        if (keystoreFilePath == null || keystoreFilePath.length() == 0) {
            throw new ElasticsearchException("Empty file path");
        }
        
        if (Files.isDirectory(Paths.get(keystoreFilePath), LinkOption.NOFOLLOW_LINKS)) {
            throw new ElasticsearchException("Is a directory: " + keystoreFilePath+" Expected file!");
        }

        if(!Files.isReadable(Paths.get(keystoreFilePath))) {
            throw new ElasticsearchException("Unable to read " + keystoreFilePath + " ("+Paths.get(keystoreFilePath)+") Please make sure this files exists and is readable regarding to permissions");
        }
    }
}