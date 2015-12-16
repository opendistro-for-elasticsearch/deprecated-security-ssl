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
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import javax.crypto.Cipher;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;

import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.ExceptionsHelper;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.env.Environment;

import com.floragunn.searchguard.ssl.util.CertificateHelper;
import com.floragunn.searchguard.ssl.util.ConfigConstants;
import com.google.common.base.Strings;

public class SearchGuardKeyStore {

    private void printJCEWarnings() {
        try {
            final int aesMaxKeyLength = Cipher.getMaxAllowedKeyLength("AES");

            if (aesMaxKeyLength < 256) {
                log.warn("AES 256 not supported, max key length for AES is " + aesMaxKeyLength
                        + ". To enable AES 256 install 'Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files'");
            }
        } catch (final NoSuchAlgorithmException e) {
            log.error("AES encryption not supported. " + e);
        }
    }

    private static final String[] PREFFERED_SSL_CIPHERS = { "TLS_RSA_WITH_AES_128_CBC_SHA256", "TLS_RSA_WITH_AES_128_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_DHE_RSA_WITH_AES_256_CBC_SHA", "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
        "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256" };

    private final Settings settings;
    private final ESLogger log = Loggers.getLogger(this.getClass());
    public final SslProvider sslHTTPProvider;
    public final SslProvider sslTransportServerProvider;
    public final SslProvider sslTransportClientProvider;
    private final boolean httpSSLEnabled;
    private final boolean transportSSLEnabled;
    private File trustedHTTPCertificates;
    private File trustedTransportCertificates;
    private File httpKeystoreCert;
    private File httpKeystoreKey;
    private File transportKeystoreCert;
    private File transportKeystoreKey;
    private boolean isOpenSSL;
    private boolean isJDKSSL;
    private boolean enforceHTTPClientAuth;
    private Set<String> availableChipers;

    @Inject
    public SearchGuardKeyStore(final Settings settings) {
        super();
        this.settings = settings;
        httpSSLEnabled = settings.getAsBoolean(ConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLED,
                ConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLED_DEFAULT);
        transportSSLEnabled = settings.getAsBoolean(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLED,
                ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLED_DEFAULT);
        final boolean useOpenSSLForHttpIfAvailable = settings.getAsBoolean(
                ConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, true);
        final boolean useOpenSSLForTransportIfAvailable = settings.getAsBoolean(
                ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, true);

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

        log.info("sslTransportClientProvider:{} ", sslTransportClientProvider);
        log.info("sslTransportServerProvider:{} ", sslTransportServerProvider);
        log.info("sslHTTPProvider:{} ", sslHTTPProvider);

        if (sslTransportClientProvider == SslProvider.OPENSSL || sslHTTPProvider == SslProvider.OPENSSL
                || sslTransportServerProvider == SslProvider.OPENSSL) {
            isOpenSSL = true;
        }

        if (sslTransportClientProvider == SslProvider.JDK || sslHTTPProvider == SslProvider.JDK
                || sslTransportServerProvider == SslProvider.JDK) {
            isJDKSSL = true;
        }

        initEnabledSSLCiphers();
        printJCEWarnings();

        log.info("isOpenSSL:{} ", isOpenSSL);
        log.info("isJDKSSL:{} ", isJDKSSL);
    }

    private void initSSLConfig() {

        if (transportSSLEnabled) {
            final Environment env = new Environment(settings);
            final String keystoreFilePath = env.configFile()
                    .resolve(settings.get(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_FILEPATH, "")).toAbsolutePath().toString();
            final String keystoreType = settings.get(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_TYPE, "JKS");
            final String keystorePassword = settings.get(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_PASSWORD, "changeit");
            final String keystoreAlias = settings.get(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS, null);

            final String truststoreFilePath = env.configFile()
                    .resolve(settings.get(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_TRUSTSTORE_FILEPATH, "")).toAbsolutePath().toString();

            if (Strings.isNullOrEmpty(keystoreFilePath)) {
                throw new ElasticsearchException(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_FILEPATH
                        + " must be set if transport ssl is reqested.");
            }

            if (!Files.isReadable(Paths.get(keystoreFilePath))) {
                throw new ElasticsearchException("No such file " + keystoreFilePath);
            }

            if (Strings.isNullOrEmpty(truststoreFilePath)) {
                throw new ElasticsearchException(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_TRUSTSTORE_FILEPATH
                        + " must be set if transport ssl is reqested.");
            }

            if (!Files.isReadable(Paths.get(truststoreFilePath))) {
                throw new ElasticsearchException("No such file " + truststoreFilePath);
            }

            final String truststoreType = settings.get(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_TRUSTSTORE_TYPE, "JKS");
            final String truststorePassword = settings.get(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_TRUSTSTORE_PASSWORD, "changeit");
            final String truststoreAlias = settings.get(ConfigConstants.SEARCHGUARD_SSL_TRANSPORT_TRUSTSTORE_ALIAS, null);

            try {

                final KeyStore ks = KeyStore.getInstance(keystoreType);
                ks.load(new FileInputStream(new File(keystoreFilePath)), keystorePassword.toCharArray());

                transportKeystoreCert = File.createTempFile("sg_", ".pem");
                transportKeystoreKey = File.createTempFile("sg_", ".pem");
                CertificateHelper.exportCertificateChain(ks, keystoreAlias, transportKeystoreCert);
                CertificateHelper.exportDecryptedKey(ks, keystoreAlias, keystorePassword.toCharArray(), transportKeystoreKey);
                transportKeystoreCert.deleteOnExit();
                transportKeystoreKey.deleteOnExit();

                final KeyStore ts = KeyStore.getInstance(truststoreType);
                ts.load(new FileInputStream(new File(truststoreFilePath)), truststorePassword.toCharArray());

                trustedTransportCertificates = File.createTempFile("sg_", ".pem");
                trustedTransportCertificates.deleteOnExit();

                CertificateHelper.exportCertificateChain(ts, truststoreAlias, trustedTransportCertificates);

            } catch (final Exception e) {
                throw ExceptionsHelper.convertToElastic(e);
            }

        }

        final boolean client = !"node".equals(this.settings.get(SearchGuardSSLPlugin.CLIENT_TYPE));

        if (!client && httpSSLEnabled) {
            final Environment env = new Environment(settings);
            final String keystoreFilePath = env.configFile()
                    .resolve(settings.get(ConfigConstants.SEARCHGUARD_SSL_HTTP_KEYSTORE_FILEPATH, "")).toAbsolutePath().toString();
            final String keystoreType = settings.get(ConfigConstants.SEARCHGUARD_SSL_HTTP_KEYSTORE_TYPE, "JKS");
            final String keystorePassword = settings.get(ConfigConstants.SEARCHGUARD_SSL_HTTP_KEYSTORE_PASSWORD, "changeit");
            final String keystoreAlias = settings.get(ConfigConstants.SEARCHGUARD_SSL_HTTP_KEYSTORE_ALIAS, null);
            enforceHTTPClientAuth = settings.getAsBoolean(ConfigConstants.SEARCHGUARD_SSL_HTTP_ENFORCE_CLIENTAUTH, false);

            final String truststoreFilePath = env.configFile()
                    .resolve(settings.get(ConfigConstants.SEARCHGUARD_SSL_HTTP_TRUSTSTORE_FILEPATH, "")).toAbsolutePath().toString();

            if (Strings.isNullOrEmpty(keystoreFilePath)) {
                throw new ElasticsearchException(ConfigConstants.SEARCHGUARD_SSL_HTTP_KEYSTORE_FILEPATH
                        + " must be set if https is reqested.");
            }

            if (!Files.isReadable(Paths.get(keystoreFilePath))) {
                throw new ElasticsearchException("No such file " + keystoreFilePath);
            }

            if (enforceHTTPClientAuth && Strings.isNullOrEmpty(truststoreFilePath)) {
                throw new ElasticsearchException("{} must not be null or empty if {} is true",
                        ConfigConstants.SEARCHGUARD_SSL_HTTP_TRUSTSTORE_FILEPATH, ConfigConstants.SEARCHGUARD_SSL_HTTP_ENFORCE_CLIENTAUTH);
            }

            if (!Strings.isNullOrEmpty(truststoreFilePath) && !Files.isReadable(Paths.get(truststoreFilePath))) {
                throw new ElasticsearchException("No such file " + truststoreFilePath);
            }

            try {

                final KeyStore ks = KeyStore.getInstance(keystoreType);
                ks.load(new FileInputStream(new File(keystoreFilePath)), keystorePassword.toCharArray());

                httpKeystoreCert = File.createTempFile("sg_", ".pem");
                httpKeystoreKey = File.createTempFile("sg_", ".pem");
                CertificateHelper.exportCertificateChain(ks, keystoreAlias, httpKeystoreCert);
                CertificateHelper.exportDecryptedKey(ks, keystoreAlias, keystorePassword.toCharArray(), httpKeystoreKey);
                httpKeystoreCert.deleteOnExit();
                httpKeystoreKey.deleteOnExit();

                if (!Strings.isNullOrEmpty(truststoreFilePath)) {

                    final String truststoreType = settings.get(ConfigConstants.SEARCHGUARD_SSL_HTTP_TRUSTSTORE_TYPE, "JKS");
                    final String truststorePassword = settings.get(ConfigConstants.SEARCHGUARD_SSL_HTTP_TRUSTSTORE_PASSWORD, "changeit");
                    final String truststoreAlias = settings.get(ConfigConstants.SEARCHGUARD_SSL_HTTP_TRUSTSTORE_ALIAS, null);

                    final KeyStore ts = KeyStore.getInstance(truststoreType);
                    ts.load(new FileInputStream(new File(truststoreFilePath)), truststorePassword.toCharArray());

                    trustedHTTPCertificates = File.createTempFile("sg_", ".pem");
                    trustedHTTPCertificates.deleteOnExit();

                    CertificateHelper.exportCertificateChain(ts, truststoreAlias, trustedHTTPCertificates);
                }
            } catch (final Exception e) {
                throw ExceptionsHelper.convertToElastic(e);
            }
        }
    }

    public SSLEngine createHTTPSSLEngine() throws SSLException {

        final SslContextBuilder sslContextBuilder = SslContextBuilder.forServer(httpKeystoreCert, httpKeystoreKey)
                .ciphers(getEnabledSSLCiphers()).applicationProtocolConfig(ApplicationProtocolConfig.DISABLED)
                .clientAuth(enforceHTTPClientAuth ? ClientAuth.REQUIRE : ClientAuth.NONE).sessionCacheSize(0).sessionTimeout(0)
                .sslProvider(this.sslHTTPProvider);

        if (enforceHTTPClientAuth) {
            sslContextBuilder.trustManager(trustedHTTPCertificates);
        }

        return sslContextBuilder.build().newEngine(PooledByteBufAllocator.DEFAULT);

    }

    public SSLEngine createServerTransportSSLEngine() throws SSLException {

        if (log.isDebugEnabled()) {
            log.debug("Create server transport engine for trustedTransportCertificates {}", trustedTransportCertificates);
        }

        if (trustedTransportCertificates == null) {
            throw new ElasticsearchException("No truststore configured for server");
        }

        final SslContextBuilder sslContextBuilder = SslContextBuilder.forServer(transportKeystoreCert, transportKeystoreKey)
                .ciphers(getEnabledSSLCiphers()).applicationProtocolConfig(ApplicationProtocolConfig.DISABLED)
                .clientAuth(ClientAuth.REQUIRE).sessionCacheSize(0).sessionTimeout(0).sslProvider(this.sslTransportServerProvider)
                .trustManager(trustedTransportCertificates);
        return sslContextBuilder.build().newEngine(PooledByteBufAllocator.DEFAULT);

    }

    public SSLEngine createClientTransportSSLEngine(final String peerHost, final int peerPort) throws SSLException {

        if (log.isDebugEnabled()) {
            log.debug("Create client transport engine for peer {} and port {}", peerHost, peerPort);
        }

        if (trustedTransportCertificates == null) {
            throw new ElasticsearchException("No truststore configured for client");
        }

        final SslContextBuilder sslContextBuilder = SslContextBuilder.forClient().ciphers(getEnabledSSLCiphers())
                .applicationProtocolConfig(ApplicationProtocolConfig.DISABLED).sessionCacheSize(0).sessionTimeout(0)
                .sslProvider(sslTransportClientProvider).trustManager(trustedTransportCertificates)
                .keyManager(transportKeystoreCert, transportKeystoreKey, null);

        final SslContext sslContext = sslContextBuilder.build();

        if (peerHost != null) {
            final SSLEngine engine = sslContext.newEngine(PooledByteBufAllocator.DEFAULT, peerHost, peerPort);

            final SSLParameters sslParams = new SSLParameters();
            sslParams.setEndpointIdentificationAlgorithm("HTTPS");
            engine.setSSLParameters(sslParams);

            return engine;
        } else {
            return sslContext.newEngine(PooledByteBufAllocator.DEFAULT);
        }

    }

    private void logOpenSSLInfos() {
        if (OpenSsl.isAvailable()) {
            log.info("Open SSL " + OpenSsl.versionString() + " available");
            log.info("Open SSL available ciphers " + OpenSsl.availableCipherSuites());
            log.info("Open SSL ALPN supported " + OpenSsl.isAlpnSupported());
        } else {
            log.info("Open SSL not available because of " + OpenSsl.unavailabilityCause());
        }
    }

    private Set<String> getEnabledSSLCiphers() {
        return Collections.unmodifiableSet(availableChipers);
    }

    private void initEnabledSSLCiphers() {
        availableChipers = new HashSet<String>(Arrays.asList(PREFFERED_SSL_CIPHERS));

        if (isOpenSSL) {

            for (int i = 0; i < PREFFERED_SSL_CIPHERS.length; i++) {
                if (!OpenSsl.isCipherSuiteAvailable(PREFFERED_SSL_CIPHERS[i])) {
                    availableChipers.remove(PREFFERED_SSL_CIPHERS[i]);
                }
            }
        }

        if (isJDKSSL) {
            try {
                final SSLContext serverContext = SSLContext.getInstance("TLS");
                serverContext.init(null, null, null);
                final SSLEngine engine = serverContext.createSSLEngine();
                availableChipers.retainAll(Arrays.asList(engine.getSupportedCipherSuites()));
            } catch (final Exception e) {
                log.error("Error detecting supported cipher suites for JDK SSL {}", e, e);
            }
        }
    }
}
