package com.amazon.opendistroforelasticsearch.security.ssl.util;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.rules.Timeout;

import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;

public class CertificateValidatorTest {

  @Rule public final ExpectedException thrown = ExpectedException.none();

  @Rule public final Timeout globalTimeout = new Timeout(10000);

  /* testedClasses: CertificateValidator */
  // Test written by Diffblue Cover.

  @Test
  public void constructorInput00OutputInvalidParameterException() {

    // Arrange
    final X509Certificate[] trustedCert = {};
    final ArrayList crls = new ArrayList();

    // Act, creating object to test constructor
    thrown.expect(java.security.InvalidParameterException.class);
    final CertificateValidator objectUnderTest = new CertificateValidator(trustedCert, crls);
  }

  // Test written by Diffblue Cover.

  @Test
  public void constructorInputNullNullOutputInvalidParameterException() {

    // Arrange
    final KeyStore trustStore = null;
    final Collection crls = null;

    // Act, creating object to test constructor
    thrown.expect(java.security.InvalidParameterException.class);
    final CertificateValidator objectUnderTest = new CertificateValidator(trustStore, crls);
  }
}
