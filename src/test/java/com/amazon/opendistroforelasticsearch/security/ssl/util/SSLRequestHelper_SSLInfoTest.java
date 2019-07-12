package com.amazon.opendistroforelasticsearch.security.ssl.util;

import com.amazon.opendistroforelasticsearch.security.ssl.transport.PrincipalExtractor;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.rest.RestRequest;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.rules.Timeout;

import java.nio.file.Path;
import javax.net.ssl.SSLPeerUnverifiedException;

public class SSLRequestHelper_SSLInfoTest {

  @Rule public final ExpectedException thrown = ExpectedException.none();

  @Rule public final Timeout globalTimeout = new Timeout(10000);

  /* testedClasses: SSLRequestHelper_SSLInfo */
  // Test written by Diffblue Cover.
  @Test
  public void getSSLInfoInputNullNullNullNullOutputNull() throws SSLPeerUnverifiedException {

    // Arrange
    final Settings settings = null;
    final Path configPath = null;
    final RestRequest request = null;
    final PrincipalExtractor principalExtractor = null;

    // Act
    final SSLRequestHelper.SSLInfo actual =
        SSLRequestHelper.getSSLInfo(settings, configPath, request, principalExtractor);

    // Assert result
    Assert.assertNull(actual);
  }
}
