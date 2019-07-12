package com.amazon.opendistroforelasticsearch.security.ssl.util;

import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.rules.Timeout;

public class ExceptionUtilsTest {

  @Rule public final ExpectedException thrown = ExpectedException.none();

  @Rule public final Timeout globalTimeout = new Timeout(10000);

  /* testedClasses: ExceptionUtils */
  // Test written by Diffblue Cover.
  @Test
  public void getRootCauseInputNullOutputNull() {

    // Arrange
    final Throwable e = null;

    // Act
    final Throwable actual = ExceptionUtils.getRootCause(e);

    // Assert result
    Assert.assertNull(actual);
  }
}
