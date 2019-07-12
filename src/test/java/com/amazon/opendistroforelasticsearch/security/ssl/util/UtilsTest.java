package com.amazon.opendistroforelasticsearch.security.ssl.util;

import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.rules.Timeout;

public class UtilsTest {

  @Rule public final ExpectedException thrown = ExpectedException.none();

  @Rule public final Timeout globalTimeout = new Timeout(10000);

  /* testedClasses: Utils */
  // Test written by Diffblue Cover.

  @Test
  public void coalesceInputNull1OutputNull() {

    // Arrange
    final Object first = null;
    final Object[] more = {null};

    // Act
    final Object actual = Utils.coalesce(first, more);

    // Assert result
    Assert.assertNull(actual);
  }

  // Test written by Diffblue Cover.

  @Test
  public void coalesceInputNull1OutputZero() {

    // Arrange
    final Object first = null;
    final Object[] more = {0};

    // Act
    final Object actual = Utils.coalesce(first, more);

    // Assert result
    Assert.assertEquals(0, actual);
  }

  // Test written by Diffblue Cover.
  @Test
  public void coalesceInputNullNullOutputNull() {

    // Arrange
    final Object first = null;
    final Object[] more = null;

    // Act
    final Object actual = Utils.coalesce(first, more);

    // Assert result
    Assert.assertNull(actual);
  }

  // Test written by Diffblue Cover.

  @Test
  public void coalesceInputZero0OutputZero() {

    // Arrange
    final Object first = 0;
    final Object[] more = {};

    // Act
    final Object actual = Utils.coalesce(first, more);

    // Assert result
    Assert.assertEquals(0, actual);
  }
}
