/*
 * Copyright (c) 2026 the Eclipse Milo Authors
 *
 * This program and the accompanying materials are made
 * available under the terms of the Eclipse Public License 2.0
 * which is available at https://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 */

package org.eclipse.milo.opcua.sdk.pubsub.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import org.junit.jupiter.api.Test;

/**
 * {@link KeyCredential} pinned record shape (K13): {@code toString()} never includes the secret,
 * and record equality compares the secret array by identity (not content) because the record does
 * not copy or inspect it.
 */
class KeyCredentialTest {

  @Test
  void toStringOmitsTheSecret() {
    var credential = new KeyCredential("user1", "hunter2".toCharArray());

    assertEquals("KeyCredential{credentialId=user1}", credential.toString());
  }

  @Test
  void equalityComparesSecretByIdentityNotContent() {
    char[] secret = "hunter2".toCharArray();

    var a = new KeyCredential("user1", secret);
    var b = new KeyCredential("user1", secret);
    var c = new KeyCredential("user1", "hunter2".toCharArray());

    assertEquals(a, b); // same array instance
    assertNotEquals(a, c); // equal content, different array
  }
}
