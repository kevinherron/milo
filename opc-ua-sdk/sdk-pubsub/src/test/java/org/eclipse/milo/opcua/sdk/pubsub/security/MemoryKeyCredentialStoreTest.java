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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;

/**
 * {@link MemoryKeyCredentialStore} secret-ownership semantics: copy-in on put, fresh copy per
 * lookup, and best-effort wipe of the internal copy on remove/replace.
 *
 * <p>The wipe happens to the store's private internal arrays and is deliberately unobservable
 * through the public API (every lookup returns a copy), so the wipe tests borrow the internal map
 * via reflection — pinning the zeroization contract, not the field layout.
 */
class MemoryKeyCredentialStoreTest {

  private static final String RESOURCE = "opc.tcp://sks.example:4840";

  @Test
  void lookupOfUnknownResourceIsEmpty() {
    var store = new MemoryKeyCredentialStore();

    assertEquals(Optional.empty(), store.lookup("urn:not:present"));
  }

  @Test
  void putThenLookupReturnsTheCredential() {
    var store = new MemoryKeyCredentialStore();
    store.put(RESOURCE, "user1", "hunter2".toCharArray());

    KeyCredential credential = store.lookup(RESOURCE).orElseThrow();

    assertEquals("user1", credential.credentialId());
    assertArrayEquals("hunter2".toCharArray(), credential.secret());
  }

  @Test
  void putCopiesTheCallerArray() {
    var store = new MemoryKeyCredentialStore();
    char[] secret = "hunter2".toCharArray();
    store.put(RESOURCE, "user1", secret);

    // The caller retains ownership and wipes its array; the store kept its own copy.
    Arrays.fill(secret, '\0');

    assertArrayEquals("hunter2".toCharArray(), store.lookup(RESOURCE).orElseThrow().secret());
  }

  @Test
  void eachLookupReturnsAFreshCopyTheCallerOwns() {
    var store = new MemoryKeyCredentialStore();
    store.put(RESOURCE, "user1", "hunter2".toCharArray());

    char[] first = store.lookup(RESOURCE).orElseThrow().secret();
    char[] second = store.lookup(RESOURCE).orElseThrow().secret();
    assertNotSame(first, second);

    // Wiping (or mutating) a returned copy never affects the store.
    Arrays.fill(first, '\0');

    assertArrayEquals("hunter2".toCharArray(), store.lookup(RESOURCE).orElseThrow().secret());
  }

  @Test
  void removeThenLookupIsEmpty() {
    var store = new MemoryKeyCredentialStore();
    store.put(RESOURCE, "user1", "hunter2".toCharArray());

    store.remove(RESOURCE);

    assertEquals(Optional.empty(), store.lookup(RESOURCE));
  }

  @Test
  void removeOfUnknownResourceIsANoOp() {
    var store = new MemoryKeyCredentialStore();

    assertDoesNotThrow(() -> store.remove("urn:not:present"));
  }

  @Test
  void removeWipesTheInternalSecretCopy() throws Exception {
    var store = new MemoryKeyCredentialStore();
    store.put(RESOURCE, "user1", "hunter2".toCharArray());

    char[] internalSecret = internalSecret(store, RESOURCE);
    assertArrayEquals("hunter2".toCharArray(), internalSecret);

    store.remove(RESOURCE);

    assertArrayEquals(new char[7], internalSecret);
  }

  @Test
  void replaceWipesTheReplacedInternalSecretCopy() throws Exception {
    var store = new MemoryKeyCredentialStore();
    store.put(RESOURCE, "user1", "hunter2".toCharArray());

    char[] replacedSecret = internalSecret(store, RESOURCE);

    store.put(RESOURCE, "user2", "swordfish".toCharArray());

    assertArrayEquals(new char[7], replacedSecret);

    KeyCredential credential = store.lookup(RESOURCE).orElseThrow();
    assertEquals("user2", credential.credentialId());
    assertArrayEquals("swordfish".toCharArray(), credential.secret());
  }

  @Test
  void storesAreIndependentPerResourceUri() {
    var store = new MemoryKeyCredentialStore();
    store.put(RESOURCE, "user1", "hunter2".toCharArray());
    store.put("mqtt://broker.example:1883", "broker-user", "brokerpw".toCharArray());

    store.remove(RESOURCE);

    KeyCredential remaining = store.lookup("mqtt://broker.example:1883").orElseThrow();
    assertEquals("broker-user", remaining.credentialId());
    assertArrayEquals("brokerpw".toCharArray(), remaining.secret());
  }

  // region helpers

  /** Borrow the store's INTERNAL secret array (not a lookup copy) to observe the wipe. */
  @SuppressWarnings("unchecked")
  private static char[] internalSecret(MemoryKeyCredentialStore store, String resourceUri)
      throws Exception {

    Field field = MemoryKeyCredentialStore.class.getDeclaredField("credentials");
    field.setAccessible(true);
    var credentials = (Map<String, KeyCredential>) field.get(store);

    synchronized (store) {
      KeyCredential credential = credentials.get(resourceUri);
      assertTrue(credential != null, "no entry for " + resourceUri);
      return credential.secret();
    }
  }

  // endregion
}
