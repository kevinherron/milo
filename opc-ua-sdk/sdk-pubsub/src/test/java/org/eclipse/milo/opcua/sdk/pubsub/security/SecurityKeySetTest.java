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

import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.uint;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import org.eclipse.milo.opcua.stack.core.types.builtin.ByteString;
import org.junit.jupiter.api.Test;

/**
 * {@link SecurityKeySet} construction validation: the carrier's own rows (non-empty policy URI,
 * non-empty keys, no null-valued keys, non-negative durations) — per-policy key LENGTH validation
 * deliberately lives at {@link SecurityKeyMaterial#of} split time, not here.
 */
class SecurityKeySetTest {

  private static final String POLICY_URI = PubSubSecurityPolicy.Aes128Ctr.getUri();
  private static final ByteString KEY = ByteString.of(new byte[52]);

  @Test
  void validKeySetConstructs() {
    SecurityKeySet keySet =
        new SecurityKeySet(
            POLICY_URI, uint(7), List.of(KEY), Duration.ofSeconds(30), Duration.ofSeconds(60));

    assertEquals(POLICY_URI, keySet.securityPolicyUri());
    assertEquals(uint(7), keySet.firstTokenId());
    assertEquals(List.of(KEY), keySet.keys());
    assertEquals(Duration.ofSeconds(30), keySet.timeToNextKey());
    assertEquals(Duration.ofSeconds(60), keySet.keyLifetime());
  }

  @Test
  void zeroDurationsAreTheStaticKeyForm() {
    // Duration.ZERO in both = no key switch ever scheduled, keys never expire.
    SecurityKeySet keySet =
        new SecurityKeySet(POLICY_URI, uint(1), List.of(KEY), Duration.ZERO, Duration.ZERO);

    assertEquals(Duration.ZERO, keySet.timeToNextKey());
    assertEquals(Duration.ZERO, keySet.keyLifetime());
  }

  @Test
  void emptyPolicyUriRejected() {
    assertThrows(
        IllegalArgumentException.class,
        () -> new SecurityKeySet("", uint(1), List.of(KEY), Duration.ZERO, Duration.ZERO));
  }

  @Test
  void arbitraryPolicyUriIsAccepted() {
    // The carrier does not gate on supported policies: an unsupported provider URI is the
    // key manager's fetch-failure path, not a construction failure.
    SecurityKeySet keySet =
        new SecurityKeySet(
            "urn:some:future:policy", uint(1), List.of(KEY), Duration.ZERO, Duration.ZERO);

    assertEquals("urn:some:future:policy", keySet.securityPolicyUri());
  }

  @Test
  void emptyKeysRejected() {
    assertThrows(
        IllegalArgumentException.class,
        () -> new SecurityKeySet(POLICY_URI, uint(1), List.of(), Duration.ZERO, Duration.ZERO));
  }

  @Test
  void nullValuedKeyRejected() {
    List<ByteString> keys = new ArrayList<>();
    keys.add(KEY);
    keys.add(ByteString.NULL_VALUE);

    assertThrows(
        IllegalArgumentException.class,
        () -> new SecurityKeySet(POLICY_URI, uint(1), keys, Duration.ZERO, Duration.ZERO));
  }

  @Test
  void negativeTimeToNextKeyRejected() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            new SecurityKeySet(
                POLICY_URI, uint(1), List.of(KEY), Duration.ofMillis(-1), Duration.ZERO));
  }

  @Test
  void negativeKeyLifetimeRejected() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            new SecurityKeySet(
                POLICY_URI, uint(1), List.of(KEY), Duration.ZERO, Duration.ofMillis(-1)));
  }

  @Test
  void toStringNeverIncludesKeyBytes() {
    // a recognizable non-zero key: the generated record toString would print it in full hex via
    // ByteString.toString(), leaking the live key window into any log/exception/debugger render
    byte[] keyBytes = new byte[52];
    for (int i = 0; i < keyBytes.length; i++) {
      keyBytes[i] = (byte) 0xAB;
    }
    SecurityKeySet keySet =
        new SecurityKeySet(
            POLICY_URI,
            uint(7),
            List.of(ByteString.of(keyBytes)),
            Duration.ofSeconds(30),
            Duration.ofSeconds(60));

    String rendered = keySet.toString();
    assertFalse(rendered.toLowerCase().contains("abab"), rendered);
    // the sanitized form still identifies the set: policy, first token id, key COUNT, durations
    assertTrue(rendered.contains(POLICY_URI), rendered);
    assertTrue(rendered.contains("firstTokenId=7"), rendered);
    assertTrue(rendered.contains("keys=1"), rendered);
  }

  @Test
  void keysListIsDefensivelyCopiedAndImmutable() {
    List<ByteString> keys = new ArrayList<>();
    keys.add(KEY);

    SecurityKeySet keySet =
        new SecurityKeySet(POLICY_URI, uint(1), keys, Duration.ZERO, Duration.ZERO);

    keys.add(ByteString.of(new byte[52]));
    assertEquals(List.of(KEY), keySet.keys());

    assertThrows(
        UnsupportedOperationException.class, () -> keySet.keys().add(ByteString.of(new byte[52])));
  }
}
