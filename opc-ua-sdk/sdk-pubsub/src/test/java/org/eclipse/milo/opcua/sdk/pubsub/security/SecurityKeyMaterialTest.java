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
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.stream.Stream;
import org.eclipse.milo.opcua.stack.core.types.builtin.ByteString;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * {@link SecurityKeyMaterial}: the Part 14 §7.2.4.4.3.1 Table 155 key data splitter ({@code
 * SigningKey || EncryptingKey || KeyNonce}, strict 52/68-byte validation), the parts factory, and
 * the destroy/zeroization semantics.
 */
class SecurityKeyMaterialTest {

  // region Table 155 splitting

  @Test
  void splitsAes128KeyDataAtTable155Offsets() {
    // 52 bytes 0x00..0x33: SigningKey = [0, 32), EncryptingKey = [32, 48), KeyNonce = [48, 52).
    SecurityKeyMaterial material =
        SecurityKeyMaterial.of(PubSubSecurityPolicy.Aes128Ctr, patternKeyData(52));

    assertEquals(PubSubSecurityPolicy.Aes128Ctr, material.getPolicy());
    assertArrayEquals(pattern(0x00, 32), material.getSigningKey());
    assertArrayEquals(pattern(0x20, 16), material.getEncryptingKey());
    assertArrayEquals(pattern(0x30, 4), material.getKeyNonce());
  }

  @Test
  void splitsAes256KeyDataAtTable155Offsets() {
    // 68 bytes 0x00..0x43: SigningKey = [0, 32), EncryptingKey = [32, 64), KeyNonce = [64, 68).
    SecurityKeyMaterial material =
        SecurityKeyMaterial.of(PubSubSecurityPolicy.Aes256Ctr, patternKeyData(68));

    assertEquals(PubSubSecurityPolicy.Aes256Ctr, material.getPolicy());
    assertArrayEquals(pattern(0x00, 32), material.getSigningKey());
    assertArrayEquals(pattern(0x20, 32), material.getEncryptingKey());
    assertArrayEquals(pattern(0x40, 4), material.getKeyNonce());
  }

  static Stream<Arguments> wrongKeyDataLengths() {
    return Stream.of(
        Arguments.of("Aes128Ctr, 0 bytes", PubSubSecurityPolicy.Aes128Ctr, 0),
        Arguments.of("Aes128Ctr, 51 bytes", PubSubSecurityPolicy.Aes128Ctr, 51),
        Arguments.of("Aes128Ctr, 53 bytes", PubSubSecurityPolicy.Aes128Ctr, 53),
        Arguments.of("Aes128Ctr, 68 bytes (other policy's)", PubSubSecurityPolicy.Aes128Ctr, 68),
        Arguments.of("Aes256Ctr, 0 bytes", PubSubSecurityPolicy.Aes256Ctr, 0),
        Arguments.of("Aes256Ctr, 67 bytes", PubSubSecurityPolicy.Aes256Ctr, 67),
        Arguments.of("Aes256Ctr, 69 bytes", PubSubSecurityPolicy.Aes256Ctr, 69),
        Arguments.of("Aes256Ctr, 52 bytes (other policy's)", PubSubSecurityPolicy.Aes256Ctr, 52));
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("wrongKeyDataLengths")
  void splitRejectsWrongKeyDataLength(String label, PubSubSecurityPolicy policy, int length) {
    assertThrows(
        IllegalArgumentException.class,
        () -> SecurityKeyMaterial.of(policy, ByteString.of(new byte[length])));
  }

  @Test
  void splitRejectsNullByteString() {
    // A null-valued ByteString has length 0: rejected by the strict length check.
    assertThrows(
        IllegalArgumentException.class,
        () -> SecurityKeyMaterial.of(PubSubSecurityPolicy.Aes128Ctr, ByteString.NULL_VALUE));
  }

  // endregion

  // region parts factory

  @Test
  void partsFactoryValidatesEachPartLength() {
    byte[] signing32 = new byte[32];
    byte[] encrypting16 = new byte[16];
    byte[] encrypting32 = new byte[32];
    byte[] nonce4 = new byte[4];

    assertThrows(
        IllegalArgumentException.class,
        () ->
            SecurityKeyMaterial.of(
                PubSubSecurityPolicy.Aes128Ctr, new byte[31], encrypting16, nonce4));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            SecurityKeyMaterial.of(
                PubSubSecurityPolicy.Aes128Ctr, new byte[33], encrypting16, nonce4));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            SecurityKeyMaterial.of(
                PubSubSecurityPolicy.Aes128Ctr, signing32, new byte[15], nonce4));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            SecurityKeyMaterial.of(
                PubSubSecurityPolicy.Aes128Ctr, signing32, new byte[17], nonce4));
    // The other policy's encrypting key length is rejected too: the policy pins 16 vs 32.
    assertThrows(
        IllegalArgumentException.class,
        () ->
            SecurityKeyMaterial.of(
                PubSubSecurityPolicy.Aes128Ctr, signing32, encrypting32, nonce4));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            SecurityKeyMaterial.of(
                PubSubSecurityPolicy.Aes256Ctr, signing32, encrypting16, nonce4));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            SecurityKeyMaterial.of(
                PubSubSecurityPolicy.Aes128Ctr, signing32, encrypting16, new byte[3]));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            SecurityKeyMaterial.of(
                PubSubSecurityPolicy.Aes128Ctr, signing32, encrypting16, new byte[5]));
  }

  @Test
  void partsFactoryCopiesItsInputs() {
    byte[] signingKey = pattern(0x00, 32);
    byte[] encryptingKey = pattern(0x20, 16);
    byte[] keyNonce = pattern(0x30, 4);

    SecurityKeyMaterial material =
        SecurityKeyMaterial.of(PubSubSecurityPolicy.Aes128Ctr, signingKey, encryptingKey, keyNonce);

    Arrays.fill(signingKey, (byte) 0);
    Arrays.fill(encryptingKey, (byte) 0);
    Arrays.fill(keyNonce, (byte) 0);

    assertArrayEquals(pattern(0x00, 32), material.getSigningKey());
    assertArrayEquals(pattern(0x20, 16), material.getEncryptingKey());
    assertArrayEquals(pattern(0x30, 4), material.getKeyNonce());
  }

  // endregion

  // region destroy semantics

  @Test
  void accessorsThrowAfterDestroy() {
    SecurityKeyMaterial material =
        SecurityKeyMaterial.of(PubSubSecurityPolicy.Aes128Ctr, patternKeyData(52));

    assertFalse(material.isDestroyed());
    material.destroy();
    assertTrue(material.isDestroyed());

    assertThrows(IllegalStateException.class, material::getSigningKey);
    assertThrows(IllegalStateException.class, material::getEncryptingKey);
    assertThrows(IllegalStateException.class, material::getKeyNonce);

    // The policy is not a key part and stays accessible.
    assertEquals(PubSubSecurityPolicy.Aes128Ctr, material.getPolicy());
  }

  @Test
  void destroyIsIdempotent() {
    SecurityKeyMaterial material =
        SecurityKeyMaterial.of(PubSubSecurityPolicy.Aes256Ctr, patternKeyData(68));

    material.destroy();
    material.destroy();

    assertTrue(material.isDestroyed());
    assertThrows(IllegalStateException.class, material::getSigningKey);
  }

  @Test
  void destroyZeroizesTheBorrowedArrays() {
    SecurityKeyMaterial material =
        SecurityKeyMaterial.of(PubSubSecurityPolicy.Aes128Ctr, patternKeyData(52));

    // The accessors return borrowed references to the internal arrays; destroy() wipes those
    // same arrays, observable through the borrow.
    byte[] signingKey = material.getSigningKey();
    byte[] encryptingKey = material.getEncryptingKey();
    byte[] keyNonce = material.getKeyNonce();

    material.destroy();

    assertArrayEquals(new byte[32], signingKey);
    assertArrayEquals(new byte[16], encryptingKey);
    assertArrayEquals(new byte[4], keyNonce);
  }

  @Test
  void toStringNeverContainsKeyBytes() {
    SecurityKeyMaterial material =
        SecurityKeyMaterial.of(PubSubSecurityPolicy.Aes128Ctr, patternKeyData(52));

    assertEquals("SecurityKeyMaterial{policy=Aes128Ctr, destroyed=false}", material.toString());

    material.destroy();

    assertEquals("SecurityKeyMaterial{policy=Aes128Ctr, destroyed=true}", material.toString());
  }

  // endregion

  // region helpers

  /** Key data of {@code length} bytes with values 0x00, 0x01, ... — offsets are self-evident. */
  private static ByteString patternKeyData(int length) {
    return ByteString.of(pattern(0x00, length));
  }

  private static byte[] pattern(int firstValue, int length) {
    byte[] bytes = new byte[length];
    for (int i = 0; i < length; i++) {
      bytes[i] = (byte) (firstValue + i);
    }
    return bytes;
  }

  // endregion
}
