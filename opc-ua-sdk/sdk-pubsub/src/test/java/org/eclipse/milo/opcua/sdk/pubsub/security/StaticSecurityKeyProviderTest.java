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
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.eclipse.milo.opcua.stack.core.types.builtin.ByteString;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * {@link StaticSecurityKeyProvider}: the static-key provisioning form (firstTokenId 1, {@link
 * Duration#ZERO} durations, request parameters ignored), strict 52/68-byte blob validation, and the
 * S2OPC/OPC Labs {@code keyPartsDirectory} file layout with policy inference by encrypting key
 * length (16 → Aes128Ctr, 32 → Aes256Ctr — the OPC Labs selects-by-key-size convention).
 */
class StaticSecurityKeyProviderTest {

  private static final byte[] SIGNING_KEY_32 = pattern(0x00, 32);
  private static final byte[] ENCRYPT_KEY_16 = pattern(0x20, 16);
  private static final byte[] ENCRYPT_KEY_32 = pattern(0x20, 32);
  private static final byte[] KEY_NONCE_4 = pattern(0x60, 4);

  // region of(...)

  @Test
  void ofServesTheStaticKeyForm() throws Exception {
    ByteString keyData = ByteString.of(pattern(0x00, 52));

    StaticSecurityKeyProvider provider =
        StaticSecurityKeyProvider.of(PubSubSecurityPolicy.Aes128Ctr, keyData);

    SecurityKeySet keySet = getKeys(provider, "any-group");

    assertEquals(PubSubSecurityPolicy.Aes128Ctr.getUri(), keySet.securityPolicyUri());
    assertEquals(uint(1), keySet.firstTokenId());
    assertEquals(List.of(keyData), keySet.keys());
    // ZERO/ZERO = no key switch ever scheduled, keys never expire (the static form).
    assertEquals(Duration.ZERO, keySet.timeToNextKey());
    assertEquals(Duration.ZERO, keySet.keyLifetime());
  }

  @Test
  void ofKeepsKeyOrderForConsecutiveTokenIds() throws Exception {
    ByteString key1 = ByteString.of(pattern(0x00, 68));
    ByteString key2 = ByteString.of(pattern(0x10, 68));
    ByteString key3 = ByteString.of(pattern(0x20, 68));

    StaticSecurityKeyProvider provider =
        StaticSecurityKeyProvider.of(PubSubSecurityPolicy.Aes256Ctr, key1, key2, key3);

    SecurityKeySet keySet = getKeys(provider, "g");

    // Tokens are consecutive in argument order starting at 1: key1=token 1, key2=2, key3=3.
    assertEquals(uint(1), keySet.firstTokenId());
    assertEquals(List.of(key1, key2, key3), keySet.keys());
  }

  @Test
  void ofRejectsNoKeyData() {
    assertThrows(
        IllegalArgumentException.class,
        () -> StaticSecurityKeyProvider.of(PubSubSecurityPolicy.Aes128Ctr));
  }

  @Test
  void ofRejectsWrongLengthBlobs() {
    for (int length : new int[] {0, 51, 53, 68}) {
      ByteString keyData = ByteString.of(new byte[length]);
      assertThrows(
          IllegalArgumentException.class,
          () -> StaticSecurityKeyProvider.of(PubSubSecurityPolicy.Aes128Ctr, keyData),
          "Aes128Ctr blob length " + length);
    }
    for (int length : new int[] {0, 52, 67, 69}) {
      ByteString keyData = ByteString.of(new byte[length]);
      assertThrows(
          IllegalArgumentException.class,
          () -> StaticSecurityKeyProvider.of(PubSubSecurityPolicy.Aes256Ctr, keyData),
          "Aes256Ctr blob length " + length);
    }
  }

  @Test
  void ofRejectsAnyWrongBlobAmongMany() {
    ByteString good = ByteString.of(new byte[52]);
    ByteString bad = ByteString.of(new byte[51]);

    assertThrows(
        IllegalArgumentException.class,
        () -> StaticSecurityKeyProvider.of(PubSubSecurityPolicy.Aes128Ctr, good, bad));
  }

  @Test
  void getKeysIgnoresItsRequestParameters() throws Exception {
    StaticSecurityKeyProvider provider =
        StaticSecurityKeyProvider.of(
            PubSubSecurityPolicy.Aes128Ctr, ByteString.of(pattern(0x00, 52)));

    SecurityKeySet first = getKeys(provider, "group-a", 1, 0);
    SecurityKeySet second = getKeys(provider, "group-b", 99, 7);

    // securityGroupId, startingTokenId, and requestedKeyCount are documented as ignored:
    // the same key set comes back regardless.
    assertEquals(first, second);
  }

  // endregion

  // region fromKeyFileDirectory (S2OPC layout)

  @Test
  void directoryWith16ByteEncryptKeyInfersAes128Ctr(@TempDir Path directory) throws Exception {
    writeKeyFiles(directory, SIGNING_KEY_32, ENCRYPT_KEY_16, KEY_NONCE_4);

    StaticSecurityKeyProvider provider = StaticSecurityKeyProvider.fromKeyFileDirectory(directory);

    SecurityKeySet keySet = getKeys(provider, "g");

    assertEquals(PubSubSecurityPolicy.Aes128Ctr.getUri(), keySet.securityPolicyUri());
    assertEquals(uint(1), keySet.firstTokenId());
    assertEquals(Duration.ZERO, keySet.timeToNextKey());
    assertEquals(Duration.ZERO, keySet.keyLifetime());

    // The single key is the Table 155 concatenation of the three files, in file-role order.
    assertEquals(
        List.of(ByteString.of(concat(SIGNING_KEY_32, ENCRYPT_KEY_16, KEY_NONCE_4))), keySet.keys());
  }

  @Test
  void directoryWith32ByteEncryptKeyInfersAes256Ctr(@TempDir Path directory) throws Exception {
    writeKeyFiles(directory, SIGNING_KEY_32, ENCRYPT_KEY_32, KEY_NONCE_4);

    StaticSecurityKeyProvider provider = StaticSecurityKeyProvider.fromKeyFileDirectory(directory);

    SecurityKeySet keySet = getKeys(provider, "g");

    assertEquals(PubSubSecurityPolicy.Aes256Ctr.getUri(), keySet.securityPolicyUri());
    assertEquals(
        List.of(ByteString.of(concat(SIGNING_KEY_32, ENCRYPT_KEY_32, KEY_NONCE_4))), keySet.keys());
  }

  @Test
  void directoryRejectsEncryptKeyLengthsThatSelectNoPolicy(@TempDir Path directory)
      throws Exception {
    for (int length : new int[] {0, 15, 17, 31, 33}) {
      writeKeyFiles(directory, SIGNING_KEY_32, new byte[length], KEY_NONCE_4);
      assertThrows(
          IllegalArgumentException.class,
          () -> StaticSecurityKeyProvider.fromKeyFileDirectory(directory),
          "encryptKey.key length " + length);
    }
  }

  @Test
  void directoryRejectsWrongSigningKeyLength(@TempDir Path directory) throws Exception {
    for (int length : new int[] {0, 31, 33}) {
      writeKeyFiles(directory, new byte[length], ENCRYPT_KEY_16, KEY_NONCE_4);
      assertThrows(
          IllegalArgumentException.class,
          () -> StaticSecurityKeyProvider.fromKeyFileDirectory(directory),
          "signingKey.key length " + length);
    }
  }

  @Test
  void directoryRejectsWrongKeyNonceLength(@TempDir Path directory) throws Exception {
    for (int length : new int[] {0, 3, 5}) {
      writeKeyFiles(directory, SIGNING_KEY_32, ENCRYPT_KEY_16, new byte[length]);
      assertThrows(
          IllegalArgumentException.class,
          () -> StaticSecurityKeyProvider.fromKeyFileDirectory(directory),
          "keyNonce.key length " + length);
    }
  }

  @Test
  void directoryMissingAnyKeyFileIsAnIoException(@TempDir Path directory) throws Exception {
    // signingKey.key missing entirely.
    Files.write(directory.resolve("encryptKey.key"), ENCRYPT_KEY_16);
    Files.write(directory.resolve("keyNonce.key"), KEY_NONCE_4);

    assertThrows(
        IOException.class, () -> StaticSecurityKeyProvider.fromKeyFileDirectory(directory));
  }

  // endregion

  // region helpers

  private static void writeKeyFiles(
      Path directory, byte[] signingKey, byte[] encryptKey, byte[] keyNonce) throws IOException {
    Files.write(directory.resolve("signingKey.key"), signingKey);
    Files.write(directory.resolve("encryptKey.key"), encryptKey);
    Files.write(directory.resolve("keyNonce.key"), keyNonce);
  }

  private static SecurityKeySet getKeys(StaticSecurityKeyProvider provider, String groupId)
      throws Exception {
    return getKeys(provider, groupId, 0, 0);
  }

  private static SecurityKeySet getKeys(
      StaticSecurityKeyProvider provider, String groupId, int startingTokenId, int requestedCount)
      throws Exception {

    return provider
        .getKeys(groupId, uint(startingTokenId), uint(requestedCount))
        .get(10, TimeUnit.SECONDS);
  }

  private static byte[] pattern(int firstValue, int length) {
    byte[] bytes = new byte[length];
    for (int i = 0; i < length; i++) {
      bytes[i] = (byte) (firstValue + i);
    }
    return bytes;
  }

  private static byte[] concat(byte[]... parts) {
    int length = 0;
    for (byte[] part : parts) {
      length += part.length;
    }
    byte[] bytes = new byte[length];
    int offset = 0;
    for (byte[] part : parts) {
      System.arraycopy(part, 0, bytes, offset, part.length);
      offset += part.length;
    }
    return bytes;
  }

  // endregion
}
