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

import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import java.util.Arrays;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Crypto-primitive vectors for {@link UadpMessageSecurity} against PUBLISHED test vectors: the
 * AES-CTR payload transform against RFC 3686 §6, and HMAC-SHA-256 sign/verify against RFC 4231 §4.
 *
 * <p><b>RFC 3686 → Part 14 Table 157 mapping.</b> RFC 3686 defines the AES-CTR counter block as
 * {@code Nonce(4) || IV(8) || BlockCounter(4)} with the block counter a big-endian UInt32 starting
 * at 1 for the first block. Part 14 Table 157 defines it as {@code KeyNonce(4) || MessageNonce(8)
 * || 0x00000001} — the identical construction. So each RFC vector maps directly: RFC AES Key ↦
 * EncryptingKey, RFC Nonce ↦ KeyNonce, RFC IV ↦ MessageNonce, and the RFC ciphertext applies
 * byte-for-byte. ({@code applyCtr} treats the 8 MessageNonce bytes as opaque — the Part 14 Table
 * 156 Random[4]||UInt32-LE composition, pinned separately below, does not constrain this mapping.)
 * The single-block vectors only pass if the block counter starts at 1; the multi-block vectors pin
 * the big-endian counter increment; the 36-byte vectors pin the partial final block.
 *
 * <p><b>RFC 4231 → 32-byte SigningKey mapping.</b> Our signing keys are exactly 32 bytes (Table
 * 155), while the RFC 4231 keys are 20/4/25/131 bytes. HMAC-SHA-256 normalizes every key to the
 * 64-byte SHA-256 block: keys shorter than 64 bytes are right-padded with zeros, keys longer are
 * replaced by SHA-256(key) (32 bytes) first (RFC 2104 §2). Therefore zero-padding a short RFC key
 * to 32 bytes, or supplying SHA-256 of the 131-byte key directly, yields the identical MAC — the
 * expected digests below are the RFC's own, unchanged. (Independently recomputed with Python
 * hmac/hashlib + the cryptography AES-CTR before inlining.)
 */
class UadpMessageSecurityTest {

  // region RFC 3686 AES-CTR vectors

  /**
   * RFC 3686 §6 vectors, remapped per the class doc. AES-192 vectors (#4-#6) are skipped: no PubSub
   * policy uses AES-192 (Table 155 defines only 16- and 32-byte encrypting keys).
   */
  static Stream<Arguments> rfc3686Vectors() {
    // "Single block msg"
    String pt16 = "53696e676c6520626c6f636b206d7367";
    String pt32 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    String pt36 = pt32 + "20212223";

    return Stream.of(
        Arguments.of(
            "TV#1 AES-128, 16 octets (single block)",
            PubSubSecurityPolicy.Aes128Ctr,
            "ae6852f8121067cc4bf7a5765577f39e", // RFC AES Key ↦ EncryptingKey
            "00000030", // RFC Nonce ↦ KeyNonce
            "0000000000000000", // RFC IV ↦ MessageNonce
            pt16,
            "e4095d4fb7a7b3792d6175a3261311b8"),
        Arguments.of(
            "TV#2 AES-128, 32 octets (two blocks)",
            PubSubSecurityPolicy.Aes128Ctr,
            "7e24067817fae0d743d6ce1f32539163",
            "006cb6db",
            "c0543b59da48d90b",
            pt32,
            "5104a106168a72d9790d41ee8edad388eb2e1efc46da57c8fce630df9141be28"),
        Arguments.of(
            "TV#3 AES-128, 36 octets (partial final block)",
            PubSubSecurityPolicy.Aes128Ctr,
            "7691be035e5020a8ac6e618529f9a0dc",
            "00e0017b",
            "27777f3f4a1786f0",
            pt36,
            "c1cf48a89f2ffdd9cf4652e9efdb72d74540a42bde6d7836d59a5ceaaef3105325b2072f"),
        Arguments.of(
            "TV#7 AES-256, 16 octets (single block)",
            PubSubSecurityPolicy.Aes256Ctr,
            "776beff2851db06f4c8a0542c8696f6c6a81af1eec96b4d37fc1d689e6c1c104",
            "00000060",
            "db5672c97aa8f0b2",
            pt16,
            "145ad01dbf824ec7560863dc71e3e0c0"),
        Arguments.of(
            "TV#8 AES-256, 32 octets (two blocks)",
            PubSubSecurityPolicy.Aes256Ctr,
            "f6d66d6bd52d59bb0796365879eff886c66dd51a5b6a99744b50590c87a23884",
            "00faac24",
            "c1585ef15a43d875",
            pt32,
            "f05e231b3894612c49ee000b804eb2a9b8306b508f839d6a5530831d9344af1c"),
        Arguments.of(
            "TV#9 AES-256, 36 octets (partial final block)",
            PubSubSecurityPolicy.Aes256Ctr,
            "ff7a617ce69148e4f1726e2f43581de2aa62d9f805532edff1eed687fb54153d",
            "001cc5b7",
            "51a51d70a1c11148",
            pt36,
            "eb6c52821d0bbbf7ce7594462aca4faab407df866569fd07f48cc0b583d6071f1ec0e6b8"));
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("rfc3686Vectors")
  void applyCtrMatchesRfc3686Vector(
      String label,
      PubSubSecurityPolicy policy,
      String keyHex,
      String keyNonceHex,
      String messageNonceHex,
      String plaintextHex,
      String ciphertextHex)
      throws Exception {

    SecurityKeyMaterial keyMaterial =
        SecurityKeyMaterial.of(
            policy,
            new byte[policy.getSigningKeyLength()], // unused by applyCtr
            hex(keyHex),
            hex(keyNonceHex));
    byte[] messageNonce = hex(messageNonceHex);
    byte[] plaintext = hex(plaintextHex);
    byte[] expectedCiphertext = hex(ciphertextHex);

    // The region sits between guard bytes: applyCtr is index/length-addressed and must
    // transform exactly [index, index + length) without touching its surroundings.
    byte[] prefix = {0x55, 0x55, 0x55};
    byte[] suffix = {0x66, 0x66};
    ByteBuf buffer = Unpooled.buffer();
    buffer.writeBytes(prefix).writeBytes(plaintext).writeBytes(suffix);
    int readerIndex = buffer.readerIndex();
    int writerIndex = buffer.writerIndex();

    UadpMessageSecurity.applyCtr(
        keyMaterial, messageNonce, buffer, prefix.length, plaintext.length);

    byte[] region = new byte[plaintext.length];
    buffer.getBytes(prefix.length, region);
    assertArrayEquals(expectedCiphertext, region);

    byte[] guards = new byte[prefix.length];
    buffer.getBytes(0, guards);
    assertArrayEquals(prefix, guards);
    byte[] tail = new byte[suffix.length];
    buffer.getBytes(prefix.length + plaintext.length, tail);
    assertArrayEquals(suffix, tail);

    // applyCtr never moves reader/writer indices (class contract).
    assertEquals(readerIndex, buffer.readerIndex());
    assertEquals(writerIndex, buffer.writerIndex());

    // CTR is symmetric: the same call on the ciphertext region restores the plaintext.
    UadpMessageSecurity.applyCtr(
        keyMaterial, messageNonce, buffer, prefix.length, plaintext.length);
    buffer.getBytes(prefix.length, region);
    assertArrayEquals(plaintext, region);

    buffer.release();
  }

  @Test
  void applyCtrRejectsWrongMessageNonceLength() {
    SecurityKeyMaterial keyMaterial =
        SecurityKeyMaterial.of(
            PubSubSecurityPolicy.Aes128Ctr, new byte[32], new byte[16], new byte[4]);
    ByteBuf buffer = Unpooled.wrappedBuffer(new byte[16]);

    for (int nonceLength : new int[] {0, 7, 9}) {
      byte[] messageNonce = new byte[nonceLength];
      assertThrows(
          IllegalArgumentException.class,
          () -> UadpMessageSecurity.applyCtr(keyMaterial, messageNonce, buffer, 0, 16),
          "nonce length " + nonceLength);
    }

    buffer.release();
  }

  // endregion

  // region RFC 4231 HMAC-SHA-256 vectors

  /**
   * RFC 4231 §4 test cases 1-4 with the keys zero-padded to our 32-byte SigningKey length, plus
   * test case 6's 131-byte key hashed down to SHA-256(key) — both MAC-preserving per the class doc.
   * Test case 5 (truncated output) does not apply: Part 14 signatures are always the full 32 bytes.
   */
  static Stream<Arguments> rfc4231Vectors() {
    // Test case 1: key = 0x0b * 20, data = "Hi There".
    byte[] key1 = new byte[32];
    Arrays.fill(key1, 0, 20, (byte) 0x0b);

    // Test case 2: key = "Jefe", data = "what do ya want for nothing?".
    byte[] key2 = Arrays.copyOf("Jefe".getBytes(US_ASCII), 32);

    // Test case 3: key = 0xaa * 20, data = 0xdd * 50.
    byte[] key3 = new byte[32];
    Arrays.fill(key3, 0, 20, (byte) 0xaa);
    byte[] data3 = new byte[50];
    Arrays.fill(data3, (byte) 0xdd);

    // Test case 4: key = 0x01..0x19 (25 bytes), data = 0xcd * 50.
    byte[] key4 = new byte[32];
    for (int i = 0; i < 25; i++) {
      key4[i] = (byte) (i + 1);
    }
    byte[] data4 = new byte[50];
    Arrays.fill(data4, (byte) 0xcd);

    // Test case 6: key = 0xaa * 131 (> the 64-byte SHA-256 block), so HMAC uses
    // SHA-256(key) as the effective key; SHA-256(0xaa * 131) is exactly 32 bytes.
    byte[] key6 = hex("45ad4b37c6e2fc0a2cfcc1b5da524132ec707615c2cae1dbbc43c97aa521db81");

    return Stream.of(
        Arguments.of(
            "TC1 20-byte key, zero-padded",
            key1,
            "Hi There".getBytes(US_ASCII),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
        Arguments.of(
            "TC2 4-byte key, zero-padded",
            key2,
            "what do ya want for nothing?".getBytes(US_ASCII),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
        Arguments.of(
            "TC3 20-byte key, zero-padded",
            key3,
            data3,
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"),
        Arguments.of(
            "TC4 25-byte key, zero-padded",
            key4,
            data4,
            "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"),
        Arguments.of(
            "TC6 131-byte key, hashed to 32 bytes",
            key6,
            "Test Using Larger Than Block-Size Key - Hash Key First".getBytes(US_ASCII),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"));
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("rfc4231Vectors")
  void signMatchesRfc4231VectorAndVerifyAccepts(
      String label, byte[] signingKey, byte[] data, String expectedHmacHex) throws Exception {

    SecurityKeyMaterial keyMaterial = keyMaterial(signingKey);
    byte[] expected = hex(expectedHmacHex);

    // The signed region sits between guard bytes: sign covers exactly [index, index + length).
    byte[] prefix = {0x11, 0x22};
    ByteBuf buffer = Unpooled.buffer();
    buffer.writeBytes(prefix).writeBytes(data).writeByte(0x33);

    byte[] signature = UadpMessageSecurity.sign(keyMaterial, buffer, prefix.length, data.length);

    assertArrayEquals(expected, signature);
    assertTrue(
        UadpMessageSecurity.verify(keyMaterial, buffer, prefix.length, data.length, expected));

    buffer.release();
  }

  @Test
  void verifyIsFalseOnFlippedDataBit() throws Exception {
    SecurityKeyMaterial keyMaterial = keyMaterial(sequentialBytes(32));
    byte[] data = "payload under test".getBytes(US_ASCII);
    ByteBuf buffer = Unpooled.wrappedBuffer(data);

    byte[] signature = UadpMessageSecurity.sign(keyMaterial, buffer, 0, data.length);
    assertTrue(UadpMessageSecurity.verify(keyMaterial, buffer, 0, data.length, signature));

    buffer.setByte(3, buffer.getByte(3) ^ 0x01); // flip one bit in the signed region

    assertFalse(UadpMessageSecurity.verify(keyMaterial, buffer, 0, data.length, signature));
    buffer.release();
  }

  @Test
  void verifyIsFalseOnFlippedSignatureBit() throws Exception {
    SecurityKeyMaterial keyMaterial = keyMaterial(sequentialBytes(32));
    byte[] data = "payload under test".getBytes(US_ASCII);
    ByteBuf buffer = Unpooled.wrappedBuffer(data);

    byte[] signature = UadpMessageSecurity.sign(keyMaterial, buffer, 0, data.length);
    signature[31] ^= (byte) 0x80; // flip one bit in the signature

    assertFalse(UadpMessageSecurity.verify(keyMaterial, buffer, 0, data.length, signature));
    buffer.release();
  }

  @Test
  void verifyIsFalseOnTruncatedSignature() throws Exception {
    SecurityKeyMaterial keyMaterial = keyMaterial(sequentialBytes(32));
    byte[] data = "payload under test".getBytes(US_ASCII);
    ByteBuf buffer = Unpooled.wrappedBuffer(data);

    byte[] signature = UadpMessageSecurity.sign(keyMaterial, buffer, 0, data.length);

    // A false result, not an exception: §7.2.4.4.3.2 receivers drop and count. Length
    // mismatches short-circuiting to false (rather than throwing) is the MessageDigest.isEqual
    // contract verify delegates to.
    byte[] truncated = Arrays.copyOf(signature, 31);
    assertFalse(UadpMessageSecurity.verify(keyMaterial, buffer, 0, data.length, truncated));
    assertFalse(UadpMessageSecurity.verify(keyMaterial, buffer, 0, data.length, new byte[0]));

    buffer.release();
  }

  /**
   * The comparison verify uses is {@code MessageDigest.isEqual} (the constant-time compare; the
   * timing property itself is a JDK guarantee and is not assertable from a test). The structural
   * consequences pinned here: content equality on a fresh array is accepted (not identity
   * comparison), a correct 32-byte prefix with trailing junk is rejected (not prefix comparison),
   * and no length mismatch throws.
   */
  @Test
  void verifyComparesContentNotIdentity() throws Exception {
    SecurityKeyMaterial keyMaterial = keyMaterial(sequentialBytes(32));
    byte[] data = "payload under test".getBytes(US_ASCII);
    ByteBuf buffer = Unpooled.wrappedBuffer(data);

    byte[] signature = UadpMessageSecurity.sign(keyMaterial, buffer, 0, data.length);
    byte[] freshCopy = signature.clone();
    assertNotSame(signature, freshCopy);
    assertTrue(UadpMessageSecurity.verify(keyMaterial, buffer, 0, data.length, freshCopy));

    byte[] extended = Arrays.copyOf(signature, 33); // correct prefix + one junk byte
    extended[32] = (byte) 0xFF;
    assertFalse(UadpMessageSecurity.verify(keyMaterial, buffer, 0, data.length, extended));

    buffer.release();
  }

  // endregion

  // region MessageNonce composition (Table 156)

  @Test
  void createMessageNonceIsRandomThenUInt32LittleEndian() {
    // Table 156: MessageNonce = Random[4] || NonceSequenceNumber, the sequence number a
    // UInt32 in little-endian byte order like any UADP UInt32.
    byte[] random = bytes(0xDE, 0xAD, 0xBE, 0xEF);

    assertArrayEquals(
        bytes(0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x00, 0x00, 0x00),
        UadpMessageSecurity.createMessageNonce(random, 1L));

    assertArrayEquals(
        bytes(0xDE, 0xAD, 0xBE, 0xEF, 0x78, 0x56, 0x34, 0x12),
        UadpMessageSecurity.createMessageNonce(random, 0x12345678L));

    assertArrayEquals(
        bytes(0xDE, 0xAD, 0xBE, 0xEF, 0xFF, 0xFF, 0xFF, 0xFF),
        UadpMessageSecurity.createMessageNonce(random, 0xFFFFFFFFL));
  }

  @Test
  void createMessageNonceRejectsWrongRandomLength() {
    for (int length : new int[] {0, 3, 5}) {
      byte[] random = new byte[length];
      assertThrows(
          IllegalArgumentException.class,
          () -> UadpMessageSecurity.createMessageNonce(random, 1L),
          "random length " + length);
    }
  }

  @Test
  void createMessageNonceRejectsSequenceNumberOutsideUInt32Range() {
    byte[] random = new byte[4];

    assertThrows(
        IllegalArgumentException.class, () -> UadpMessageSecurity.createMessageNonce(random, -1L));
    assertThrows(
        IllegalArgumentException.class,
        () -> UadpMessageSecurity.createMessageNonce(random, 0x1_0000_0000L));

    // The UInt32 boundaries themselves are accepted.
    assertArrayEquals(
        bytes(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00),
        UadpMessageSecurity.createMessageNonce(random, 0L));
  }

  // endregion

  // region helpers

  private static SecurityKeyMaterial keyMaterial(byte[] signingKey) {
    return SecurityKeyMaterial.of(
        PubSubSecurityPolicy.Aes128Ctr, signingKey, new byte[16], new byte[4]);
  }

  private static byte[] sequentialBytes(int length) {
    byte[] bytes = new byte[length];
    for (int i = 0; i < length; i++) {
      bytes[i] = (byte) i;
    }
    return bytes;
  }

  private static byte[] bytes(int... values) {
    byte[] bytes = new byte[values.length];
    for (int i = 0; i < values.length; i++) {
      bytes[i] = (byte) values[i];
    }
    return bytes;
  }

  private static byte[] hex(String hex) {
    byte[] bytes = new byte[hex.length() / 2];
    for (int i = 0; i < bytes.length; i++) {
      bytes[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  }

  // endregion
}
