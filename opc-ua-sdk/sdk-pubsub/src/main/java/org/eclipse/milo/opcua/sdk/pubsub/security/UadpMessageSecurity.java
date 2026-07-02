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

import io.netty.buffer.ByteBuf;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.eclipse.milo.opcua.stack.core.StatusCodes;
import org.eclipse.milo.opcua.stack.core.UaException;
import org.eclipse.milo.opcua.stack.core.util.SignatureUtil;

/**
 * Cryptographic primitives for UADP message security (OPC UA Part 14 §7.2.4.4.3): the AES-CTR
 * payload transform, HMAC signing/verification over NetworkMessage regions, and MessageNonce
 * composition.
 *
 * <p>These are stateless building blocks for the UADP codec's security paths. The Part 14 order of
 * operations they serve: on encode, encrypt the payload region in place, then sign the whole
 * NetworkMessage and append the signature; on decode, verify the trailing signature <b>before</b>
 * parsing the payload, then decrypt a copy of the payload region ("When a Subscriber or a Publisher
 * receives a NetworkMessage, it shall verify the signature before processing the payload. If
 * verification fails, it drops the NetworkMessage." — §7.2.4.4.3.2).
 *
 * <p>None of these methods move a buffer's reader or writer index; regions are addressed explicitly
 * by index and length.
 */
public final class UadpMessageSecurity {

  /** The AES block size in bytes; also the AES-CTR counter block size (Table 157). */
  private static final int COUNTER_BLOCK_SIZE = 16;

  /** The length of the random part of the MessageNonce (Table 156). */
  private static final int NONCE_RANDOM_LENGTH = 4;

  private UadpMessageSecurity() {}

  /**
   * Compose an 8-byte MessageNonce from its parts (Part 14 §7.2.4.4.3.2 Table 156): 4 random bytes
   * followed by a UInt32 sequence number in little-endian byte order, like any UADP UInt32.
   *
   * <p>The sequence number is per-key state owned by the publisher: reset to 1 each time the key
   * and SecurityTokenId are updated, incremented by exactly one per NetworkMessage. A (key, nonce)
   * pair must never repeat — see {@link MessageNonceSupplier}.
   *
   * @param random the random part; need not be cryptographically random (Table 156).
   * @param sequenceNumber the nonce sequence number, in UInt32 range.
   * @return the 8-byte MessageNonce.
   * @throws IllegalArgumentException if {@code random} is not exactly 4 bytes or {@code
   *     sequenceNumber} is outside UInt32 range.
   */
  public static byte[] createMessageNonce(byte[] random, long sequenceNumber) {
    if (random.length != NONCE_RANDOM_LENGTH) {
      throw new IllegalArgumentException(
          "random part must be exactly %d bytes, got %d"
              .formatted(NONCE_RANDOM_LENGTH, random.length));
    }
    if (sequenceNumber < 0L || sequenceNumber > 0xFFFFFFFFL) {
      throw new IllegalArgumentException(
          "sequenceNumber must be in UInt32 range, got " + sequenceNumber);
    }

    byte[] nonce = new byte[NONCE_RANDOM_LENGTH + 4];
    System.arraycopy(random, 0, nonce, 0, NONCE_RANDOM_LENGTH);
    nonce[4] = (byte) sequenceNumber;
    nonce[5] = (byte) (sequenceNumber >>> 8);
    nonce[6] = (byte) (sequenceNumber >>> 16);
    nonce[7] = (byte) (sequenceNumber >>> 24);
    return nonce;
  }

  /**
   * Apply the AES-CTR keystream to {@code length} bytes of {@code buffer} starting at {@code
   * index}, in place.
   *
   * <p>CTR is symmetric: the same call encrypts a plaintext region and decrypts a ciphertext
   * region, without changing its size. The counter block is {@code KeyNonce(4) || MessageNonce(8)
   * || BlockCounter(4)} with the block counter a big-endian UInt32 starting at 1 (Part 14 Table
   * 157, the RFC 3686 convention).
   *
   * <p>Decode-side callers must operate on a copy of the payload region, not the shared transport
   * buffer (the K5 decrypt-a-copy rule); encode-side callers own their output buffer and transform
   * it in place.
   *
   * @param keyMaterial the key material; supplies the EncryptingKey and KeyNonce.
   * @param messageNonce the 8-byte MessageNonce from the SecurityHeader.
   * @param buffer the buffer holding the region to transform.
   * @param index the index of the first byte of the region.
   * @param length the length of the region in bytes.
   * @throws IllegalArgumentException if {@code messageNonce} is not exactly the policy's
   *     MessageNonce length.
   * @throws UaException if the cipher operation fails.
   */
  public static void applyCtr(
      SecurityKeyMaterial keyMaterial, byte[] messageNonce, ByteBuf buffer, int index, int length)
      throws UaException {

    PubSubSecurityPolicy policy = keyMaterial.getPolicy();

    if (messageNonce.length != policy.getMessageNonceLength()) {
      throw new IllegalArgumentException(
          "messageNonce must be exactly %d bytes, got %d"
              .formatted(policy.getMessageNonceLength(), messageNonce.length));
    }

    byte[] keyNonce = keyMaterial.getKeyNonce();

    byte[] counterBlock = new byte[COUNTER_BLOCK_SIZE];
    System.arraycopy(keyNonce, 0, counterBlock, 0, keyNonce.length);
    System.arraycopy(messageNonce, 0, counterBlock, keyNonce.length, messageNonce.length);
    counterBlock[COUNTER_BLOCK_SIZE - 1] = 0x01; // block counter starts at 1, big-endian

    String transformation = policy.getSymmetricEncryptionAlgorithm().getTransformation();
    String keyAlgorithm = transformation.substring(0, transformation.indexOf('/'));

    byte[] scratch = new byte[length];
    buffer.getBytes(index, scratch);

    try {
      Cipher cipher = Cipher.getInstance(transformation);
      cipher.init(
          Cipher.ENCRYPT_MODE,
          new SecretKeySpec(keyMaterial.getEncryptingKey(), keyAlgorithm),
          new IvParameterSpec(counterBlock));

      byte[] transformed = cipher.doFinal(scratch);
      buffer.setBytes(index, transformed);
    } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
      throw new UaException(StatusCodes.Bad_InternalError, e);
    } catch (GeneralSecurityException e) {
      throw new UaException(StatusCodes.Bad_SecurityChecksFailed, e);
    } finally {
      Arrays.fill(scratch, (byte) 0);
    }
  }

  /**
   * Compute the NetworkMessage signature over {@code length} bytes of {@code buffer} starting at
   * {@code index}.
   *
   * <p>The signed region is the entire NetworkMessage including any encrypted data (Part 14
   * §7.2.4.4.3.2); the returned signature is appended after it and is not part of it.
   *
   * @param keyMaterial the key material; supplies the SigningKey.
   * @param buffer the buffer holding the signed region.
   * @param index the index of the first byte of the signed region.
   * @param length the length of the signed region in bytes.
   * @return the signature, {@link PubSubSecurityPolicy#getSignatureLength()} bytes.
   * @throws UaException if the MAC operation fails.
   */
  public static byte[] sign(SecurityKeyMaterial keyMaterial, ByteBuf buffer, int index, int length)
      throws UaException {

    return SignatureUtil.hmac(
        keyMaterial.getPolicy().getSymmetricSignatureAlgorithm(),
        keyMaterial.getSigningKey(),
        buffer.nioBuffer(index, length));
  }

  /**
   * Verify a NetworkMessage signature over {@code length} bytes of {@code buffer} starting at
   * {@code index}, in constant time.
   *
   * <p>A {@code false} result is not exceptional: per §7.2.4.4.3.2 the receiver drops the
   * NetworkMessage (and counts the drop).
   *
   * @param keyMaterial the key material; supplies the SigningKey.
   * @param buffer the buffer holding the signed region.
   * @param index the index of the first byte of the signed region.
   * @param length the length of the signed region in bytes.
   * @param signature the received signature, the trailing bytes of the NetworkMessage.
   * @return {@code true} if {@code signature} matches the computed signature.
   * @throws UaException if the MAC operation fails.
   */
  public static boolean verify(
      SecurityKeyMaterial keyMaterial, ByteBuf buffer, int index, int length, byte[] signature)
      throws UaException {

    byte[] computed = sign(keyMaterial, buffer, index, length);

    return MessageDigest.isEqual(computed, signature);
  }
}
