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

import java.util.Arrays;
import javax.security.auth.Destroyable;
import org.eclipse.milo.opcua.stack.core.types.builtin.ByteString;

/**
 * The split key material for one security token: the {@code SigningKey}, {@code EncryptingKey}, and
 * {@code KeyNonce} parts of one key data blob (OPC UA Part 14 §7.2.4.4.3.1 Table 155).
 *
 * <p>Create instances by splitting a {@link SecurityKeySet} key via {@link
 * #of(PubSubSecurityPolicy, ByteString)}; splitting validates the key data length strictly against
 * the policy's parameter table (52 bytes for {@link PubSubSecurityPolicy#Aes128Ctr}, 68 bytes for
 * {@link PubSubSecurityPolicy#Aes256Ctr}) — there is no further key derivation.
 *
 * <p><b>Ownership and zeroization.</b> This is the mutable working copy of key material actually
 * used for cryptographic operations, and the only wipeable representation of it. The accessors
 * return the internal arrays without copying: they are borrowed references — callers shall not
 * modify them and shall not retain them beyond the owner's lifetime. The owner (the key manager
 * holding the token window) should call {@link #destroy()} when the token leaves its retention
 * window; accessing key parts after {@code destroy()} throws {@link IllegalStateException}, and the
 * owner must not destroy material while a codec operation borrowing it is in flight. Zeroization on
 * the JVM is best-effort defense in depth only: the garbage collector may already have copied the
 * bytes, and the immutable {@link ByteString} this was split from is never wiped.
 *
 * <p>Equality is identity; {@link #toString()} never includes key bytes.
 */
public final class SecurityKeyMaterial implements Destroyable {

  private final PubSubSecurityPolicy policy;
  private final byte[] signingKey;
  private final byte[] encryptingKey;
  private final byte[] keyNonce;

  private volatile boolean destroyed = false;

  private SecurityKeyMaterial(
      PubSubSecurityPolicy policy, byte[] signingKey, byte[] encryptingKey, byte[] keyNonce) {

    this.policy = policy;
    this.signingKey = signingKey;
    this.encryptingKey = encryptingKey;
    this.keyNonce = keyNonce;
  }

  /**
   * Get the {@link PubSubSecurityPolicy} this key material is for.
   *
   * @return the {@link PubSubSecurityPolicy}.
   */
  public PubSubSecurityPolicy getPolicy() {
    return policy;
  }

  /**
   * Get the SigningKey part of the key data.
   *
   * @return the SigningKey bytes; a borrowed reference to the internal array, do not modify.
   * @throws IllegalStateException if this material has been destroyed.
   */
  public byte[] getSigningKey() {
    checkNotDestroyed();
    return signingKey;
  }

  /**
   * Get the EncryptingKey part of the key data.
   *
   * @return the EncryptingKey bytes; a borrowed reference to the internal array, do not modify.
   * @throws IllegalStateException if this material has been destroyed.
   */
  public byte[] getEncryptingKey() {
    checkNotDestroyed();
    return encryptingKey;
  }

  /**
   * Get the KeyNonce part of the key data.
   *
   * @return the KeyNonce bytes; a borrowed reference to the internal array, do not modify.
   * @throws IllegalStateException if this material has been destroyed.
   */
  public byte[] getKeyNonce() {
    checkNotDestroyed();
    return keyNonce;
  }

  /**
   * Best-effort wipe of the key part arrays.
   *
   * <p>Idempotent; subsequent key part access throws {@link IllegalStateException}.
   */
  @Override
  public void destroy() {
    destroyed = true;
    Arrays.fill(signingKey, (byte) 0);
    Arrays.fill(encryptingKey, (byte) 0);
    Arrays.fill(keyNonce, (byte) 0);
  }

  @Override
  public boolean isDestroyed() {
    return destroyed;
  }

  @Override
  public String toString() {
    return "SecurityKeyMaterial{policy=" + policy + ", destroyed=" + destroyed + "}";
  }

  private void checkNotDestroyed() {
    if (destroyed) {
      throw new IllegalStateException("key material has been destroyed");
    }
  }

  /**
   * Split one key data blob into its SigningKey, EncryptingKey, and KeyNonce parts (Part 14
   * §7.2.4.4.3.1 Table 155), copying each part out of {@code keyData}.
   *
   * @param policy the {@link PubSubSecurityPolicy} defining the part lengths.
   * @param keyData the key data, e.g. an element of {@link SecurityKeySet#keys()}.
   * @return the split {@link SecurityKeyMaterial}.
   * @throws IllegalArgumentException if {@code keyData} is null-valued or its length is not exactly
   *     {@link PubSubSecurityPolicy#getKeyDataLength()}.
   */
  public static SecurityKeyMaterial of(PubSubSecurityPolicy policy, ByteString keyData) {
    if (keyData.length() != policy.getKeyDataLength()) {
      throw new IllegalArgumentException(
          "key data for %s must be exactly %d bytes, got %d"
              .formatted(policy, policy.getKeyDataLength(), keyData.length()));
    }
    byte[] bytes = keyData.bytesOrEmpty();

    int signingKeyLength = policy.getSigningKeyLength();
    int encryptingKeyLength = policy.getEncryptingKeyLength();
    int keyNonceLength = policy.getKeyNonceLength();

    byte[] signingKey = Arrays.copyOfRange(bytes, 0, signingKeyLength);
    byte[] encryptingKey =
        Arrays.copyOfRange(bytes, signingKeyLength, signingKeyLength + encryptingKeyLength);
    byte[] keyNonce =
        Arrays.copyOfRange(
            bytes,
            signingKeyLength + encryptingKeyLength,
            signingKeyLength + encryptingKeyLength + keyNonceLength);

    return new SecurityKeyMaterial(policy, signingKey, encryptingKey, keyNonce);
  }

  /**
   * Create {@link SecurityKeyMaterial} from already-split parts, copying each part.
   *
   * @param policy the {@link PubSubSecurityPolicy} defining the part lengths.
   * @param signingKey the SigningKey part.
   * @param encryptingKey the EncryptingKey part.
   * @param keyNonce the KeyNonce part.
   * @return the {@link SecurityKeyMaterial}.
   * @throws IllegalArgumentException if any part's length does not match the policy's parameter
   *     table.
   */
  public static SecurityKeyMaterial of(
      PubSubSecurityPolicy policy, byte[] signingKey, byte[] encryptingKey, byte[] keyNonce) {

    if (signingKey.length != policy.getSigningKeyLength()) {
      throw new IllegalArgumentException(
          "signingKey for %s must be exactly %d bytes, got %d"
              .formatted(policy, policy.getSigningKeyLength(), signingKey.length));
    }
    if (encryptingKey.length != policy.getEncryptingKeyLength()) {
      throw new IllegalArgumentException(
          "encryptingKey for %s must be exactly %d bytes, got %d"
              .formatted(policy, policy.getEncryptingKeyLength(), encryptingKey.length));
    }
    if (keyNonce.length != policy.getKeyNonceLength()) {
      throw new IllegalArgumentException(
          "keyNonce for %s must be exactly %d bytes, got %d"
              .formatted(policy, policy.getKeyNonceLength(), keyNonce.length));
    }

    return new SecurityKeyMaterial(
        policy, signingKey.clone(), encryptingKey.clone(), keyNonce.clone());
  }
}
