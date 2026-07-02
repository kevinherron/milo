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

import java.util.Optional;
import org.eclipse.milo.opcua.stack.core.security.SecurityAlgorithm;

/**
 * The SecurityPolicies applicable to PubSub message security, with the parameter table each policy
 * defines (OPC UA Part 7 profiles "SecurityPolicy PubSub"; OPC UA Part 14 §7.2.4.4.3).
 *
 * <p>Client/server SecurityPolicies (Basic256Sha256 et al.) do not apply to PubSub message
 * security, and PubSub policies are purely symmetric: key material arrives pre-formed from a
 * Security Key Service or a static provider as the Part 14 Table 155 concatenation {@code
 * SigningKey || EncryptingKey || KeyNonce} (see {@link SecurityKeyMaterial}), there is no
 * certificate exchange and no key derivation.
 *
 * <p>Parameters common to both defined policies: HMAC-SHA2-256 signatures (32-byte signature,
 * 32-byte signing key), AES-CTR encryption with a 4-byte KeyNonce and an 8-byte MessageNonce
 * (Tables 156/157), and no SecurityFooter — Milo never emits one, and drops (with {@code
 * Bad_NotSupported}) received NetworkMessages whose SecurityFlags indicate one (Annex A pins
 * "SecurityFooter enabled = 0" for both secured layouts, so a footer signals a policy outside this
 * table). Kept table-driven because §7.2.4.4.3.2 allows future policies to "specify different key
 * lengths or cryptography algorithms".
 */
public enum PubSubSecurityPolicy {

  /**
   * PubSub-Aes128-CTR: AES-128 in CTR mode with HMAC-SHA2-256 signatures; "a security policy for
   * configurations with average security needs".
   */
  Aes128Ctr(
      "http://opcfoundation.org/UA/SecurityPolicy#PubSub-Aes128-CTR",
      SecurityAlgorithm.HmacSha256,
      SecurityAlgorithm.Aes128Ctr,
      32,
      16,
      4,
      8,
      32),

  /**
   * PubSub-Aes256-CTR: AES-256 in CTR mode with HMAC-SHA2-256 signatures; "a security policy for
   * configurations with high security needs".
   */
  Aes256Ctr(
      "http://opcfoundation.org/UA/SecurityPolicy#PubSub-Aes256-CTR",
      SecurityAlgorithm.HmacSha256,
      SecurityAlgorithm.Aes256Ctr,
      32,
      32,
      4,
      8,
      32);

  private final String uri;
  private final SecurityAlgorithm symmetricSignatureAlgorithm;
  private final SecurityAlgorithm symmetricEncryptionAlgorithm;
  private final int signingKeyLength;
  private final int encryptingKeyLength;
  private final int keyNonceLength;
  private final int messageNonceLength;
  private final int signatureLength;

  PubSubSecurityPolicy(
      String uri,
      SecurityAlgorithm symmetricSignatureAlgorithm,
      SecurityAlgorithm symmetricEncryptionAlgorithm,
      int signingKeyLength,
      int encryptingKeyLength,
      int keyNonceLength,
      int messageNonceLength,
      int signatureLength) {

    this.uri = uri;
    this.symmetricSignatureAlgorithm = symmetricSignatureAlgorithm;
    this.symmetricEncryptionAlgorithm = symmetricEncryptionAlgorithm;
    this.signingKeyLength = signingKeyLength;
    this.encryptingKeyLength = encryptingKeyLength;
    this.keyNonceLength = keyNonceLength;
    this.messageNonceLength = messageNonceLength;
    this.signatureLength = signatureLength;
  }

  /**
   * Get the URI identifying this SecurityPolicy.
   *
   * @return the SecurityPolicy URI.
   */
  public String getUri() {
    return uri;
  }

  /**
   * Get the SymmetricSignatureAlgorithm of this policy.
   *
   * @return the {@link SecurityAlgorithm} used to sign and verify NetworkMessages.
   */
  public SecurityAlgorithm getSymmetricSignatureAlgorithm() {
    return symmetricSignatureAlgorithm;
  }

  /**
   * Get the SymmetricEncryptionAlgorithm of this policy.
   *
   * @return the {@link SecurityAlgorithm} used to encrypt and decrypt the payload region.
   */
  public SecurityAlgorithm getSymmetricEncryptionAlgorithm() {
    return symmetricEncryptionAlgorithm;
  }

  /**
   * Get the length of the SigningKey part of the key data, in bytes.
   *
   * @return the SigningKey length in bytes.
   */
  public int getSigningKeyLength() {
    return signingKeyLength;
  }

  /**
   * Get the length of the EncryptingKey part of the key data, in bytes.
   *
   * @return the EncryptingKey length in bytes.
   */
  public int getEncryptingKeyLength() {
    return encryptingKeyLength;
  }

  /**
   * Get the length of the KeyNonce part of the key data, in bytes.
   *
   * @return the KeyNonce length in bytes.
   */
  public int getKeyNonceLength() {
    return keyNonceLength;
  }

  /**
   * Get the total length of one key data blob, in bytes: the Part 14 Table 155 concatenation {@code
   * SigningKey || EncryptingKey || KeyNonce}.
   *
   * <p>52 bytes for {@link #Aes128Ctr}, 68 bytes for {@link #Aes256Ctr}.
   *
   * @return the key data length in bytes.
   */
  public int getKeyDataLength() {
    return signingKeyLength + encryptingKeyLength + keyNonceLength;
  }

  /**
   * Get the length of the MessageNonce carried in the SecurityHeader, in bytes.
   *
   * @return the MessageNonce length in bytes.
   */
  public int getMessageNonceLength() {
    return messageNonceLength;
  }

  /**
   * Get the length of the NetworkMessage signature, in bytes.
   *
   * @return the signature length in bytes.
   */
  public int getSignatureLength() {
    return signatureLength;
  }

  /**
   * Look up the {@link PubSubSecurityPolicy} identified by {@code uri}.
   *
   * @param uri a SecurityPolicy URI.
   * @return the matching policy, or empty if {@code uri} names no supported PubSub policy. An empty
   *     result on a provider-returned URI means the key fetch failed; key material is never
   *     accepted under an unsupported policy.
   */
  public static Optional<PubSubSecurityPolicy> fromUri(String uri) {
    for (PubSubSecurityPolicy policy : values()) {
      if (policy.uri.equals(uri)) {
        return Optional.of(policy);
      }
    }
    return Optional.empty();
  }
}
