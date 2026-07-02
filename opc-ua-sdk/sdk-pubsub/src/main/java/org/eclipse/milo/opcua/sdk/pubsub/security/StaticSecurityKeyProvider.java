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

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import org.eclipse.milo.opcua.stack.core.types.builtin.ByteString;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UInteger;

/**
 * A {@link SecurityKeyProvider} serving a fixed, pre-shared set of keys: the static-key
 * provisioning model used when no Security Key Service is deployed.
 *
 * <p>Static keys never rotate: the provider always returns the same {@link SecurityKeySet} with
 * {@code firstTokenId} 1 and {@code timeToNextKey}/{@code keyLifetime} {@link Duration#ZERO} (no
 * scheduled key switch, keys never expire — see {@link SecurityKeySet}). The {@code
 * securityGroupId}, {@code startingTokenId}, and {@code requestedKeyCount} arguments of {@link
 * #getKeys} are ignored; bind one provider per SecurityGroup via {@code PubSubBindings}.
 *
 * <p>Key data is validated strictly at construction: every blob must be exactly {@link
 * PubSubSecurityPolicy#getKeyDataLength()} bytes (52 for Aes128Ctr, 68 for Aes256Ctr). {@link
 * #fromKeyFileDirectory(Path)} reads the de-facto static-key interop convention established by
 * S2OPC and adopted by OPC Labs OpcCmd ({@code static:?keyPartsDirectory=}): a directory of three
 * raw binary files, {@code signingKey.key} (32 bytes), {@code encryptKey.key} (16 or 32 bytes — the
 * length selects the policy), and {@code keyNonce.key} (4 bytes).
 *
 * <p>The keys are held as immutable {@link ByteString}s and are never zeroized (see the package
 * documentation for the zeroization posture).
 */
public final class StaticSecurityKeyProvider implements SecurityKeyProvider {

  static final String SIGNING_KEY_FILE_NAME = "signingKey.key";
  static final String ENCRYPT_KEY_FILE_NAME = "encryptKey.key";
  static final String KEY_NONCE_FILE_NAME = "keyNonce.key";

  private final SecurityKeySet keySet;

  private StaticSecurityKeyProvider(SecurityKeySet keySet) {
    this.keySet = keySet;
  }

  @Override
  public CompletableFuture<SecurityKeySet> getKeys(
      String securityGroupId, UInteger startingTokenId, UInteger requestedKeyCount) {

    return CompletableFuture.completedFuture(keySet);
  }

  /**
   * Create a {@link StaticSecurityKeyProvider} serving {@code keyData} under {@code policy}.
   *
   * <p>Keys are assigned consecutive token ids starting at 1, in argument order.
   *
   * @param policy the {@link PubSubSecurityPolicy} the keys are for.
   * @param keyData one or more key data blobs, each the Part 14 Table 155 concatenation {@code
   *     SigningKey || EncryptingKey || KeyNonce}.
   * @return a new {@link StaticSecurityKeyProvider}.
   * @throws IllegalArgumentException if no key data is given or any blob is not exactly {@link
   *     PubSubSecurityPolicy#getKeyDataLength()} bytes.
   */
  public static StaticSecurityKeyProvider of(PubSubSecurityPolicy policy, ByteString... keyData) {
    if (keyData.length == 0) {
      throw new IllegalArgumentException("at least one key data blob is required");
    }
    for (int i = 0; i < keyData.length; i++) {
      if (keyData[i].length() != policy.getKeyDataLength()) {
        throw new IllegalArgumentException(
            "keyData[%d] for %s must be exactly %d bytes, got %d"
                .formatted(i, policy, policy.getKeyDataLength(), keyData[i].length()));
      }
    }

    var keySet =
        new SecurityKeySet(
            policy.getUri(), uint(1), List.of(keyData), Duration.ZERO, Duration.ZERO);

    return new StaticSecurityKeyProvider(keySet);
  }

  /**
   * Create a {@link StaticSecurityKeyProvider} from a directory of key part files in the S2OPC/OPC
   * Labs static-key layout: {@code signingKey.key} (32 bytes), {@code encryptKey.key} (16 or 32
   * bytes), and {@code keyNonce.key} (4 bytes), each containing raw key bytes.
   *
   * <p>The policy is selected by the encrypting key length: 16 bytes {@link
   * PubSubSecurityPolicy#Aes128Ctr}, 32 bytes {@link PubSubSecurityPolicy#Aes256Ctr}.
   *
   * @param directory the directory containing the three key part files.
   * @return a new {@link StaticSecurityKeyProvider} serving the single key read from {@code
   *     directory}.
   * @throws IOException if any key part file cannot be read.
   * @throws IllegalArgumentException if any key part has an invalid length.
   */
  public static StaticSecurityKeyProvider fromKeyFileDirectory(Path directory) throws IOException {
    byte[] signingKey = Files.readAllBytes(directory.resolve(SIGNING_KEY_FILE_NAME));
    byte[] encryptKey = Files.readAllBytes(directory.resolve(ENCRYPT_KEY_FILE_NAME));
    byte[] keyNonce = Files.readAllBytes(directory.resolve(KEY_NONCE_FILE_NAME));

    PubSubSecurityPolicy policy;
    if (encryptKey.length == PubSubSecurityPolicy.Aes128Ctr.getEncryptingKeyLength()) {
      policy = PubSubSecurityPolicy.Aes128Ctr;
    } else if (encryptKey.length == PubSubSecurityPolicy.Aes256Ctr.getEncryptingKeyLength()) {
      policy = PubSubSecurityPolicy.Aes256Ctr;
    } else {
      throw new IllegalArgumentException(
          "%s must be 16 or 32 bytes, got %d".formatted(ENCRYPT_KEY_FILE_NAME, encryptKey.length));
    }

    if (signingKey.length != policy.getSigningKeyLength()) {
      throw new IllegalArgumentException(
          "%s must be exactly %d bytes, got %d"
              .formatted(SIGNING_KEY_FILE_NAME, policy.getSigningKeyLength(), signingKey.length));
    }
    if (keyNonce.length != policy.getKeyNonceLength()) {
      throw new IllegalArgumentException(
          "%s must be exactly %d bytes, got %d"
              .formatted(KEY_NONCE_FILE_NAME, policy.getKeyNonceLength(), keyNonce.length));
    }

    byte[] keyData = new byte[policy.getKeyDataLength()];
    System.arraycopy(signingKey, 0, keyData, 0, signingKey.length);
    System.arraycopy(encryptKey, 0, keyData, signingKey.length, encryptKey.length);
    System.arraycopy(keyNonce, 0, keyData, signingKey.length + encryptKey.length, keyNonce.length);

    return of(policy, ByteString.of(keyData));
  }
}
