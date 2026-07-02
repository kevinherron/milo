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

import java.time.Duration;
import java.util.List;
import org.eclipse.milo.opcua.stack.core.types.builtin.ByteString;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UInteger;

/**
 * Key material for a SecurityGroup, returned by a {@link SecurityKeyProvider}.
 *
 * <p>Mirrors the out-arguments of the Security Key Service {@code GetSecurityKeys} method (OPC UA
 * Part 14 §8.3.2) — equivalently the in-arguments of {@code SetSecurityKeys}, so the same shape
 * serves a future push-model receiver. Keys are identified by consecutive SecurityTokenIds starting
 * at {@link #firstTokenId()}: token ids start at 1, increment by 1 each time the KeyLifetime
 * elapses (even if no keys are requested), and restart at 1 past the maximum UInt32 value. Each key
 * is the Part 14 Table 155 concatenation {@code SigningKey || EncryptingKey || KeyNonce}; split it
 * with {@link SecurityKeyMaterial#of(PubSubSecurityPolicy, ByteString)}, which also performs the
 * strict per-policy length validation this carrier deliberately does not.
 *
 * <p>{@link #securityPolicyUri()} is authoritative: key material is used only under the policy the
 * provider named (see {@link SecurityKeyProvider} for the configured-URI precedence rule).
 *
 * <p>{@code timeToNextKey} and {@code keyLifetime} drive the key switch schedule on both sides.
 * {@link Duration#ZERO} in both is the static-key form (e.g. {@link StaticSecurityKeyProvider}): no
 * key switch is ever scheduled and the keys never expire; otherwise the Part 14 rules apply —
 * switch at TimeToNextKey then every KeyLifetime, and keys not renewed within twice the KeyLifetime
 * are stale and must not be used.
 *
 * <p>The keys are immutable {@link ByteString}s and are never zeroized; the wipeable working copies
 * are the {@link SecurityKeyMaterial} instances split from them (see the package documentation for
 * the zeroization posture). {@link #toString()} never includes key bytes — the generated record
 * form would print every key in full hex via {@code ByteString.toString()}, so it is overridden
 * with a sanitized form safe for logs and debuggers.
 *
 * @param securityPolicyUri the URI of the security policy the keys are for.
 * @param firstTokenId the id of the security token corresponding to the first key.
 * @param keys the keys, ordered by consecutive token id starting at {@code firstTokenId}.
 * @param timeToNextKey the time until the current key is replaced by the next key.
 * @param keyLifetime the lifetime of each subsequent key.
 */
public record SecurityKeySet(
    String securityPolicyUri,
    UInteger firstTokenId,
    List<ByteString> keys,
    Duration timeToNextKey,
    Duration keyLifetime) {

  /**
   * Create a new {@link SecurityKeySet}.
   *
   * @param securityPolicyUri the URI of the security policy the keys are for.
   * @param firstTokenId the id of the security token corresponding to the first key.
   * @param keys the keys, ordered by consecutive token id starting at {@code firstTokenId}.
   * @param timeToNextKey the time until the current key is replaced by the next key.
   * @param keyLifetime the lifetime of each subsequent key.
   * @throws IllegalArgumentException if {@code securityPolicyUri} is empty, {@code keys} is empty
   *     or contains a null-valued key, or either duration is negative.
   */
  public SecurityKeySet {
    if (securityPolicyUri.isEmpty()) {
      throw new IllegalArgumentException("securityPolicyUri must not be empty");
    }
    keys = List.copyOf(keys);
    if (keys.isEmpty()) {
      throw new IllegalArgumentException("keys must not be empty");
    }
    for (int i = 0; i < keys.size(); i++) {
      if (keys.get(i).isNull()) {
        throw new IllegalArgumentException("keys[%d] must not be a null ByteString".formatted(i));
      }
    }
    if (timeToNextKey.isNegative()) {
      throw new IllegalArgumentException("timeToNextKey must not be negative");
    }
    if (keyLifetime.isNegative()) {
      throw new IllegalArgumentException("keyLifetime must not be negative");
    }
  }

  /**
   * A sanitized form that never includes key bytes: the policy URI, first token id, key count, and
   * the two durations only.
   */
  @Override
  public String toString() {
    return ("SecurityKeySet{securityPolicyUri=%s, firstTokenId=%s, keys=%d, timeToNextKey=%s,"
            + " keyLifetime=%s}")
        .formatted(securityPolicyUri, firstTokenId, keys.size(), timeToNextKey, keyLifetime);
  }
}
