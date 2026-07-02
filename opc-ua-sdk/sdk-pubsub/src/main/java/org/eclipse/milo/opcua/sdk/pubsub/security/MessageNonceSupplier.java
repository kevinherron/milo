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

/**
 * Supplies the MessageNonce for each secured NetworkMessage: the nonce seam of the encode-side
 * security contract (see {@link MessageSecurityContext}).
 *
 * <p>The encoder invokes {@link #nextNonce()} exactly once per secured NetworkMessage it encodes
 * and writes the returned bytes into the SecurityHeader verbatim. Implementations own the nonce
 * composition of OPC UA Part 14 §7.2.4.4.3.2 Table 156 — 4 random bytes (pseudo-random is
 * sufficient; {@code NonceUtil.generateNonce(4)} is the default source, injectable as a test seam
 * for computed golden vectors) followed by a little-endian UInt32 sequence number — and the per-key
 * counter state behind it: the sequence number is reset to 1 each time the key and SecurityTokenId
 * are updated and incremented by exactly one per NetworkMessage. Compose via {@link
 * UadpMessageSecurity#createMessageNonce(byte[], long)}.
 *
 * <p><b>A (key, nonce) pair must never repeat</b>: AES-CTR keystream reuse is a total
 * confidentiality break. Because the counter is per-key state, a supplier is only valid for the key
 * material and token id it was resolved with; the runtime resolves a fresh {@link
 * MessageSecurityContext} per publish cycle to keep them paired.
 */
@FunctionalInterface
public interface MessageNonceSupplier {

  /**
   * Get the MessageNonce for the next secured NetworkMessage.
   *
   * @return the nonce bytes, {@link PubSubSecurityPolicy#getMessageNonceLength()} (8) bytes; a
   *     fresh array the caller may consume freely.
   */
  byte[] nextNonce();
}
