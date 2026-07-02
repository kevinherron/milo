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

import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UInteger;
import org.eclipse.milo.opcua.stack.core.types.enumerated.MessageSecurityMode;

/**
 * The encode-side message security contract: everything the UADP encoder needs to secure the
 * NetworkMessages of one WriterGroup publish cycle.
 *
 * <p>Resolved by the publisher runtime from the group's active key state once per publish cycle and
 * carried to the codec on {@code EncodeContext}; a {@code null} context on the EncodeContext means
 * the group's security mode is None and no SecurityHeader is written. The codec stays stateless:
 * all key state — the active token, the split key material, and the per-key nonce counter behind
 * {@link #nonceSupplier()} — lives with the publisher key state that resolved this context.
 *
 * <p>The encoder uses this context per OPC UA Part 14 §7.2.4.4: set ExtendedFlags1 bit 4, write the
 * SecurityHeader (SecurityFlags from {@link #mode()}, {@link #securityTokenId()}, an 8-byte
 * MessageNonce from {@link #nonceSupplier()} — emitted for Sign and SignAndEncrypt alike, per the
 * Annex A layouts), encrypt the payload region in place when the mode is SignAndEncrypt, then sign
 * the whole NetworkMessage and append the {@link PubSubSecurityPolicy#getSignatureLength()}
 * signature. No SecurityFooter is ever emitted.
 *
 * <p>The {@link #keyMaterial()} is held for the duration of the publish cycle, which may span
 * user-supplied dataset source reads of unbounded duration. The resolver must therefore hand each
 * cycle key material whose lifetime it controls — Milo's key manager provides a cycle-owned
 * <b>copy</b> of the active window material, which the publish cycle {@link
 * SecurityKeyMaterial#destroy() destroys} when it completes — never a reference that a concurrent
 * key retirement could destroy (and wipe) while the cycle is still in flight.
 *
 * <p>Future versions (e.g. force-key-reset emission) will add components to this record via new
 * {@code of(...)} factory overloads; the canonical constructor may change incompatibly when they
 * do.
 *
 * @param mode the security mode of the group; {@link MessageSecurityMode#Sign} or {@link
 *     MessageSecurityMode#SignAndEncrypt}.
 * @param policy the security policy the key material belongs to.
 * @param securityTokenId the id of the security token identifying {@link #keyMaterial()} within its
 *     SecurityGroup; written to the SecurityHeader.
 * @param keyMaterial the split key material of the active token.
 * @param nonceSupplier the per-key MessageNonce supplier; invoked exactly once per secured
 *     NetworkMessage.
 * @apiNote Create instances via {@link #of(MessageSecurityMode, PubSubSecurityPolicy, UInteger,
 *     SecurityKeyMaterial, MessageNonceSupplier)} rather than the canonical constructor; the
 *     factory methods are stable while the canonical constructor is not.
 */
public record MessageSecurityContext(
    MessageSecurityMode mode,
    PubSubSecurityPolicy policy,
    UInteger securityTokenId,
    SecurityKeyMaterial keyMaterial,
    MessageNonceSupplier nonceSupplier) {

  /**
   * Create a new {@link MessageSecurityContext}.
   *
   * @param mode the security mode of the group; {@link MessageSecurityMode#Sign} or {@link
   *     MessageSecurityMode#SignAndEncrypt}.
   * @param policy the security policy the key material belongs to.
   * @param securityTokenId the id of the security token identifying {@code keyMaterial} within its
   *     SecurityGroup.
   * @param keyMaterial the split key material of the active token.
   * @param nonceSupplier the per-key MessageNonce supplier.
   * @throws IllegalArgumentException if {@code mode} is not Sign or SignAndEncrypt, or {@code
   *     keyMaterial} belongs to a different policy than {@code policy}.
   */
  public MessageSecurityContext {
    if (mode != MessageSecurityMode.Sign && mode != MessageSecurityMode.SignAndEncrypt) {
      throw new IllegalArgumentException("mode must be Sign or SignAndEncrypt, got " + mode);
    }
    if (keyMaterial.getPolicy() != policy) {
      throw new IllegalArgumentException(
          "keyMaterial policy %s does not match policy %s"
              .formatted(keyMaterial.getPolicy(), policy));
    }
  }

  /**
   * Create a {@link MessageSecurityContext}.
   *
   * @param mode the security mode of the group; {@link MessageSecurityMode#Sign} or {@link
   *     MessageSecurityMode#SignAndEncrypt}.
   * @param policy the security policy the key material belongs to.
   * @param securityTokenId the id of the security token identifying {@code keyMaterial} within its
   *     SecurityGroup.
   * @param keyMaterial the split key material of the active token.
   * @param nonceSupplier the per-key MessageNonce supplier.
   * @return a new {@link MessageSecurityContext}.
   * @throws IllegalArgumentException if {@code mode} is not Sign or SignAndEncrypt, or {@code
   *     keyMaterial} belongs to a different policy than {@code policy}.
   */
  public static MessageSecurityContext of(
      MessageSecurityMode mode,
      PubSubSecurityPolicy policy,
      UInteger securityTokenId,
      SecurityKeyMaterial keyMaterial,
      MessageNonceSupplier nonceSupplier) {

    return new MessageSecurityContext(mode, policy, securityTokenId, keyMaterial, nonceSupplier);
  }
}
