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
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.eclipse.milo.opcua.stack.core.types.enumerated.MessageSecurityMode;
import org.junit.jupiter.api.Test;

/**
 * {@link MessageSecurityContext} construction validation (the K5 encode seam): mode must be Sign or
 * SignAndEncrypt (mode None is represented by a {@code null} context on the EncodeContext, and
 * Invalid is the per-reader inherit sentinel — neither is ever a secured context), and the key
 * material must belong to the stated policy.
 */
class MessageSecurityContextTest {

  private static final MessageNonceSupplier NONCE_SUPPLIER =
      () -> UadpMessageSecurity.createMessageNonce(new byte[] {0, 1, 2, 3}, 1L);

  @Test
  void signAndSignAndEncryptConstruct() {
    SecurityKeyMaterial material = aes128Material();

    for (MessageSecurityMode mode :
        new MessageSecurityMode[] {MessageSecurityMode.Sign, MessageSecurityMode.SignAndEncrypt}) {

      MessageSecurityContext context =
          MessageSecurityContext.of(
              mode, PubSubSecurityPolicy.Aes128Ctr, uint(3), material, NONCE_SUPPLIER);

      assertEquals(mode, context.mode());
      assertEquals(PubSubSecurityPolicy.Aes128Ctr, context.policy());
      assertEquals(uint(3), context.securityTokenId());
      assertSame(material, context.keyMaterial());
      assertSame(NONCE_SUPPLIER, context.nonceSupplier());
    }
  }

  @Test
  void modeNoneRejected() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            MessageSecurityContext.of(
                MessageSecurityMode.None,
                PubSubSecurityPolicy.Aes128Ctr,
                uint(1),
                aes128Material(),
                NONCE_SUPPLIER));
  }

  @Test
  void modeInvalidRejected() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            MessageSecurityContext.of(
                MessageSecurityMode.Invalid,
                PubSubSecurityPolicy.Aes128Ctr,
                uint(1),
                aes128Material(),
                NONCE_SUPPLIER));
  }

  @Test
  void keyMaterialPolicyMismatchRejected() {
    // Aes128Ctr material offered under the Aes256Ctr policy (and vice versa) is a wiring bug:
    // the context validates policy == keyMaterial.getPolicy() at construction.
    assertThrows(
        IllegalArgumentException.class,
        () ->
            MessageSecurityContext.of(
                MessageSecurityMode.SignAndEncrypt,
                PubSubSecurityPolicy.Aes256Ctr,
                uint(1),
                aes128Material(),
                NONCE_SUPPLIER));

    SecurityKeyMaterial aes256Material =
        SecurityKeyMaterial.of(
            PubSubSecurityPolicy.Aes256Ctr, new byte[32], new byte[32], new byte[4]);
    assertThrows(
        IllegalArgumentException.class,
        () ->
            MessageSecurityContext.of(
                MessageSecurityMode.SignAndEncrypt,
                PubSubSecurityPolicy.Aes128Ctr,
                uint(1),
                aes256Material,
                NONCE_SUPPLIER));
  }

  @Test
  void ofMirrorsTheCanonicalConstructor() {
    SecurityKeyMaterial material = aes128Material();

    MessageSecurityContext viaOf =
        MessageSecurityContext.of(
            MessageSecurityMode.Sign,
            PubSubSecurityPolicy.Aes128Ctr,
            uint(9),
            material,
            NONCE_SUPPLIER);
    MessageSecurityContext viaCanonical =
        new MessageSecurityContext(
            MessageSecurityMode.Sign,
            PubSubSecurityPolicy.Aes128Ctr,
            uint(9),
            material,
            NONCE_SUPPLIER);

    assertEquals(viaCanonical, viaOf);
  }

  private static SecurityKeyMaterial aes128Material() {
    return SecurityKeyMaterial.of(
        PubSubSecurityPolicy.Aes128Ctr, new byte[32], new byte[16], new byte[4]);
  }
}
