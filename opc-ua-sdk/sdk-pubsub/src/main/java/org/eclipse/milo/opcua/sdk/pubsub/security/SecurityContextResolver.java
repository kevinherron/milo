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

import java.util.List;
import java.util.Optional;
import org.eclipse.milo.opcua.sdk.pubsub.config.PublisherId;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UInteger;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UShort;
import org.eclipse.milo.opcua.stack.core.types.enumerated.MessageSecurityMode;
import org.jspecify.annotations.Nullable;

/**
 * The decode-side message security contract: what the UADP decoder consults, once per received
 * secured NetworkMessage, to obtain the key material for verification and decryption.
 *
 * <p>Owned by the reader-side key manager and carried to the codec on {@code DecodeContext}; a
 * {@code null} resolver on the DecodeContext means no secured message can be resolved and every
 * secured message is dropped.
 *
 * <p>The SecurityHeader does not name the SecurityGroup: "The relation to the SecurityGroup is done
 * through DataSetWriterIds contained in the NetworkMessage" (OPC UA Part 14 Table 154). The decoder
 * therefore passes everything the wire provides — the plaintext header identifiers plus the
 * SecurityHeader's token id and the mode indicated by its SecurityFlags — and the resolver maps
 * them to a SecurityGroup and selects the key within that group's token window.
 *
 * <p>The decoder consults the resolver after parsing the SecurityHeader and <b>before</b> touching
 * the signature or payload; with the returned material it verifies the trailing signature first and
 * then, when the message is encrypted, decrypts a <b>copy</b> of the payload region (the shared
 * transport buffer is never mutated). An empty result means the message is dropped, and the
 * resolver implementation is the counting point for the drop reason it decided: unknown token id
 * (trigger a single key refresh per §8.3.2; drop, never buffer), received mode below the group's
 * configured mode (§7.2.4.3 SHALL), no resolvable group, or stale keys. Signature and decryption
 * failures on resolved material are counted by the codec's caller, not the resolver.
 *
 * <p>The returned material is borrowed for the duration of the current decode operation; the owner
 * must not {@link SecurityKeyMaterial#destroy()} it while a decode holding it is in flight.
 */
@FunctionalInterface
public interface SecurityContextResolver {

  /**
   * Resolve the key material for a received secured NetworkMessage.
   *
   * @param publisherId the publisher id from the NetworkMessage header, or {@code null} if not
   *     present on the wire.
   * @param writerGroupId the WriterGroupId from the GroupHeader, or {@code null} if not present.
   * @param dataSetWriterIds the DataSetWriterIds from the PayloadHeader, in payload order; possibly
   *     empty when the message carries no PayloadHeader.
   * @param receivedMode the security mode indicated by the received SecurityFlags; {@link
   *     MessageSecurityMode#Sign} or {@link MessageSecurityMode#SignAndEncrypt}.
   * @param securityTokenId the SecurityTokenId from the SecurityHeader.
   * @return the key material identified by {@code securityTokenId} within the resolved
   *     SecurityGroup, or empty if the message cannot or must not be processed — the decoder drops
   *     it.
   */
  Optional<SecurityKeyMaterial> resolve(
      @Nullable PublisherId publisherId,
      @Nullable UShort writerGroupId,
      List<UShort> dataSetWriterIds,
      MessageSecurityMode receivedMode,
      UInteger securityTokenId);
}
