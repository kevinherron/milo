/*
 * Copyright (c) 2026 the Eclipse Milo Authors
 *
 * This program and the accompanying materials are made
 * available under the terms of the Eclipse Public License 2.0
 * which is available at https://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 */

package org.eclipse.milo.opcua.sdk.pubsub.uadp;

import org.eclipse.milo.opcua.sdk.pubsub.security.SecurityContextResolver;
import org.eclipse.milo.opcua.stack.core.encoding.EncodingContext;
import org.jspecify.annotations.Nullable;

/**
 * Context for {@link MessageMappingProvider#decode(DecodeContext, io.netty.buffer.ByteBuf)}.
 *
 * <p>Future versions (e.g. JSON mapping, broker transports) will add components to this record via
 * new {@code of(...)} factory overloads; the canonical constructor may change incompatibly when
 * they do.
 *
 * @param encodingContext the {@link EncodingContext} used to decode field values.
 * @param securityContextResolver the resolver consulted for received secured NetworkMessages, or
 *     {@code null} if none is available — secured messages are then dropped.
 * @param chunkReassembler the stateful chunk reassembler for this connection's inbound chunked
 *     NetworkMessages, or {@code null} if none is available — chunked messages are then dropped.
 *     The reassembler is owned by the caller and must be the <b>same instance</b> across the decode
 *     calls of one connection: chunks of one payload arrive in separate NetworkMessages and the
 *     codec itself is stateless.
 * @apiNote Create instances via the {@code of(...)} factory methods rather than the canonical
 *     constructor; the factory methods are stable while the canonical constructor is not.
 */
public record DecodeContext(
    EncodingContext encodingContext,
    @Nullable SecurityContextResolver securityContextResolver,
    @Nullable ChunkReassembler chunkReassembler) {

  /**
   * Create a {@link DecodeContext} without message security or chunk reassembly support.
   *
   * @param encodingContext the {@link EncodingContext} used to decode field values.
   * @return a new {@link DecodeContext}.
   */
  public static DecodeContext of(EncodingContext encodingContext) {
    return new DecodeContext(encodingContext, null, null);
  }

  /**
   * Create a {@link DecodeContext} without chunk reassembly support.
   *
   * @param encodingContext the {@link EncodingContext} used to decode field values.
   * @param securityContextResolver the resolver consulted for received secured NetworkMessages, or
   *     {@code null} if none is available — secured messages are then dropped.
   * @return a new {@link DecodeContext}.
   */
  public static DecodeContext of(
      EncodingContext encodingContext, @Nullable SecurityContextResolver securityContextResolver) {

    return new DecodeContext(encodingContext, securityContextResolver, null);
  }

  /**
   * Create a {@link DecodeContext}.
   *
   * @param encodingContext the {@link EncodingContext} used to decode field values.
   * @param securityContextResolver the resolver consulted for received secured NetworkMessages, or
   *     {@code null} if none is available — secured messages are then dropped.
   * @param chunkReassembler the caller-owned, per-connection chunk reassembler, or {@code null} if
   *     none is available — chunked messages are then dropped.
   * @return a new {@link DecodeContext}.
   */
  public static DecodeContext of(
      EncodingContext encodingContext,
      @Nullable SecurityContextResolver securityContextResolver,
      @Nullable ChunkReassembler chunkReassembler) {

    return new DecodeContext(encodingContext, securityContextResolver, chunkReassembler);
  }
}
