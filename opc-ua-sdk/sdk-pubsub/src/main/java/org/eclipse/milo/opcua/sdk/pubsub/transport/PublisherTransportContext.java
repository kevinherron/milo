/*
 * Copyright (c) 2026 the Eclipse Milo Authors
 *
 * This program and the accompanying materials are made
 * available under the terms of the Eclipse Public License 2.0
 * which is available at https://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 */

package org.eclipse.milo.opcua.sdk.pubsub.transport;

import io.netty.channel.EventLoopGroup;
import org.eclipse.milo.opcua.sdk.pubsub.config.PubSubConnectionConfig;
import org.jspecify.annotations.Nullable;

/**
 * Context for {@link TransportProvider#openPublisher(PublisherTransportContext)}.
 *
 * <p>Future versions (e.g. broker transports such as MQTT) will add components to this record via
 * new {@code of(...)} factory overloads; the canonical constructor may change incompatibly when
 * they do.
 *
 * @param connection the config of the connection the channel is opened for.
 * @param eventLoopGroup the Netty {@link EventLoopGroup} the channel must use for I/O.
 * @param transportStateListener an optional engine callback the provider may invoke to report
 *     connectivity changes (see {@link TransportStateListener}), or {@code null} when the engine
 *     supplied none. A provider that does not track connectivity ignores it.
 * @apiNote Create instances via one of the {@code of(...)} factory methods rather than the
 *     canonical constructor; the factory methods are stable while the canonical constructor is not.
 */
public record PublisherTransportContext(
    PubSubConnectionConfig connection,
    EventLoopGroup eventLoopGroup,
    @Nullable TransportStateListener transportStateListener) {

  /**
   * Create a {@link PublisherTransportContext} without a transport-state listener.
   *
   * @param connection the config of the connection the channel is opened for.
   * @param eventLoopGroup the Netty {@link EventLoopGroup} the channel must use for I/O.
   * @return a new {@link PublisherTransportContext}.
   */
  public static PublisherTransportContext of(
      PubSubConnectionConfig connection, EventLoopGroup eventLoopGroup) {

    return new PublisherTransportContext(connection, eventLoopGroup, null);
  }

  /**
   * Create a {@link PublisherTransportContext}.
   *
   * @param connection the config of the connection the channel is opened for.
   * @param eventLoopGroup the Netty {@link EventLoopGroup} the channel must use for I/O.
   * @param transportStateListener an optional engine callback the provider may invoke to report
   *     connectivity changes, or {@code null} to supply none.
   * @return a new {@link PublisherTransportContext}.
   */
  public static PublisherTransportContext of(
      PubSubConnectionConfig connection,
      EventLoopGroup eventLoopGroup,
      @Nullable TransportStateListener transportStateListener) {

    return new PublisherTransportContext(connection, eventLoopGroup, transportStateListener);
  }
}
