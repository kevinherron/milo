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

/**
 * Optional engine callback a transport provider may invoke to report changes in its underlying
 * connectivity, carried in the {@link PublisherTransportContext} and {@link
 * SubscriberTransportContext} at channel-open time.
 *
 * <p>The engine maps these callbacks onto the connection's {@code PubSubState}: a {@link
 * #onDisconnected()} moves the connection to {@code Error} (cascading its groups and their
 * writers/readers to {@code Paused} per the Part 14 §6.2.1 state rules), and a subsequent {@link
 * #onConnected()} recovers it to {@code Operational}, re-activating those components (which
 * re-publishes retained metadata on broker connections). Both callbacks are idempotent from the
 * engine's side: repeated {@code onDisconnected()} while already disconnected, or {@code
 * onConnected()} while already operational, are no-ops.
 *
 * <p>Implementing the callback is <b>optional</b>. A transport with no disconnect concept (e.g. the
 * built-in UDP transport) simply never calls it, and a custom {@link TransportProvider} that
 * ignores the listener entirely keeps the pre-callback behavior — broker outages then surface only
 * as send-failure diagnostics, never as a {@code PubSubState} transition. Transports that do call
 * it (e.g. MQTT) must invoke it off the engine lock; the engine hops to its own executor before
 * driving any state change, so the listener may be called from a transport I/O thread.
 */
public interface TransportStateListener {

  /**
   * The transport (re)established its connection to its peer or broker. Invoked on every connect,
   * including the first; the engine treats a connect while already operational as a no-op.
   */
  void onConnected();

  /**
   * The transport lost its connection to its peer or broker. Invoked on every disconnect; the
   * engine treats a disconnect while already in {@code Error} (or not operational) as a no-op.
   */
  void onDisconnected();
}
