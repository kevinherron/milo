/*
 * Copyright (c) 2026 the Eclipse Milo Authors
 *
 * This program and the accompanying materials are made
 * available under the terms of the Eclipse Public License 2.0
 * which is available at https://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 */

package org.eclipse.milo.opcua.sdk.pubsub.sks;

import java.util.List;
import java.util.concurrent.CompletableFuture;
import org.eclipse.milo.opcua.sdk.client.identity.IdentityProvider;
import org.eclipse.milo.opcua.stack.core.types.structured.CallMethodRequest;
import org.eclipse.milo.opcua.stack.core.types.structured.CallMethodResult;
import org.eclipse.milo.opcua.stack.core.types.structured.EndpointDescription;

/**
 * The client operations {@link SksSecurityKeyProvider} needs from the OPC UA client SDK, seamed out
 * so the Part 14 Table 40 resolution algorithm is testable against a stubbed discovery/session
 * surface.
 *
 * <p>{@link DefaultSksClientOperations} is the production implementation backed by {@code
 * DiscoveryClient} and {@code OpcUaClient}. All operations are asynchronous and must never block
 * the calling thread.
 */
interface SksClientOperations {

  /**
   * Query the GetEndpoints service at {@code discoveryUrl}.
   *
   * @param discoveryUrl the discovery URL to get endpoints from.
   * @return a future that completes with the endpoints returned by the server, or completes
   *     exceptionally if discovery fails.
   */
  CompletableFuture<List<EndpointDescription>> getEndpoints(String discoveryUrl);

  /**
   * Connect to {@code endpoint} and activate a session with {@code identityProvider}.
   *
   * @param endpoint the endpoint to connect to.
   * @param discoveredEndpoints the full endpoint list the discovery step produced, for the Part 4
   *     §6.1.4 CreateSession endpoint comparison defense.
   * @param identityProvider the identity to activate the session with.
   * @return a future that completes with a connected {@link Session}, or completes exceptionally if
   *     the connection or session activation fails.
   */
  CompletableFuture<Session> connect(
      EndpointDescription endpoint,
      List<EndpointDescription> discoveredEndpoints,
      IdentityProvider identityProvider);

  /** A connected session that can invoke methods until it is {@link #disconnect() disconnected}. */
  interface Session {

    /**
     * Invoke a method on this session.
     *
     * @param request the {@link CallMethodRequest} identifying the object/method and arguments.
     * @return a future that completes with the {@link CallMethodResult}, or completes exceptionally
     *     on a service- or transport-level failure.
     */
    CompletableFuture<CallMethodResult> call(CallMethodRequest request);

    /**
     * Disconnect this session, releasing its underlying client and channel.
     *
     * @return a future that completes when the disconnect has been processed.
     */
    CompletableFuture<Void> disconnect();
  }
}
