/*
 * Copyright (c) 2026 the Eclipse Milo Authors
 *
 * This program and the accompanying materials are made
 * available under the terms of the Eclipse Public License 2.0
 * which is available at https://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 */

package org.eclipse.milo.opcua.sdk.pubsub.server;

import static org.eclipse.milo.opcua.sdk.server.OpcUaServerConfig.USER_TOKEN_POLICY_ANONYMOUS;
import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.uint;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import org.eclipse.milo.opcua.sdk.client.OpcUaClient;
import org.eclipse.milo.opcua.sdk.server.EndpointConfig;
import org.eclipse.milo.opcua.sdk.server.OpcUaServer;
import org.eclipse.milo.opcua.sdk.server.OpcUaServerConfig;
import org.eclipse.milo.opcua.stack.core.security.DefaultCertificateManager;
import org.eclipse.milo.opcua.stack.core.security.MemoryCertificateQuarantine;
import org.eclipse.milo.opcua.stack.core.security.SecurityPolicy;
import org.eclipse.milo.opcua.stack.core.transport.TransportProfile;
import org.eclipse.milo.opcua.stack.core.types.builtin.LocalizedText;
import org.eclipse.milo.opcua.stack.core.types.enumerated.MessageSecurityMode;
import org.eclipse.milo.opcua.stack.transport.server.tcp.OpcTcpServerTransport;
import org.eclipse.milo.opcua.stack.transport.server.tcp.OpcTcpServerTransportConfig;

/**
 * A started, endpoint-bound {@link OpcUaServer} plus a connected {@link OpcUaClient}, the minimal
 * client/server pair the WP-T5 status-event client tests need to drive Part 14 §9.1.13 events
 * through a <b>real</b> event subscription (the shared {@link TestPubSubServer} fixture is endpoint
 * -less and never started, so it can only be observed through a direct {@code EventNotifier}
 * listener — not a client Subscription).
 *
 * <p>Deliberately minimal and CI-safe: a single {@code SecurityPolicy.None} / anonymous TCP
 * endpoint bound to {@code 127.0.0.1} on an ephemeral port (so no certificates, BouncyCastle, or
 * identity validation are needed, and nothing touches the network beyond loopback). The client
 * discovers and connects to that one endpoint.
 *
 * <p>Unlike {@link TestPubSubServer}, this server <b>is</b> started, so its {@code EventFactory}
 * and {@code SubscriptionManager} are live and a client event MonitoredItem on the Server Object
 * ({@code i=2253}) receives events fired through {@link OpcUaServer#getEventNotifier()} — the
 * routing Part 14 §9.1.13 status events rely on.
 */
final class EmbeddedClientServer implements AutoCloseable {

  private final OpcUaServer server;
  private final OpcUaClient client;

  private EmbeddedClientServer(OpcUaServer server, OpcUaClient client) {
    this.server = server;
    this.client = client;
  }

  OpcUaServer server() {
    return server;
  }

  OpcUaClient client() {
    return client;
  }

  /** Start an embedded server on a free loopback port and connect a client to it. */
  static EmbeddedClientServer start() throws Exception {
    int port = freeTcpPort();

    EndpointConfig endpoint =
        EndpointConfig.newBuilder()
            .setBindAddress("127.0.0.1")
            .setHostname("127.0.0.1")
            .setPath("/milo")
            .setSecurityPolicy(SecurityPolicy.None)
            .setSecurityMode(MessageSecurityMode.None)
            .addTokenPolicies(USER_TOKEN_POLICY_ANONYMOUS)
            .setTransportProfile(TransportProfile.TCP_UASC_UABINARY)
            .setBindPort(port)
            .build();

    OpcUaServerConfig config =
        OpcUaServerConfig.builder()
            .setApplicationUri("urn:eclipse:milo:pubsub:status-event-test-server")
            .setApplicationName(LocalizedText.english("PubSub status-event test server"))
            .setProductUri("urn:eclipse:milo:pubsub:status-event-test-server")
            .setEndpoints(Set.of(endpoint))
            .setCertificateManager(new DefaultCertificateManager(new MemoryCertificateQuarantine()))
            .build();

    var server =
        new OpcUaServer(
            config,
            transportProfile -> {
              if (transportProfile == TransportProfile.TCP_UASC_UABINARY) {
                return new OpcTcpServerTransport(OpcTcpServerTransportConfig.newBuilder().build());
              }
              throw new IllegalStateException("unexpected TransportProfile: " + transportProfile);
            });

    server.startup().get(30, TimeUnit.SECONDS);

    OpcUaClient client;
    try {
      client =
          OpcUaClient.create(
              endpoint.getEndpointUrl(),
              endpoints ->
                  endpoints.stream()
                      .filter(
                          e ->
                              Objects.equals(
                                  e.getSecurityPolicyUri(), SecurityPolicy.None.getUri()))
                      .findFirst(),
              transportConfigBuilder -> {},
              clientConfigBuilder ->
                  clientConfigBuilder
                      .setApplicationName(LocalizedText.english("PubSub status-event test client"))
                      .setApplicationUri("urn:eclipse:milo:pubsub:status-event-test-client")
                      .setRequestTimeout(uint(10_000)));

      client.connect();
    } catch (Exception e) {
      server.shutdown().get(10, TimeUnit.SECONDS);
      throw e;
    }

    return new EmbeddedClientServer(server, client);
  }

  @Override
  public void close() throws Exception {
    try {
      client.disconnectAsync().get(5, TimeUnit.SECONDS);
    } finally {
      server.shutdown().get(10, TimeUnit.SECONDS);
    }
  }

  private static int freeTcpPort() throws Exception {
    try (ServerSocket socket = new ServerSocket()) {
      socket.bind(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0));
      return socket.getLocalPort();
    }
  }
}
