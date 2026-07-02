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

import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.ubyte;
import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.uint;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;
import org.eclipse.milo.opcua.sdk.client.DiscoveryClient;
import org.eclipse.milo.opcua.sdk.client.OpcUaClient;
import org.eclipse.milo.opcua.sdk.client.OpcUaClientConfig;
import org.eclipse.milo.opcua.sdk.client.OpcUaClientConfigBuilder;
import org.eclipse.milo.opcua.stack.core.NodeIds;
import org.eclipse.milo.opcua.stack.core.types.builtin.LocalizedText;
import org.eclipse.milo.opcua.stack.core.types.builtin.NodeId;
import org.eclipse.milo.opcua.stack.core.types.builtin.Variant;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UInteger;
import org.eclipse.milo.opcua.stack.core.types.enumerated.MessageSecurityMode;
import org.eclipse.milo.opcua.stack.core.types.structured.CallMethodRequest;
import org.eclipse.milo.opcua.stack.core.types.structured.CallMethodResult;
import org.eclipse.milo.opcua.stack.core.types.structured.EndpointDescription;

/**
 * Shared helpers for the client-driven remote-configuration tests: connect a real {@link
 * OpcUaClient} to the {@link TestSksServer} fixture over its {@code None} endpoint and call the ns0
 * {@code PublishSubscribe/PubSubConfiguration} FileType methods ({@code i=25451}) through the real
 * {@code Call} service.
 *
 * <p>The file method nodes carry {@code AccessRestrictionType(0)} (no channel-security requirement)
 * and, with no {@code RoleMapper} configured, the access controller performs no role-permission
 * check, so an anonymous {@code None}-channel session reaches the handlers — keeping these tests
 * certificate-free while still driving the whole server-side chain (access control, method
 * dispatch, {@link RemoteConfigurationServer} authorization, and the {@link FileHandleManager} /
 * {@link ReserveIdRegistry} / {@link RemoteConfigurationApplier} state).
 */
final class RemoteConfigClientSupport {

  static final Duration TIMEOUT = Duration.ofSeconds(30);
  static final Duration AWAIT = Duration.ofSeconds(10);

  static final NodeId CONFIG = NodeIds.PublishSubscribe_PubSubConfiguration;
  static final NodeId OPEN = NodeIds.PublishSubscribe_PubSubConfiguration_Open;
  static final NodeId CLOSE = NodeIds.PublishSubscribe_PubSubConfiguration_Close;
  static final NodeId READ = NodeIds.PublishSubscribe_PubSubConfiguration_Read;
  static final NodeId WRITE = NodeIds.PublishSubscribe_PubSubConfiguration_Write;
  static final NodeId GET_POSITION = NodeIds.PublishSubscribe_PubSubConfiguration_GetPosition;
  static final NodeId SET_POSITION = NodeIds.PublishSubscribe_PubSubConfiguration_SetPosition;
  static final NodeId RESERVE_IDS = NodeIds.PublishSubscribe_PubSubConfiguration_ReserveIds;
  static final NodeId CLOSE_AND_UPDATE =
      NodeIds.PublishSubscribe_PubSubConfiguration_CloseAndUpdate;

  private RemoteConfigClientSupport() {}

  /** Discover the fixture's {@code None} endpoint and connect an anonymous {@link OpcUaClient}. */
  static OpcUaClient connect(TestSksServer sks) throws Exception {
    List<EndpointDescription> endpoints =
        DiscoveryClient.getEndpoints(sks.getEndpointUrl())
            .get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);

    EndpointDescription endpoint =
        endpoints.stream()
            .filter(e -> e.getSecurityMode() == MessageSecurityMode.None)
            .findFirst()
            .orElseThrow(() -> new IllegalStateException("no None endpoint"));

    OpcUaClientConfigBuilder configBuilder = OpcUaClientConfig.builder();
    configBuilder.setEndpoint(endpoint);
    configBuilder.setApplicationName(LocalizedText.english("remote-config test client"));
    configBuilder.setApplicationUri("urn:eclipse:milo:pubsub:remote-config-test-client");
    configBuilder.setRequestTimeout(uint(TIMEOUT.toMillis()));

    OpcUaClient client = OpcUaClient.create(configBuilder.build());
    client.connect();
    return client;
  }

  /** Call one of the {@code i=25451} FileType methods and return the single result. */
  static CallMethodResult call(OpcUaClient client, NodeId methodId, Variant... inputs)
      throws Exception {
    CallMethodResult[] results =
        client.call(List.of(new CallMethodRequest(CONFIG, methodId, inputs))).getResults();
    assertEquals(1, results.length);
    return results[0];
  }

  /** Open the file in {@code mode}, asserting success, and return the file handle. */
  static UInteger open(OpcUaClient client, int mode) throws Exception {
    CallMethodResult result = call(client, OPEN, new Variant(ubyte(mode)));
    assertTrue(
        result.getStatusCode().isGood(), "Open(0x" + Integer.toHexString(mode) + ") " + result);
    return (UInteger) result.getOutputArguments()[0].getValue();
  }

  /** Poll {@code condition} until true or the {@link #AWAIT} deadline elapses; fail on timeout. */
  static void awaitTrue(BooleanSupplier condition, String description) {
    long deadline = System.nanoTime() + AWAIT.toNanos();
    while (System.nanoTime() < deadline) {
      if (condition.getAsBoolean()) {
        return;
      }
      try {
        Thread.sleep(25);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        fail("interrupted awaiting: " + description);
      }
    }
    fail("timed out awaiting: " + description);
  }
}
