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
import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.ushort;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.net.DatagramSocket;
import java.net.SocketException;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.function.Predicate;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubService;
import org.eclipse.milo.opcua.sdk.pubsub.config.DataSetWriterConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.FieldDefinition;
import org.eclipse.milo.opcua.sdk.pubsub.config.NodeFieldAddress;
import org.eclipse.milo.opcua.sdk.pubsub.config.PubSubConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.PubSubConnectionConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.PublishedDataSetConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.PublishedDataSetRef;
import org.eclipse.milo.opcua.sdk.pubsub.config.PublisherId;
import org.eclipse.milo.opcua.sdk.pubsub.config.ReaderGroupConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.SecurityGroupConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.UadpDataSetWriterSettings;
import org.eclipse.milo.opcua.sdk.pubsub.config.UadpWriterGroupSettings;
import org.eclipse.milo.opcua.sdk.pubsub.config.UdpDatagramAddress;
import org.eclipse.milo.opcua.sdk.pubsub.config.WriterGroupConfig;
import org.eclipse.milo.opcua.sdk.pubsub.server.PubSubMethodAuthorizer.Decision;
import org.eclipse.milo.opcua.sdk.server.AccessContext;
import org.eclipse.milo.opcua.sdk.server.OpcUaServer;
import org.eclipse.milo.opcua.sdk.server.SecurityConfiguration;
import org.eclipse.milo.opcua.sdk.server.Session;
import org.eclipse.milo.opcua.sdk.server.nodes.UaMethodNode;
import org.eclipse.milo.opcua.sdk.server.nodes.UaVariableNode;
import org.eclipse.milo.opcua.stack.core.AttributeId;
import org.eclipse.milo.opcua.stack.core.NodeIds;
import org.eclipse.milo.opcua.stack.core.StatusCodes;
import org.eclipse.milo.opcua.stack.core.security.SecurityPolicy;
import org.eclipse.milo.opcua.stack.core.types.builtin.ByteString;
import org.eclipse.milo.opcua.stack.core.types.builtin.DataValue;
import org.eclipse.milo.opcua.stack.core.types.builtin.LocalizedText;
import org.eclipse.milo.opcua.stack.core.types.builtin.NodeId;
import org.eclipse.milo.opcua.stack.core.types.builtin.StatusCode;
import org.eclipse.milo.opcua.stack.core.types.builtin.Variant;
import org.eclipse.milo.opcua.stack.core.types.enumerated.ApplicationType;
import org.eclipse.milo.opcua.stack.core.types.enumerated.MessageSecurityMode;
import org.eclipse.milo.opcua.stack.core.types.enumerated.PubSubState;
import org.eclipse.milo.opcua.stack.core.types.structured.ApplicationDescription;
import org.eclipse.milo.opcua.stack.core.types.structured.CallMethodRequest;
import org.eclipse.milo.opcua.stack.core.types.structured.CallMethodResult;
import org.eclipse.milo.opcua.stack.core.types.structured.DataSetFieldContentMask;
import org.eclipse.milo.opcua.stack.core.types.structured.EndpointDescription;
import org.eclipse.milo.opcua.stack.core.types.structured.UadpDataSetMessageContentMask;
import org.eclipse.milo.opcua.stack.core.types.structured.UadpNetworkMessageContentMask;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * Writable/live information-model evolution: the config-derived rebuild driven by a reconfigure,
 * the §9.1.10 Enable/Disable methods on the Status objects, and the agreement between the
 * fragment's NodeIds and the ConfigurationObjects scheme returned from {@code CloseAndUpdate}.
 *
 * <p>Network safety: enabled connections use unicast 127.0.0.1 with ephemeral ports and an explicit
 * loopback {@code discoveryAddress}; the rebuild and ConfigurationObjects tests use disabled
 * components so no sockets are opened at all.
 */
class PubSubInfoModelWritableTest {

  private static final Duration TIMEOUT = Duration.ofSeconds(10);

  private static final UadpWriterGroupSettings GROUP_SETTINGS =
      UadpWriterGroupSettings.builder()
          .networkMessageContentMask(
              UadpNetworkMessageContentMask.of(
                  UadpNetworkMessageContentMask.Field.PublisherId,
                  UadpNetworkMessageContentMask.Field.GroupHeader,
                  UadpNetworkMessageContentMask.Field.WriterGroupId,
                  UadpNetworkMessageContentMask.Field.SequenceNumber,
                  UadpNetworkMessageContentMask.Field.PayloadHeader))
          .build();

  private static final UadpDataSetWriterSettings WRITER_SETTINGS =
      UadpDataSetWriterSettings.builder()
          .dataSetMessageContentMask(
              UadpDataSetMessageContentMask.of(UadpDataSetMessageContentMask.Field.SequenceNumber))
          .build();

  private static final DataSetFieldContentMask FIELD_MASK =
      DataSetFieldContentMask.of(DataSetFieldContentMask.Field.StatusCode);

  private final List<ServerPubSub> attached = new CopyOnWriteArrayList<>();
  private final List<TestPubSubServer> servers = new CopyOnWriteArrayList<>();

  @AfterEach
  void tearDown() {
    for (ServerPubSub serverPubSub : attached) {
      serverPubSub.close();
    }
    attached.clear();
    for (TestPubSubServer server : servers) {
      server.close();
    }
    servers.clear();
  }

  // region Enable/Disable

  @Test
  void enableDisableMethodsMintedOnlyWhenRemoteConfigurationEnabled() throws Exception {
    // read-only exposure: no Enable/Disable methods (read-only posture preserved)
    TestPubSubServer readOnlyServer = newServer();
    ServerPubSub readOnly =
        attach(
            readOnlyServer,
            disabledConfig(readOnlyServer),
            ServerPubSubOptions.builder().exposeInformationModel(true).build());
    readOnly.startup().get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);

    assertFalse(
        node(readOnlyServer, "PubSub/c1/Status/Enable").isPresent(),
        "read-only exposure must not mint an Enable method");
    assertFalse(
        node(readOnlyServer, "PubSub/c1/Status/Disable").isPresent(),
        "read-only exposure must not mint a Disable method");

    // remote-config exposure: Enable/Disable minted and browsable from the Status object
    TestPubSubServer rcServer = newServer();
    ServerPubSub rc =
        attach(
            rcServer,
            disabledConfig(rcServer),
            ServerPubSubOptions.builder()
                .exposeInformationModel(true)
                .allowRemoteConfiguration(true)
                .build());
    rc.startup().get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);

    NodeId statusId = fragmentNodeId(rcServer, "PubSub/c1/Status");
    NodeId enableId = fragmentNodeId(rcServer, "PubSub/c1/Status/Enable");
    assertInstanceOf(UaMethodNode.class, node(rcServer, "PubSub/c1/Status/Enable").orElseThrow());
    assertInstanceOf(UaMethodNode.class, node(rcServer, "PubSub/c1/Status/Disable").orElseThrow());
    assertTrue(
        hasReference(rcServer, statusId, NodeIds.HasComponent, enableId),
        "Status object must browse the Enable method via HasComponent");
  }

  @Test
  void enableDisableEnforceCurrentStateRules() throws Exception {
    TestPubSubServer server = newServer();
    NodeId source =
        server.addVariable("W_Source", NodeIds.Double, new DataValue(Variant.ofDouble(1.5)));

    ServerPubSub serverPubSub =
        attach(
            server,
            enabledPublisherConfig(server, source),
            ServerPubSubOptions.builder()
                .exposeInformationModel(true)
                .allowRemoteConfiguration(true)
                .build());
    serverPubSub.startup().get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);

    String statusPath = "PubSub/c1/wg1/Status";
    awaitState(server, "PubSub/c1/wg1", PubSubState.Operational);

    AccessContext session = sessionContext(server);

    // Enable on an Operational component: Bad_InvalidState (§9.1.10.2)
    assertEquals(
        StatusCodes.Bad_InvalidState, callMethod(server, statusPath, "Enable", session).getValue());

    // Disable succeeds; the component moves to Disabled
    assertEquals(StatusCode.GOOD, callMethod(server, statusPath, "Disable", session));
    awaitState(server, "PubSub/c1/wg1", PubSubState.Disabled);

    // Disable on an already-Disabled component: Bad_InvalidState (§9.1.10.3)
    assertEquals(
        StatusCodes.Bad_InvalidState,
        callMethod(server, statusPath, "Disable", session).getValue());

    // Enable succeeds again from Disabled
    assertEquals(StatusCode.GOOD, callMethod(server, statusPath, "Enable", session));
    awaitStateNot(server, "PubSub/c1/wg1", PubSubState.Disabled);
  }

  @Test
  void enableDisableRequireAuthorizedSession() throws Exception {
    // session-less internal call is rejected regardless of authorizer
    TestPubSubServer server = newServer();
    ServerPubSub serverPubSub =
        attach(
            server,
            disabledConfig(server),
            ServerPubSubOptions.builder()
                .exposeInformationModel(true)
                .allowRemoteConfiguration(true)
                .build());
    serverPubSub.startup().get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);

    assertEquals(
        StatusCodes.Bad_UserAccessDenied,
        callMethod(server, "PubSub/c1/Status", "Enable", AccessContext.INTERNAL).getValue());

    // a session the authorizer denies checkConfigure for is rejected too
    TestPubSubServer deniedServer = newServer();
    ServerPubSub denied =
        attach(
            deniedServer,
            disabledConfig(deniedServer),
            ServerPubSubOptions.builder()
                .exposeInformationModel(true)
                .allowRemoteConfiguration(true)
                .methodAuthorizer(denyConfigureAuthorizer())
                .build());
    denied.startup().get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);

    assertEquals(
        StatusCodes.Bad_UserAccessDenied,
        callMethod(deniedServer, "PubSub/c1/Status", "Disable", sessionContext(deniedServer))
            .getValue());
  }

  // endregion

  // region rebuild

  @Test
  void reconfigureRebuildsConfigDerivedSubtrees() throws Exception {
    TestPubSubServer server = newServer();
    NodeId source =
        server.addVariable("R_Source", NodeIds.Double, new DataValue(Variant.ofDouble(1.5)));

    ServerPubSub serverPubSub =
        attach(
            server,
            disabledConfig(server, source),
            ServerPubSubOptions.builder().exposeInformationModel(true).build());
    serverPubSub.startup().get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);

    assertTrue(node(server, "PubSub/c1").isPresent());
    assertTrue(node(server, "PubSub/c1/wg1").isPresent());
    assertTrue(node(server, "PubSub/PublishedDataSets/ds1").isPresent());

    // add a second connection
    PubSubConfig withC2 =
        PubSubConfig.builder()
            .publishedDataSet(publishedDataSet(server, source, false))
            .connection(disabledConnection("c1", "wg1", "w1"))
            .connection(disabledConnection("c2", "wg2", "w2"))
            .build();
    serverPubSub.reconfigure(withC2, PubSubService.ReconfigureMode.DISABLE_AFFECTED);

    assertTrue(node(server, "PubSub/c2").isPresent(), "added connection should appear");
    assertTrue(node(server, "PubSub/c2/wg2").isPresent(), "added group should appear");
    assertTrue(node(server, "PubSub/c1").isPresent(), "untouched connection should remain");

    // remove the second connection
    serverPubSub.reconfigure(
        disabledConfig(server, source), PubSubService.ReconfigureMode.DISABLE_AFFECTED);

    assertFalse(node(server, "PubSub/c2").isPresent(), "removed connection should be gone");
    assertFalse(node(server, "PubSub/c2/wg2").isPresent(), "removed group should be gone");
    assertTrue(node(server, "PubSub/c1").isPresent(), "untouched connection should remain");

    // change a writer group property
    Double before =
        (Double)
            ((UaVariableNode) node(server, "PubSub/c1/wg1/PublishingInterval").orElseThrow())
                .getValue()
                .value()
                .value();
    PubSubConfig changedInterval =
        PubSubConfig.builder()
            .publishedDataSet(publishedDataSet(server, source, false))
            .connection(disabledConnection("c1", "wg1", "w1", Duration.ofMillis(250)))
            .build();
    serverPubSub.reconfigure(changedInterval, PubSubService.ReconfigureMode.DISABLE_AFFECTED);

    Double after =
        (Double)
            ((UaVariableNode) node(server, "PubSub/c1/wg1/PublishingInterval").orElseThrow())
                .getValue()
                .value()
                .value();
    assertNotEquals(before, after, "changed PublishingInterval should be reflected");
    assertEquals(250.0, after.doubleValue());

    // change the published dataset (add a field) and confirm the DataSetToWriter link survives
    PubSubConfig changedDataSet =
        PubSubConfig.builder()
            .publishedDataSet(publishedDataSet(server, source, true))
            .connection(disabledConnection("c1", "wg1", "w1", Duration.ofMillis(250)))
            .build();
    serverPubSub.reconfigure(changedDataSet, PubSubService.ReconfigureMode.DISABLE_AFFECTED);

    NodeId dataSetId = fragmentNodeId(server, "PubSub/PublishedDataSets/ds1");
    NodeId writerId = fragmentNodeId(server, "PubSub/c1/wg1/w1");
    assertTrue(node(server, "PubSub/PublishedDataSets/ds1").isPresent());
    assertTrue(
        hasReference(server, dataSetId, NodeIds.DataSetToWriter, writerId),
        "the DataSetToWriter reference must be re-established after a dataset rebuild");
  }

  // endregion

  // region ConfigurationObjects agreement

  @Test
  void configurationObjectNodeIdsMatchTheCloseAndUpdateScheme() throws Exception {
    TestPubSubServer server = newServer();
    NodeId source =
        server.addVariable("C_Source", NodeIds.Double, new DataValue(Variant.ofDouble(1.5)));

    ServerPubSub serverPubSub =
        attach(
            server,
            disabledConfig(server, source),
            ServerPubSubOptions.builder().exposeInformationModel(true).build());
    serverPubSub.startup().get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);

    // toConfigurationObjects returns "PubSub/" + the applier's object path:
    //   connection = <name>, group = <conn>/<group>, writer = <conn>/<group>/<leaf>,
    //   published dataset = PublishedDataSets/<name>. The fragment must mint each config-derived
    //   component at exactly these NodeIds for the returned ids to resolve.
    for (String path :
        List.of("PubSub/c1", "PubSub/c1/wg1", "PubSub/c1/wg1/w1", "PubSub/PublishedDataSets/ds1")) {
      assertTrue(node(server, path).isPresent(), "expected a fragment node at " + path);
    }
  }

  // endregion

  // region fragment lifecycle (fragmentStarted race fix)

  @Test
  void startupThenCloseUnregistersFragmentCleanly() throws Exception {
    TestPubSubServer server = newServer();
    ServerPubSub serverPubSub =
        attach(
            server,
            disabledConfig(server),
            ServerPubSubOptions.builder().exposeInformationModel(true).build());

    serverPubSub.startup().get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);
    assertTrue(node(server, "PubSub/c1").isPresent());

    serverPubSub.close();
    assertFalse(
        node(server, "PubSub/c1").isPresent(), "close must unregister the fragment node manager");

    // second close is a no-op and does not throw (idempotent, no double fragment.shutdown)
    serverPubSub.close();
  }

  // endregion

  // region fixtures and helpers

  private TestPubSubServer newServer() {
    TestPubSubServer server = TestPubSubServer.create();
    servers.add(server);
    return server;
  }

  private ServerPubSub attach(
      TestPubSubServer server, PubSubConfig config, ServerPubSubOptions options) {
    ServerPubSub serverPubSub = ServerPubSub.attach(server.getServer(), config, options);
    attached.add(serverPubSub);
    return serverPubSub;
  }

  /** A fully-disabled config with one connection/group/writer publishing a node-backed dataset. */
  private static PubSubConfig disabledConfig(TestPubSubServer server) {
    NodeId source =
        server.addVariable(
            "D_Source_" + System.nanoTime(), NodeIds.Double, new DataValue(Variant.ofDouble(1.5)));
    return disabledConfig(server, source);
  }

  private static PubSubConfig disabledConfig(TestPubSubServer server, NodeId source) {
    return PubSubConfig.builder()
        .publishedDataSet(publishedDataSet(server, source, false))
        .connection(disabledConnection("c1", "wg1", "w1"))
        .build();
  }

  private static PublishedDataSetConfig publishedDataSet(
      TestPubSubServer server, NodeId source, boolean extraField) {
    PublishedDataSetConfig.Builder builder =
        PublishedDataSetConfig.builder("ds1")
            .field(
                FieldDefinition.builder("value")
                    .source(nodeAddress(server, source))
                    .dataType(NodeIds.Double)
                    .dataSetFieldId(new UUID(0L, 1L))
                    .build());
    if (extraField) {
      builder.field(
          FieldDefinition.builder("value2")
              .source(nodeAddress(server, source))
              .dataType(NodeIds.Double)
              .dataSetFieldId(new UUID(0L, 2L))
              .build());
    }
    return builder.build();
  }

  private static PubSubConnectionConfig disabledConnection(
      String connection, String group, String writer) {
    return disabledConnection(connection, group, writer, Duration.ofMillis(100));
  }

  private static PubSubConnectionConfig disabledConnection(
      String connection, String group, String writer, Duration interval) {
    // disabled connections never bind a socket, so fixed deterministic ports keep the config
    // stable across reconfigures (component config equality drives the incremental rebuild)
    int base = 40000 + Math.floorMod(connection.hashCode(), 1000) * 2;
    // each connection gets its own deterministic publisherId so multi-connection configs (e.g. the
    // rebuild test's c1 + c2) keep their reused writerGroupId/dataSetWriterId in distinct
    // publisher-id scopes (PubSubConfig enforces id uniqueness within a publisher-id scope)
    int publisherId = 1 + Math.floorMod(connection.hashCode(), 60000);
    return PubSubConnectionConfig.udp(connection)
        .enabled(false)
        .publisherId(PublisherId.uint16(ushort(publisherId)))
        .address(UdpDatagramAddress.unicast("127.0.0.1", base))
        .discoveryAddress(UdpDatagramAddress.unicast("127.0.0.1", base + 1))
        .writerGroup(
            WriterGroupConfig.builder(group)
                .enabled(false)
                .writerGroupId(ushort(21))
                .publishingInterval(interval)
                .messageSettings(GROUP_SETTINGS)
                .dataSetWriter(
                    DataSetWriterConfig.builder(writer)
                        .dataSet(new PublishedDataSetRef("ds1"))
                        .dataSetWriterId(ushort(31))
                        .fieldContentMask(FIELD_MASK)
                        .settings(WRITER_SETTINGS)
                        .build())
                .build())
        .readerGroup(ReaderGroupConfig.builder("rg1").build())
        .build();
  }

  /** An enabled UDP publisher whose writer group reaches Operational after startup. */
  private static PubSubConfig enabledPublisherConfig(TestPubSubServer server, NodeId source)
      throws SocketException {
    PublishedDataSetConfig dataSet = publishedDataSet(server, source, false);
    return PubSubConfig.builder()
        .publishedDataSet(dataSet)
        .connection(
            PubSubConnectionConfig.udp("c1")
                .publisherId(PublisherId.uint16(ushort(1)))
                .address(UdpDatagramAddress.unicast("127.0.0.1", freeUdpPort()))
                .discoveryAddress(UdpDatagramAddress.unicast("127.0.0.1", freeUdpPort()))
                .writerGroup(
                    WriterGroupConfig.builder("wg1")
                        .writerGroupId(ushort(21))
                        .publishingInterval(Duration.ofMillis(100))
                        .messageSettings(GROUP_SETTINGS)
                        .dataSetWriter(
                            DataSetWriterConfig.builder("w1")
                                .dataSet(dataSet.ref())
                                .dataSetWriterId(ushort(31))
                                .fieldContentMask(FIELD_MASK)
                                .settings(WRITER_SETTINGS)
                                .build())
                        .build())
                .build())
        .build();
  }

  private static NodeFieldAddress nodeAddress(TestPubSubServer server, NodeId nodeId) {
    return NodeFieldAddress.of(nodeId, AttributeId.Value, server.getServer().getNamespaceTable());
  }

  private static PubSubMethodAuthorizer denyConfigureAuthorizer() {
    return new PubSubMethodAuthorizer() {
      @Override
      public Decision checkConfigure(Session session) {
        return Decision.DENY;
      }

      @Override
      public Decision checkSksAdmin(Session session) {
        return Decision.DENY;
      }

      @Override
      public Decision checkKeyAccess(
          Session session,
          @Nullable String securityGroupId,
          @Nullable SecurityGroupConfig securityGroup) {
        return Decision.DENY;
      }
    };
  }

  /**
   * Invoke {@code methodName} on the Status object at {@code statusPath} and return the result
   * code.
   */
  private static StatusCode callMethod(
      TestPubSubServer server, String statusPath, String methodName, AccessContext context) {

    NodeId statusId = fragmentNodeId(server, statusPath);
    NodeId methodId = fragmentNodeId(server, statusPath + "/" + methodName);
    UaMethodNode methodNode =
        (UaMethodNode) node(server, statusPath + "/" + methodName).orElseThrow();

    CallMethodResult result =
        methodNode
            .getInvocationHandler()
            .invoke(context, new CallMethodRequest(statusId, methodId, new Variant[0]));
    return result.getStatusCode();
  }

  private static AccessContext sessionContext(TestPubSubServer server) {
    Session session = newSession(server.getServer());
    return () -> java.util.Optional.of(session);
  }

  private static Session newSession(OpcUaServer server) {
    var applicationDescription =
        new ApplicationDescription(
            "urn:eclipse:milo:pubsub:test-client",
            "urn:eclipse:milo:pubsub:test-client",
            LocalizedText.english("test client"),
            ApplicationType.Client,
            null,
            null,
            null);
    var endpoint =
        new EndpointDescription(
            "opc.tcp://localhost:0",
            applicationDescription,
            ByteString.NULL_VALUE,
            MessageSecurityMode.SignAndEncrypt,
            SecurityPolicy.Basic256Sha256.getUri(),
            null,
            null,
            ubyte(0));
    var securityConfiguration =
        new SecurityConfiguration(
            SecurityPolicy.Basic256Sha256,
            MessageSecurityMode.SignAndEncrypt,
            null,
            null,
            null,
            null,
            null);
    return new Session(
        server,
        new NodeId(1, "wp-y-session-" + System.nanoTime()),
        "wp-y-session",
        Duration.ofMinutes(5),
        applicationDescription,
        "urn:eclipse:milo:pubsub:test-server",
        uint(0),
        endpoint,
        1L,
        securityConfiguration);
  }

  private static NodeId fragmentNodeId(TestPubSubServer server, String identifier) {
    return new NodeId(server.getServer().getServerNamespace().getNamespaceIndex(), identifier);
  }

  private static java.util.Optional<org.eclipse.milo.opcua.sdk.server.nodes.UaNode> node(
      TestPubSubServer server, String identifier) {
    return server
        .getServer()
        .getAddressSpaceManager()
        .getManagedNode(fragmentNodeId(server, identifier));
  }

  private static boolean hasReference(
      TestPubSubServer server, NodeId sourceId, NodeId referenceType, NodeId targetId) {
    return server.getServer().getAddressSpaceManager().getManagedReferences(sourceId).stream()
        .anyMatch(
            ref ->
                ref.isForward()
                    && ref.getReferenceTypeId().equals(referenceType)
                    && ref.getTargetNodeId()
                        .toNodeId(server.getServer().getNamespaceTable())
                        .map(targetId::equals)
                        .orElse(false));
  }

  private static void awaitState(TestPubSubServer server, String componentPath, PubSubState state)
      throws InterruptedException {
    awaitStateValue(server, componentPath, state::equals, "State == " + state);
  }

  private static void awaitStateNot(
      TestPubSubServer server, String componentPath, PubSubState state)
      throws InterruptedException {
    awaitStateValue(server, componentPath, value -> !state.equals(value), "State != " + state);
  }

  private static void awaitStateValue(
      TestPubSubServer server,
      String componentPath,
      Predicate<Object> predicate,
      String description)
      throws InterruptedException {

    NodeId stateId = fragmentNodeId(server, componentPath + "/Status/State");
    long deadline = System.nanoTime() + TIMEOUT.toNanos();
    Object last = null;
    while (true) {
      UaVariableNode stateNode =
          (UaVariableNode)
              server.getServer().getAddressSpaceManager().getManagedNode(stateId).orElse(null);
      if (stateNode != null) {
        last = stateNode.getValue().value().value();
        if (predicate.test(last)) {
          return;
        }
      }
      if (System.nanoTime() >= deadline) {
        fail("timed out waiting for " + description + " on " + componentPath + "; last=" + last);
      }
      Thread.sleep(25);
    }
  }

  private static int freeUdpPort() throws SocketException {
    try (DatagramSocket socket = new DatagramSocket(0)) {
      return socket.getLocalPort();
    }
  }

  // endregion
}
