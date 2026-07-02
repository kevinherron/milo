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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.net.DatagramSocket;
import java.net.SocketException;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubHandle;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubService;
import org.eclipse.milo.opcua.sdk.pubsub.config.DataSetReaderConfig;
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
import org.eclipse.milo.opcua.sdk.server.nodes.UaNode;
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
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UInteger;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UShort;
import org.eclipse.milo.opcua.stack.core.types.enumerated.ApplicationType;
import org.eclipse.milo.opcua.stack.core.types.enumerated.DiagnosticsLevel;
import org.eclipse.milo.opcua.stack.core.types.enumerated.MessageSecurityMode;
import org.eclipse.milo.opcua.stack.core.types.enumerated.PubSubState;
import org.eclipse.milo.opcua.stack.core.types.structured.ApplicationDescription;
import org.eclipse.milo.opcua.stack.core.types.structured.CallMethodRequest;
import org.eclipse.milo.opcua.stack.core.types.structured.DataSetFieldContentMask;
import org.eclipse.milo.opcua.stack.core.types.structured.EndpointDescription;
import org.eclipse.milo.opcua.stack.core.types.structured.UadpDataSetMessageContentMask;
import org.eclipse.milo.opcua.stack.core.types.structured.UadpNetworkMessageContentMask;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * WP-Z-diag: the Part 14 §9.1.11 diagnostics exposure (pins R13/R14/R15/R18) and the §9.1.9
 * PubSubCapabilities population (pin R20) in {@link PubSubInfoModelFragment}. Verifies the ns0 root
 * ({@code i=17409}) and PubSubCapabilities ({@code i=23678}) backing, the fragment-minted
 * per-component Diagnostics objects, live counter/count values, the Reset method round-trip and
 * authorization, ResolvedAddress, and rebuild-on-reconfigure.
 *
 * <p>Diagnostics is gated on both {@link ServerPubSubOptions#isExposeInformationModel()} and {@link
 * ServerPubSubOptions#isDiagnosticsEnabled()}; the per-component Diagnostics objects hang off the
 * fragment's component nodes, so both must be set. Network-touching tests use unicast 127.0.0.1 on
 * ephemeral ports; the structural, capabilities, and rebuild tests use disabled components.
 */
class PubSubInfoModelDiagnosticsTest {

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

  @Test
  void diagnosticsDisabledLeavesNs0SkeletonUntouched() throws Exception {
    // exposeInformationModel(true) but diagnosticsEnabled(false): no per-component Diagnostics and
    // the ns0 skeleton left as the loader created it (NULL DiagnosticsLevel / capabilities)
    TestPubSubServer server = newServer();
    ServerPubSub serverPubSub =
        attach(
            server,
            disabledConfig(server),
            ServerPubSubOptions.builder().exposeInformationModel(true).build());
    serverPubSub.startup().get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);

    assertFalse(node(server, "PubSub/c1/Diagnostics").isPresent());
    assertFalse(node(server, "PubSub/c1/wg1/Diagnostics").isPresent());

    assertNull(ns0Value(server, NodeIds.PublishSubscribe_Diagnostics_DiagnosticsLevel));
    assertNull(ns0Value(server, NodeIds.PublishSubscribe_PubSubCapablities_SupportSecurityKeyPull));
  }

  @Test
  void diagnosticsExposesPerComponentAndRootNodes() throws Exception {
    TestPubSubServer server = newServer();
    ServerPubSub serverPubSub = attachWithDiagnostics(server, disabledConfig(server));
    serverPubSub.startup().get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);

    // per-component Diagnostics objects exist for every runtime component
    for (String path :
        List.of(
            "PubSub/c1/Diagnostics",
            "PubSub/c1/wg1/Diagnostics",
            "PubSub/c1/wg1/w1/Diagnostics",
            "PubSub/c1/rg1/Diagnostics")) {
      assertTrue(node(server, path).isPresent(), "expected a Diagnostics object at " + path);
    }

    // Basic level, the six State* counters, and the kind-specific counters (pin R13/R14)
    assertEquals(
        DiagnosticsLevel.Basic,
        fragmentValue(server, "PubSub/c1/wg1/Diagnostics/DiagnosticsLevel"));
    assertTrue(node(server, "PubSub/c1/wg1/Diagnostics/Counters/StateError").isPresent());
    assertTrue(node(server, "PubSub/c1/wg1/Diagnostics/Counters/SentNetworkMessages").isPresent());
    assertTrue(node(server, "PubSub/c1/wg1/Diagnostics/Counters/FailedTransmissions").isPresent());
    assertTrue(
        node(server, "PubSub/c1/wg1/w1/Diagnostics/Counters/FailedDataSetMessages").isPresent());
    assertTrue(
        node(server, "PubSub/c1/rg1/Diagnostics/Counters/ReceivedNetworkMessages").isPresent());

    // a counter is a PubSubDiagnosticsCounterType with a Mandatory Classification property
    assertInstanceOf(
        UaVariableNode.class,
        node(server, "PubSub/c1/wg1/Diagnostics/Counters/SentNetworkMessages").orElseThrow());
    assertNotNull(
        fragmentValue(
            server, "PubSub/c1/wg1/Diagnostics/Counters/SentNetworkMessages/Classification"));

    // Reset method minted on every Diagnostics object
    assertInstanceOf(
        UaMethodNode.class, node(server, "PubSub/c1/wg1/Diagnostics/Reset").orElseThrow());

    // ns0 root backed: DiagnosticsLevel Basic; ConfiguredDataSetWriters reflects the config
    assertEquals(
        DiagnosticsLevel.Basic,
        ns0Value(server, NodeIds.PublishSubscribe_Diagnostics_DiagnosticsLevel));
    assertEquals(
        ushort(1),
        ns0Value(server, NodeIds.PublishSubscribe_Diagnostics_LiveValues_ConfiguredDataSetWriters));
  }

  @Test
  void capabilitiesPopulatedWhenExposed() throws Exception {
    TestPubSubServer server = newServer();
    ServerPubSub serverPubSub = attachWithDiagnostics(server, disabledConfig(server));
    serverPubSub.startup().get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);

    // Max* = 0 (no limit) for every advertised capability (pin R20)
    for (NodeId maxNode :
        List.of(
            NodeIds.PublishSubscribe_PubSubCapablities_MaxPubSubConnections,
            NodeIds.PublishSubscribe_PubSubCapablities_MaxWriterGroups,
            NodeIds.PublishSubscribe_PubSubCapablities_MaxDataSetWriters,
            NodeIds.PublishSubscribe_PubSubCapablities_MaxNetworkMessageSizeDatagram)) {
      assertEquals(uint(0), ns0Value(server, maxNode), "Max should be 0 (no limit) at " + maxNode);
    }

    assertEquals(
        Boolean.TRUE,
        ns0Value(server, NodeIds.PublishSubscribe_PubSubCapablities_SupportSecurityKeyPull));
    assertEquals(
        Boolean.FALSE,
        ns0Value(server, NodeIds.PublishSubscribe_PubSubCapablities_SupportSecurityKeyPush));
    // SKS server face is off by default
    assertEquals(
        Boolean.FALSE,
        ns0Value(server, NodeIds.PublishSubscribe_PubSubCapablities_SupportSecurityKeyServer));
  }

  @Test
  void resolvedAddressResolvesUdpHostAtExposureTime() throws Exception {
    TestPubSubServer server = newServer();
    ServerPubSub serverPubSub = attachWithDiagnostics(server, disabledConfig(server));
    serverPubSub.startup().get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);

    // 127.0.0.1 resolves to itself; the connection LiveValue carries the resolved address (pin R15)
    assertEquals(
        "127.0.0.1", fragmentValue(server, "PubSub/c1/Diagnostics/LiveValues/ResolvedAddress"));
  }

  @Test
  void operationalCountsReflectRuntimeState() throws Exception {
    TestPubSubServer server = newServer();
    NodeId source =
        server.addVariable("O_Source", NodeIds.Double, new DataValue(Variant.ofDouble(1.5)));
    ServerPubSub serverPubSub =
        attachWithDiagnostics(server, enabledPublisherConfig(server, source));
    serverPubSub.startup().get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);

    awaitState(server, "PubSub/c1/wg1", PubSubState.Operational);

    // root and writer-group Configured/Operational counts reflect the single Operational writer
    assertEquals(
        ushort(1),
        ns0Value(server, NodeIds.PublishSubscribe_Diagnostics_LiveValues_ConfiguredDataSetWriters));
    awaitCount(
        server,
        NodeIds.PublishSubscribe_Diagnostics_LiveValues_OperationalDataSetWriters,
        ushort(1));
    assertEquals(
        ushort(1),
        fragmentValue(server, "PubSub/c1/wg1/Diagnostics/LiveValues/ConfiguredDataSetWriters"));
  }

  @Test
  void counterValueTracksEngineAndIsUInt32() throws Exception {
    TestPubSubServer server = newServer();
    NodeId source =
        server.addVariable("V_Source", NodeIds.Double, new DataValue(Variant.ofDouble(1.5)));
    ServerPubSub serverPubSub =
        attachWithDiagnostics(server, enabledPublisherConfig(server, source));
    serverPubSub.startup().get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);

    awaitState(server, "PubSub/c1/wg1", PubSubState.Operational);
    awaitCounterAbove(server, "PubSub/c1/wg1/Diagnostics/Counters/SentNetworkMessages", 0L);

    // freeze the counter so the node read and the engine read cannot straddle an increment
    PubSubHandle writerGroup =
        serverPubSub.runtime().components().writerGroup("c1", "wg1").orElseThrow();
    serverPubSub.runtime().disable(writerGroup);
    awaitState(server, "PubSub/c1/wg1", PubSubState.Disabled);
    Thread.sleep(150);

    UInteger exposed =
        (UInteger) fragmentValue(server, "PubSub/c1/wg1/Diagnostics/Counters/SentNetworkMessages");
    long engine =
        serverPubSub
            .runtime()
            .diagnostics()
            .component("c1/wg1")
            .orElseThrow()
            .networkMessagesSent();
    // exposure clamps the 64-bit engine value to UInt32 (§9.1.11.5); below the cap they agree
    assertEquals(Math.min(engine, 0xFFFF_FFFFL), exposed.longValue());
  }

  @Test
  void resetZeroesCountersWhenAuthorizedAndDeniesUnauthorized() throws Exception {
    TestPubSubServer server = newServer();
    NodeId source =
        server.addVariable("R_Source", NodeIds.Double, new DataValue(Variant.ofDouble(1.5)));
    ServerPubSub serverPubSub =
        attachWithDiagnostics(server, enabledPublisherConfig(server, source));
    serverPubSub.startup().get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);

    awaitState(server, "PubSub/c1/wg1", PubSubState.Operational);
    awaitCounterAbove(server, "PubSub/c1/wg1/Diagnostics/Counters/SentNetworkMessages", 0L);

    // freeze the counter: disable the writer group so no more NetworkMessages are sent
    PubSubHandle writerGroup =
        serverPubSub.runtime().components().writerGroup("c1", "wg1").orElseThrow();
    serverPubSub.runtime().disable(writerGroup);
    awaitState(server, "PubSub/c1/wg1", PubSubState.Disabled);
    Thread.sleep(150);

    String counterPath = "PubSub/c1/wg1/Diagnostics/Counters/SentNetworkMessages";
    long before = ((UInteger) fragmentValue(server, counterPath)).longValue();
    assertTrue(before > 0, "expected a non-zero SentNetworkMessages before reset");

    // session-less Reset is denied (pin R18/R9) and does not zero the counter
    assertEquals(
        StatusCodes.Bad_UserAccessDenied,
        callMethod(server, "PubSub/c1/wg1/Diagnostics", "Reset", AccessContext.INTERNAL)
            .getValue());
    assertEquals(before, ((UInteger) fragmentValue(server, counterPath)).longValue());

    // authorized Reset zeroes the counter
    assertEquals(
        StatusCode.GOOD, callMethod(server, "PubSub/c1/wg1/Diagnostics", "Reset", session(server)));
    assertEquals(0L, ((UInteger) fragmentValue(server, counterPath)).longValue());
  }

  @Test
  void resetDeniedByAuthorizer() throws Exception {
    TestPubSubServer server = newServer();
    ServerPubSub serverPubSub =
        attach(
            server,
            disabledConfig(server),
            ServerPubSubOptions.builder()
                .exposeInformationModel(true)
                .diagnosticsEnabled(true)
                .methodAuthorizer(denyConfigureAuthorizer())
                .build());
    serverPubSub.startup().get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);

    // an authorized session still fails when the authorizer denies checkConfigure (pin R9)
    assertEquals(
        StatusCodes.Bad_UserAccessDenied,
        callMethod(server, "PubSub/c1/wg1/Diagnostics", "Reset", session(server)).getValue());
    // the ns0 root Reset is guarded the same way
    assertEquals(
        StatusCodes.Bad_UserAccessDenied, callRootReset(server, session(server)).getValue());
  }

  @Test
  void rootResetRequiresAuthorizationThenSucceeds() throws Exception {
    TestPubSubServer server = newServer();
    ServerPubSub serverPubSub = attachWithDiagnostics(server, disabledConfig(server));
    serverPubSub.startup().get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);

    assertEquals(
        StatusCodes.Bad_UserAccessDenied, callRootReset(server, AccessContext.INTERNAL).getValue());
    assertEquals(StatusCode.GOOD, callRootReset(server, session(server)));
  }

  @Test
  void reconfigureRebuildsPerComponentDiagnostics() throws Exception {
    TestPubSubServer server = newServer();
    NodeId source =
        server.addVariable("RB_Source", NodeIds.Double, new DataValue(Variant.ofDouble(1.5)));

    ServerPubSub serverPubSub =
        attachWithDiagnostics(
            server,
            PubSubConfig.builder()
                .publishedDataSet(publishedDataSet(server, source))
                .connection(disabledConnection("c1"))
                .build());
    serverPubSub.startup().get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);

    assertFalse(node(server, "PubSub/c2/Diagnostics").isPresent());

    PubSubConfig withC2 =
        PubSubConfig.builder()
            .publishedDataSet(publishedDataSet(server, source))
            .connection(disabledConnection("c1"))
            .connection(disabledConnection("c2"))
            .build();
    serverPubSub.reconfigure(withC2, PubSubService.ReconfigureMode.DISABLE_AFFECTED);

    assertTrue(
        node(server, "PubSub/c2/Diagnostics").isPresent(),
        "added connection should get a Diagnostics object");
    assertTrue(node(server, "PubSub/c2/wg1/Diagnostics/Counters/SentNetworkMessages").isPresent());
    assertTrue(
        node(server, "PubSub/c1/Diagnostics").isPresent(),
        "untouched connection Diagnostics should remain");

    serverPubSub.reconfigure(
        PubSubConfig.builder()
            .publishedDataSet(publishedDataSet(server, source))
            .connection(disabledConnection("c1"))
            .build(),
        PubSubService.ReconfigureMode.DISABLE_AFFECTED);

    assertFalse(
        node(server, "PubSub/c2/Diagnostics").isPresent(),
        "removed connection Diagnostics should be gone");
  }

  @Test
  void dataSetReaderExposesMessageSequenceNumberLiveValue() throws Exception {
    TestPubSubServer server = newServer();
    ServerPubSub serverPubSub = attachWithDiagnostics(server, readerConfig());
    serverPubSub.startup().get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);

    // Optional §9.1.11.12 MessageSequenceNumber (pin R13): a UInt16 LiveValue on the reader's
    // Diagnostics, backed by the DataSetReceivedEvent feed, reading 0 until a DataSet is received
    String path = "PubSub/rc1/rg1/reader1/Diagnostics/LiveValues/MessageSequenceNumber";
    UaVariableNode node = (UaVariableNode) node(server, path).orElseThrow();
    assertEquals(NodeIds.UInt16, node.getDataType());
    assertEquals(ushort(0), fragmentValue(server, path));
  }

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

  private ServerPubSub attachWithDiagnostics(TestPubSubServer server, PubSubConfig config) {
    return attach(
        server,
        config,
        ServerPubSubOptions.builder()
            .exposeInformationModel(true)
            .diagnosticsEnabled(true)
            .build());
  }

  private static PubSubConfig disabledConfig(TestPubSubServer server) {
    NodeId source =
        server.addVariable(
            "D_Source_" + System.nanoTime(), NodeIds.Double, new DataValue(Variant.ofDouble(1.5)));
    return PubSubConfig.builder()
        .publishedDataSet(publishedDataSet(server, source))
        .connection(disabledConnection("c1"))
        .build();
  }

  private static PublishedDataSetConfig publishedDataSet(TestPubSubServer server, NodeId source) {
    return PublishedDataSetConfig.builder("ds1")
        .field(
            FieldDefinition.builder("value")
                .source(nodeAddress(server, source))
                .dataType(NodeIds.Double)
                .dataSetFieldId(new UUID(0L, 1L))
                .build())
        .build();
  }

  /** A fully-disabled connection with one writer group/writer and one reader group. */
  private static PubSubConnectionConfig disabledConnection(String connection) {
    int base = 40000 + Math.floorMod(connection.hashCode(), 1000) * 2;
    int publisherId = 1 + Math.floorMod(connection.hashCode(), 60000);
    return PubSubConnectionConfig.udp(connection)
        .enabled(false)
        .publisherId(PublisherId.uint16(ushort(publisherId)))
        .address(UdpDatagramAddress.unicast("127.0.0.1", base))
        .discoveryAddress(UdpDatagramAddress.unicast("127.0.0.1", base + 1))
        .writerGroup(
            WriterGroupConfig.builder("wg1")
                .enabled(false)
                .writerGroupId(ushort(21))
                .publishingInterval(Duration.ofMillis(100))
                .messageSettings(GROUP_SETTINGS)
                .dataSetWriter(
                    DataSetWriterConfig.builder("w1")
                        .dataSet(new PublishedDataSetRef("ds1"))
                        .dataSetWriterId(ushort(31))
                        .fieldContentMask(FIELD_MASK)
                        .settings(WRITER_SETTINGS)
                        .build())
                .build())
        .readerGroup(ReaderGroupConfig.builder("rg1").build())
        .build();
  }

  /** A disabled UDP connection with one reader group holding a single DataSetReader. */
  private static PubSubConfig readerConfig() {
    return PubSubConfig.builder()
        .connection(
            PubSubConnectionConfig.udp("rc1")
                .enabled(false)
                .publisherId(PublisherId.uint16(ushort(7)))
                .address(UdpDatagramAddress.unicast("127.0.0.1", 40800))
                .discoveryAddress(UdpDatagramAddress.unicast("127.0.0.1", 40801))
                .readerGroup(
                    ReaderGroupConfig.builder("rg1")
                        .dataSetReader(
                            DataSetReaderConfig.builder("reader1")
                                .publisherId(PublisherId.uint16(ushort(7)))
                                .dataSetWriterId(ushort(31))
                                .build())
                        .build())
                .build())
        .build();
  }

  /** An enabled UDP publisher whose writer group reaches Operational and publishes. */
  private static PubSubConfig enabledPublisherConfig(TestPubSubServer server, NodeId source)
      throws SocketException {
    PublishedDataSetConfig dataSet =
        PublishedDataSetConfig.builder("ds1")
            .field(
                FieldDefinition.builder("value")
                    .source(nodeAddress(server, source))
                    .dataType(NodeIds.Double)
                    .dataSetFieldId(new UUID(0L, 1L))
                    .build())
            .build();
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
                        .publishingInterval(Duration.ofMillis(50))
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

  private static StatusCode callMethod(
      TestPubSubServer server, String objectPath, String methodName, AccessContext context) {
    NodeId objectId = fragmentNodeId(server, objectPath);
    NodeId methodId = fragmentNodeId(server, objectPath + "/" + methodName);
    UaMethodNode method = (UaMethodNode) node(server, objectPath + "/" + methodName).orElseThrow();
    return method
        .getInvocationHandler()
        .invoke(context, new CallMethodRequest(objectId, methodId, new Variant[0]))
        .getStatusCode();
  }

  private static StatusCode callRootReset(TestPubSubServer server, AccessContext context) {
    UaMethodNode method =
        (UaMethodNode)
            server
                .getServer()
                .getAddressSpaceManager()
                .getManagedNode(NodeIds.PublishSubscribe_Diagnostics_Reset)
                .orElseThrow();
    return method
        .getInvocationHandler()
        .invoke(
            context,
            new CallMethodRequest(
                NodeIds.PublishSubscribe_Diagnostics,
                NodeIds.PublishSubscribe_Diagnostics_Reset,
                new Variant[0]))
        .getStatusCode();
  }

  private static AccessContext session(TestPubSubServer server) {
    Session session = newSession(server.getServer());
    return () -> Optional.of(session);
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
        new NodeId(1, "wp-z-session-" + System.nanoTime()),
        "wp-z-session",
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

  private static Optional<UaNode> node(TestPubSubServer server, String identifier) {
    return server
        .getServer()
        .getAddressSpaceManager()
        .getManagedNode(fragmentNodeId(server, identifier));
  }

  private static @Nullable Object fragmentValue(TestPubSubServer server, String identifier) {
    return ((UaVariableNode) node(server, identifier).orElseThrow()).getValue().value().value();
  }

  private static @Nullable Object ns0Value(TestPubSubServer server, NodeId nodeId) {
    UaNode node = server.getServer().getAddressSpaceManager().getManagedNode(nodeId).orElseThrow();
    return ((UaVariableNode) node).getValue().value().value();
  }

  private static void awaitCount(TestPubSubServer server, NodeId nodeId, UShort expected)
      throws InterruptedException {
    long deadline = System.nanoTime() + TIMEOUT.toNanos();
    Object last = null;
    while (true) {
      last = ns0Value(server, nodeId);
      if (expected.equals(last)) {
        return;
      }
      if (System.nanoTime() >= deadline) {
        fail("timed out waiting for " + nodeId + " == " + expected + "; last=" + last);
      }
      Thread.sleep(25);
    }
  }

  private static void awaitCounterAbove(TestPubSubServer server, String counterPath, long threshold)
      throws InterruptedException {
    long deadline = System.nanoTime() + TIMEOUT.toNanos();
    Object last = null;
    while (true) {
      last = fragmentValue(server, counterPath);
      if (last instanceof UInteger value && value.longValue() > threshold) {
        return;
      }
      if (System.nanoTime() >= deadline) {
        fail("counter " + counterPath + " did not exceed " + threshold + "; last=" + last);
      }
      Thread.sleep(25);
    }
  }

  private static void awaitState(TestPubSubServer server, String componentPath, PubSubState state)
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
        if (state.equals(last)) {
          return;
        }
      }
      if (System.nanoTime() >= deadline) {
        fail("timed out waiting for State == " + state + " on " + componentPath + "; last=" + last);
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
