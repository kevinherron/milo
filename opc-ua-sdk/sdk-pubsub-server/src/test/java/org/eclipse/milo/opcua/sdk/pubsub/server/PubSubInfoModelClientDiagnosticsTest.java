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

import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.uint;
import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.ushort;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.net.DatagramSocket;
import java.net.SocketException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.function.Predicate;
import org.eclipse.milo.opcua.sdk.client.DiscoveryClient;
import org.eclipse.milo.opcua.sdk.client.OpcUaClient;
import org.eclipse.milo.opcua.sdk.client.OpcUaClientConfig;
import org.eclipse.milo.opcua.sdk.client.OpcUaClientConfigBuilder;
import org.eclipse.milo.opcua.sdk.client.subscriptions.OpcUaMonitoredItem;
import org.eclipse.milo.opcua.sdk.client.subscriptions.OpcUaSubscription;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubDiagnostics.ComponentDiagnostics;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubHandle;
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
import org.eclipse.milo.opcua.sdk.pubsub.security.PubSubSecurityPolicy;
import org.eclipse.milo.opcua.sdk.pubsub.server.PubSubMethodAuthorizer.Decision;
import org.eclipse.milo.opcua.sdk.server.RoleMapper;
import org.eclipse.milo.opcua.sdk.server.Session;
import org.eclipse.milo.opcua.sdk.server.nodes.UaNode;
import org.eclipse.milo.opcua.sdk.server.nodes.UaVariableNode;
import org.eclipse.milo.opcua.stack.core.AttributeId;
import org.eclipse.milo.opcua.stack.core.NamespaceTable;
import org.eclipse.milo.opcua.stack.core.NodeIds;
import org.eclipse.milo.opcua.stack.core.StatusCodes;
import org.eclipse.milo.opcua.stack.core.UaException;
import org.eclipse.milo.opcua.stack.core.types.UaEnumeratedType;
import org.eclipse.milo.opcua.stack.core.types.builtin.DataValue;
import org.eclipse.milo.opcua.stack.core.types.builtin.LocalizedText;
import org.eclipse.milo.opcua.stack.core.types.builtin.NodeId;
import org.eclipse.milo.opcua.stack.core.types.builtin.StatusCode;
import org.eclipse.milo.opcua.stack.core.types.builtin.Variant;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UInteger;
import org.eclipse.milo.opcua.stack.core.types.enumerated.BrowseDirection;
import org.eclipse.milo.opcua.stack.core.types.enumerated.DiagnosticsLevel;
import org.eclipse.milo.opcua.stack.core.types.enumerated.MessageSecurityMode;
import org.eclipse.milo.opcua.stack.core.types.enumerated.PubSubState;
import org.eclipse.milo.opcua.stack.core.types.enumerated.TimestampsToReturn;
import org.eclipse.milo.opcua.stack.core.types.structured.BrowseDescription;
import org.eclipse.milo.opcua.stack.core.types.structured.BrowseResult;
import org.eclipse.milo.opcua.stack.core.types.structured.CallMethodRequest;
import org.eclipse.milo.opcua.stack.core.types.structured.CallMethodResult;
import org.eclipse.milo.opcua.stack.core.types.structured.DataSetFieldContentMask;
import org.eclipse.milo.opcua.stack.core.types.structured.EndpointDescription;
import org.eclipse.milo.opcua.stack.core.types.structured.PubSubConfiguration2DataType;
import org.eclipse.milo.opcua.stack.core.types.structured.ReferenceDescription;
import org.eclipse.milo.opcua.stack.core.types.structured.UadpDataSetMessageContentMask;
import org.eclipse.milo.opcua.stack.core.types.structured.UadpNetworkMessageContentMask;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * WP-T5b: the Part 14 §9.1.11 diagnostics exposure, §9.1.9 PubSubCapabilities (R20), §9.1.10
 * Enable/Disable, and the R10 rebuild-on-reconfigure driven <b>end-to-end through a real {@link
 * OpcUaClient}</b> connected to a started, endpoint-bound embedded server.
 *
 * <p>Where {@link PubSubInfoModelDiagnosticsTest} and {@link PubSubInfoModelWritableTest} exercise
 * the fragment internals by reading nodes from the {@code AddressSpaceManager} directly and
 * invoking the method {@code InvocationHandler}s in-process, this class deepens that coverage over
 * the wire: every Browse, Read, and Call is a real service request over a real secure channel, so
 * the whole server-side chain runs — the {@code AccessController} Call gate ahead of each handler's
 * {@link PubSubMethodAuthorizer} check, the enum/UInt32 wire encoding, the fragment's read-time
 * {@code getValue} filters, and client subscription/monitored-item lifecycle across a reconfigure.
 *
 * <p>Each test spins up its own started {@link TestSksServer} (endpoint-bound on {@code 127.0.0.1},
 * ephemeral port) so no ns0 diagnostics binding or fragment registration leaks across tests, and
 * connects over the {@code None} endpoint — the diagnostics/Enable/Disable/Reset nodes carry no
 * AccessRestrictions, so the channel security mode is irrelevant to reaching the handlers, and any
 * configured {@code RoleMapper} applies regardless of channel. The published-dataset source is a
 * ns0 variable that always reads Good, so the fixture needs no application variables namespace.
 * Enabled configs use unicast {@code 127.0.0.1} on ephemeral ports with an explicit loopback {@code
 * discoveryAddress}; disabled configs open no sockets at all.
 */
class PubSubInfoModelClientDiagnosticsTest {

  private static final Duration TIMEOUT = Duration.ofSeconds(30);

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

  // A ns0 variable that always reads Good serves as the published-dataset source, so the fixture
  // needs no application variables namespace; AddressSpacePublishedDataSetSource reads it through
  // the server's AddressSpaceManager on each publish cycle.
  private static final NodeId SOURCE = NodeIds.Server_ServerStatus_CurrentTime;

  private final List<TestSksServer> servers = new CopyOnWriteArrayList<>();
  private final List<ServerPubSub> attached = new CopyOnWriteArrayList<>();
  private final List<OpcUaClient> clients = new CopyOnWriteArrayList<>();

  @AfterEach
  void tearDown() {
    for (OpcUaClient client : clients) {
      try {
        client.disconnect();
      } catch (Exception ignored) {
        // best effort
      }
    }
    clients.clear();
    for (ServerPubSub serverPubSub : attached) {
      serverPubSub.close();
    }
    attached.clear();
    for (TestSksServer server : servers) {
      try {
        server.close();
      } catch (Exception ignored) {
        // best effort
      }
    }
    servers.clear();
  }

  // region browse + read

  @Test
  void browsesRootAndPerComponentDiagnosticsOverClient() throws Exception {
    TestSksServer server = newServer(null);
    attachDiagnostics(server, disabledConfig());
    OpcUaClient client = connect(server);

    // Browse the ns0 root PubSubDiagnosticsRootType (i=17409): the §9.1.11.2 Table 310 members are
    // all reachable over the wire.
    List<String> rootChildren = browseChildNames(client, NodeIds.PublishSubscribe_Diagnostics);
    assertTrue(
        rootChildren.containsAll(
            List.of(
                "DiagnosticsLevel",
                "TotalInformation",
                "TotalError",
                "SubError",
                "Counters",
                "LiveValues",
                "Reset")),
        "root Diagnostics children over the wire: " + rootChildren);

    // DiagnosticsLevel reads Basic (R13); the enum crosses the wire as its Int32 value.
    assertEquals(
        DiagnosticsLevel.Basic.getValue(),
        enumValue(readValueOrThrow(client, NodeIds.PublishSubscribe_Diagnostics_DiagnosticsLevel)));

    // The connection node (grafted under ns0 PublishSubscribe) browses to its own Diagnostics
    // object, proving the fragment-minted per-component objects are reachable by browse.
    List<String> connectionChildren = browseChildNames(client, fragmentNodeId(server, "PubSub/c1"));
    assertTrue(
        connectionChildren.contains("Diagnostics"),
        "connection children over the wire: " + connectionChildren);

    // The per-component Diagnostics objects exist for connection/WG/RG/DSW and their
    // DiagnosticsLevel
    // markers are readable over the client.
    for (String path :
        List.of(
            "PubSub/c1/Diagnostics/DiagnosticsLevel",
            "PubSub/c1/wg1/Diagnostics/DiagnosticsLevel",
            "PubSub/c1/rg1/Diagnostics/DiagnosticsLevel",
            "PubSub/c1/wg1/w1/Diagnostics/DiagnosticsLevel")) {
      assertEquals(
          DiagnosticsLevel.Basic.getValue(),
          enumValue(readValueOrThrow(client, fragmentNodeId(server, path))),
          "expected a Basic DiagnosticsLevel at " + path);
    }

    // The WP-W per-kind counter nodes are readable over the client (all 0 while disabled).
    for (String counterPath :
        List.of(
            "PubSub/c1/wg1/Diagnostics/Counters/SentNetworkMessages",
            "PubSub/c1/wg1/Diagnostics/Counters/FailedTransmissions",
            "PubSub/c1/wg1/w1/Diagnostics/Counters/FailedDataSetMessages",
            "PubSub/c1/rg1/Diagnostics/Counters/ReceivedNetworkMessages")) {
      DataValue value = readValue(client, fragmentNodeId(server, counterPath));
      assertTrue(value.getStatusCode().isGood(), "counter not readable at " + counterPath);
      assertEquals(uint(0), value.getValue().getValue(), "counter should be 0 at " + counterPath);
    }

    // A counter's Mandatory Classification property is a readable enum property over the wire.
    DataValue classification =
        readValue(
            client,
            fragmentNodeId(
                server, "PubSub/c1/wg1/Diagnostics/Counters/SentNetworkMessages/Classification"));
    assertTrue(classification.getStatusCode().isGood());
    assertNotNull(classification.getValue().getValue());
  }

  @Test
  void readsCapabilitiesOverClient() throws Exception {
    TestSksServer server = newServer(null);
    attachDiagnostics(server, disabledConfig());
    OpcUaClient client = connect(server);

    // R20: Max* = 0 (no limit) over the wire.
    for (NodeId maxNode :
        List.of(
            NodeIds.PublishSubscribe_PubSubCapablities_MaxPubSubConnections,
            NodeIds.PublishSubscribe_PubSubCapablities_MaxWriterGroups,
            NodeIds.PublishSubscribe_PubSubCapablities_MaxDataSetWriters,
            NodeIds.PublishSubscribe_PubSubCapablities_MaxNetworkMessageSizeDatagram)) {
      assertEquals(uint(0), readValueOrThrow(client, maxNode), "expected Max = 0 at " + maxNode);
    }

    assertEquals(
        Boolean.TRUE,
        readValueOrThrow(
            client, NodeIds.PublishSubscribe_PubSubCapablities_SupportSecurityKeyPull));
    assertEquals(
        Boolean.FALSE,
        readValueOrThrow(
            client, NodeIds.PublishSubscribe_PubSubCapablities_SupportSecurityKeyPush));
    // SKS server face is off by default => SupportSecurityKeyServer false.
    assertEquals(
        Boolean.FALSE,
        readValueOrThrow(
            client, NodeIds.PublishSubscribe_PubSubCapablities_SupportSecurityKeyServer));
  }

  @Test
  void capabilitiesReportSecurityKeyServerWhenSksEnabledOverClient() throws Exception {
    TestSksServer server = newServer(null);
    ServerPubSubOptions options =
        ServerPubSubOptions.builder()
            .exposeInformationModel(true)
            .diagnosticsEnabled(true)
            .sksServerEnabled(true)
            .build();
    attach(server, sksConfig(), options);
    OpcUaClient client = connect(server);

    // R20 per-option: with the SKS server face enabled the capability flips true over the wire.
    assertEquals(
        Boolean.TRUE,
        readValueOrThrow(
            client, NodeIds.PublishSubscribe_PubSubCapablities_SupportSecurityKeyServer));
  }

  @Test
  void readsConnectionResolvedAddressOverClient() throws Exception {
    TestSksServer server = newServer(null);
    attachDiagnostics(server, disabledConfig());
    OpcUaClient client = connect(server);

    // R15: the connection LiveValue carries the resolved UDP host; 127.0.0.1 resolves to itself.
    assertEquals(
        "127.0.0.1",
        readValueOrThrow(
            client, fragmentNodeId(server, "PubSub/c1/Diagnostics/LiveValues/ResolvedAddress")));
  }

  // endregion

  // region value cross-check (R13/R14 + UInt32 clamp semantics)

  @Test
  void counterNodeTracksEngineSnapshotOverClient() throws Exception {
    TestSksServer server = newServer(null);
    ServerPubSub serverPubSub = attachDiagnostics(server, enabledPublisherConfig());
    OpcUaClient client = connect(server);

    awaitState(server, "PubSub/c1/wg1", PubSubState.Operational);
    awaitEngineNetworkMessagesSent(serverPubSub, "c1/wg1", 0L);

    // Freeze the counter: disable the writer group so no further NetworkMessages are sent and the
    // node read and the engine snapshot cannot straddle an increment.
    PubSubHandle writerGroup =
        serverPubSub.runtime().components().writerGroup("c1", "wg1").orElseThrow();
    serverPubSub.runtime().disable(writerGroup);
    awaitState(server, "PubSub/c1/wg1", PubSubState.Disabled);
    settle();

    NodeId counterId =
        fragmentNodeId(server, "PubSub/c1/wg1/Diagnostics/Counters/SentNetworkMessages");

    long engine =
        serverPubSub
            .runtime()
            .diagnostics()
            .component("c1/wg1")
            .map(ComponentDiagnostics::networkMessagesSent)
            .orElseThrow();
    assertTrue(engine > 0, "expected the writer group to have sent NetworkMessages");

    DataValue firstRead = readValue(client, counterId);
    UInteger exposed = (UInteger) firstRead.getValue().getValue();

    // Exposure clamps the 64-bit engine counter to UInt32 (§9.1.11.5); below the cap they agree.
    assertEquals(ComponentDiagnostics.toUInt32Saturating(engine), exposed.longValue());

    // The observable half of the cap semantics: the read-time getValue filter stamps a fresh
    // SourceTimestamp on every read, so even with the value frozen the timestamp keeps advancing
    // (which is exactly what §9.1.11.5 requires once the value pins at 0xFFFFFFFF). Forcing the
    // actual 2^32 cap needs an internal DiagnosticsCollector seam not reachable from this module
    // (see the WP-T5b notes) and is unit-covered in sdk-pubsub's DiagnosticsCollectorTest.
    assertNotNull(firstRead.getSourceTime());
    DataValue secondRead = readValue(client, counterId);
    assertEquals(
        exposed, secondRead.getValue().getValue(), "frozen counter value should not change");
    assertNotNull(secondRead.getSourceTime());
    assertTrue(
        secondRead.getSourceTime().getUtcTime() >= firstRead.getSourceTime().getUtcTime(),
        "SourceTimestamp should keep advancing across reads");
  }

  // endregion

  // region Reset round-trip (R18 + R9)

  @Test
  void perComponentResetOverClientZeroesCountersAndPreservesLastError() throws Exception {
    TestSksServer server = newServer(null);
    ServerPubSub serverPubSub = attachDiagnostics(server, enabledPublisherConfig());
    OpcUaClient client = connect(server);

    awaitState(server, "PubSub/c1/wg1", PubSubState.Operational);
    awaitEngineNetworkMessagesSent(serverPubSub, "c1/wg1", 0L);

    PubSubHandle writerGroup =
        serverPubSub.runtime().components().writerGroup("c1", "wg1").orElseThrow();
    serverPubSub.runtime().disable(writerGroup);
    awaitState(server, "PubSub/c1/wg1", PubSubState.Disabled);
    settle();

    NodeId counterId =
        fragmentNodeId(server, "PubSub/c1/wg1/Diagnostics/Counters/SentNetworkMessages");
    long before = ((UInteger) readValueOrThrow(client, counterId)).longValue();
    assertTrue(before > 0, "expected a non-zero SentNetworkMessages before reset");

    Optional<StatusCode> lastErrorBefore =
        serverPubSub
            .runtime()
            .diagnostics()
            .component("c1/wg1")
            .map(ComponentDiagnostics::lastError);

    // With no RoleMapper the default authorizer allows any authenticated session (pin R9); the real
    // client Call runs the AccessController Call gate then the handler's checkConfigure.
    NodeId diagnosticsId = fragmentNodeId(server, "PubSub/c1/wg1/Diagnostics");
    NodeId resetId = fragmentNodeId(server, "PubSub/c1/wg1/Diagnostics/Reset");
    assertEquals(StatusCode.GOOD, call(client, diagnosticsId, resetId));

    assertEquals(0L, ((UInteger) readValueOrThrow(client, counterId)).longValue());

    // Reset is specified for counters only: lastError is left untouched (pin R12/§9.1.11.3).
    Optional<StatusCode> lastErrorAfter =
        serverPubSub
            .runtime()
            .diagnostics()
            .component("c1/wg1")
            .map(ComponentDiagnostics::lastError);
    assertEquals(lastErrorBefore, lastErrorAfter, "Reset must not clear lastError");
  }

  @Test
  void configMethodsRequireConfigureAdminRoleOverClient() throws Exception {
    var roleMapper = new TestRoleMapper();
    TestSksServer server = newServer(roleMapper);
    ServerPubSubOptions options =
        ServerPubSubOptions.builder()
            .exposeInformationModel(true)
            .diagnosticsEnabled(true)
            .allowRemoteConfiguration(true)
            .build();
    attach(server, disabledConfig(), options);
    OpcUaClient client = connect(server);

    NodeId diagnosticsId = fragmentNodeId(server, "PubSub/c1/wg1/Diagnostics");
    NodeId resetId = fragmentNodeId(server, "PubSub/c1/wg1/Diagnostics/Reset");
    NodeId statusId = fragmentNodeId(server, "PubSub/c1/wg1/Status");
    NodeId enableId = fragmentNodeId(server, "PubSub/c1/wg1/Status/Enable");

    // Without ConfigureAdmin the default authorizer denies over the wire (pin R9).
    roleMapper.setRoleIds(List.of());
    assertEquals(StatusCodes.Bad_UserAccessDenied, call(client, diagnosticsId, resetId).getValue());
    assertEquals(StatusCodes.Bad_UserAccessDenied, call(client, statusId, enableId).getValue());

    // With ConfigureAdmin both are permitted (Reset zeroes; Enable moves the disabled WG off
    // Disabled — the parent connection is disabled so it goes Paused, opening no sockets).
    roleMapper.setRoleIds(List.of(NodeIds.WellKnownRole_ConfigureAdmin));
    assertEquals(StatusCode.GOOD, call(client, diagnosticsId, resetId));
    assertEquals(StatusCode.GOOD, call(client, statusId, enableId));
  }

  @Test
  void configMethodsDeniedOverClientByAuthorizer() throws Exception {
    TestSksServer server = newServer(null);
    ServerPubSubOptions options =
        ServerPubSubOptions.builder()
            .exposeInformationModel(true)
            .diagnosticsEnabled(true)
            .allowRemoteConfiguration(true)
            .methodAuthorizer(denyConfigureAuthorizer())
            .build();
    attach(server, disabledConfig(), options);
    OpcUaClient client = connect(server);

    NodeId diagnosticsId = fragmentNodeId(server, "PubSub/c1/wg1/Diagnostics");
    NodeId resetId = fragmentNodeId(server, "PubSub/c1/wg1/Diagnostics/Reset");
    NodeId statusId = fragmentNodeId(server, "PubSub/c1/wg1/Status");
    NodeId enableId = fragmentNodeId(server, "PubSub/c1/wg1/Status/Enable");
    NodeId disableId = fragmentNodeId(server, "PubSub/c1/wg1/Status/Disable");

    // A denying authorizer rejects Reset AND Enable/Disable over the wire (pin R9).
    assertEquals(StatusCodes.Bad_UserAccessDenied, call(client, diagnosticsId, resetId).getValue());
    assertEquals(StatusCodes.Bad_UserAccessDenied, call(client, statusId, enableId).getValue());
    assertEquals(StatusCodes.Bad_UserAccessDenied, call(client, statusId, disableId).getValue());
  }

  // endregion

  // region Enable/Disable (§9.1.10)

  @Test
  void enableDisableOverClientDrivesPubSubState() throws Exception {
    TestSksServer server = newServer(null);
    ServerPubSubOptions options =
        ServerPubSubOptions.builder()
            .exposeInformationModel(true)
            .allowRemoteConfiguration(true)
            .build();
    attach(server, enabledPublisherConfig(), options);
    OpcUaClient client = connect(server);

    awaitState(server, "PubSub/c1/wg1", PubSubState.Operational);

    NodeId statusId = fragmentNodeId(server, "PubSub/c1/wg1/Status");
    NodeId stateId = fragmentNodeId(server, "PubSub/c1/wg1/Status/State");
    NodeId enableId = fragmentNodeId(server, "PubSub/c1/wg1/Status/Enable");
    NodeId disableId = fragmentNodeId(server, "PubSub/c1/wg1/Status/Disable");

    // Enable on an Operational component: Bad_InvalidState (§9.1.10.2).
    assertEquals(StatusCodes.Bad_InvalidState, call(client, statusId, enableId).getValue());

    // Disable succeeds; the state change is observable over the client.
    assertEquals(StatusCode.GOOD, call(client, statusId, disableId));
    awaitState(server, "PubSub/c1/wg1", PubSubState.Disabled);
    assertEquals(PubSubState.Disabled.getValue(), enumValue(readValueOrThrow(client, stateId)));

    // Disable on an already-Disabled component: Bad_InvalidState (§9.1.10.3).
    assertEquals(StatusCodes.Bad_InvalidState, call(client, statusId, disableId).getValue());

    // Enable succeeds again from Disabled; the component leaves the Disabled state.
    assertEquals(StatusCode.GOOD, call(client, statusId, enableId));
    awaitStateNot(server, "PubSub/c1/wg1", PubSubState.Disabled);
    assertFalse(
        PubSubState.Disabled.getValue() == enumValue(readValueOrThrow(client, stateId)),
        "the component should have left Disabled over the client");
  }

  @Test
  void enableDisableDoNotTriggerStoreSaveOverClient() throws Exception {
    TestSksServer server = newServer(null);
    var store = new CountingStore();
    ServerPubSubOptions options =
        ServerPubSubOptions.builder()
            .exposeInformationModel(true)
            .allowRemoteConfiguration(true)
            .configurationStore(store)
            .build();
    attach(server, disabledConfig(), options);
    OpcUaClient client = connect(server);

    // The attach persisted the config once (S7); Enable/Disable are not config mutations (pin R8).
    int baseline = store.saveCount;
    assertTrue(baseline >= 1, "attach should have saved the config once");

    NodeId statusId = fragmentNodeId(server, "PubSub/c1/wg1/Status");
    NodeId enableId = fragmentNodeId(server, "PubSub/c1/wg1/Status/Enable");
    NodeId disableId = fragmentNodeId(server, "PubSub/c1/wg1/Status/Disable");

    // A disabled WG under a disabled connection goes Paused on Enable (no sockets), then Disabled.
    assertEquals(StatusCode.GOOD, call(client, statusId, enableId));
    assertEquals(StatusCode.GOOD, call(client, statusId, disableId));

    assertEquals(baseline, store.saveCount, "Enable/Disable must not trigger store.save (pin R8)");
  }

  // endregion

  // region rebuild-on-reconfigure (R10)

  @Test
  void reconfigureTracksDiagnosticsSubtreesAndSparesMonitoredItemsOverClient() throws Exception {
    TestSksServer server = newServer(null);
    ServerPubSub serverPubSub = attachDiagnostics(server, disabledConfig());
    OpcUaClient client = connect(server);

    NodeId c1Counter =
        fragmentNodeId(server, "PubSub/c1/wg1/Diagnostics/Counters/SentNetworkMessages");
    NodeId c2Counter =
        fragmentNodeId(server, "PubSub/c2/wg2/Diagnostics/Counters/SentNetworkMessages");

    // A client monitored item on an unaffected subtree (c1) must survive the reconfigure.
    OpcUaSubscription subscription = new OpcUaSubscription(client);
    subscription.create();
    OpcUaMonitoredItem c1Item = OpcUaMonitoredItem.newDataItem(c1Counter);
    subscription.addMonitoredItem(c1Item);
    subscription.createMonitoredItems();
    assertEquals(OpcUaMonitoredItem.SyncState.SYNCHRONIZED, c1Item.getSyncState());

    // Before: c1 present, c2 absent (Bad_NodeIdUnknown over the wire).
    assertTrue(readValue(client, c1Counter).getStatusCode().isGood());
    assertEquals(
        StatusCodes.Bad_NodeIdUnknown, readValue(client, c2Counter).getStatusCode().getValue());

    // Add a second connection via the info-model-consistent reconfigure (R10).
    PubSubConfig withC2 =
        PubSubConfig.builder()
            .publishedDataSet(publishedDataSet(false))
            .connection(disabledConnection("c1", "wg1", "w1"))
            .connection(disabledConnection("c2", "wg2", "w2"))
            .build();
    serverPubSub.reconfigure(withC2, PubSubService.ReconfigureMode.DISABLE_AFFECTED);

    // The added subtree and its Diagnostics counter appear over the client; the untouched c1
    // subtree and its monitored item survive.
    assertTrue(
        readValue(client, c2Counter).getStatusCode().isGood(), "added c2 counter unreadable");
    assertTrue(readValue(client, c1Counter).getStatusCode().isGood(), "untouched c1 counter lost");
    assertEquals(
        OpcUaMonitoredItem.SyncState.SYNCHRONIZED,
        c1Item.getSyncState(),
        "the c1 monitored item should survive the reconfigure");

    // Remove the second connection: its Diagnostics subtree disappears; c1 still stands.
    serverPubSub.reconfigure(disabledConfig(), PubSubService.ReconfigureMode.DISABLE_AFFECTED);

    assertEquals(
        StatusCodes.Bad_NodeIdUnknown,
        readValue(client, c2Counter).getStatusCode().getValue(),
        "removed c2 counter should be gone");
    assertTrue(readValue(client, c1Counter).getStatusCode().isGood(), "c1 counter should remain");

    subscription.delete();
  }

  // endregion

  // region fixtures and helpers

  private TestSksServer newServer(@Nullable RoleMapper roleMapper) throws Exception {
    TestSksServer server = TestSksServer.create(roleMapper);
    servers.add(server);
    return server;
  }

  private ServerPubSub attach(
      TestSksServer server, PubSubConfig config, ServerPubSubOptions options) {
    ServerPubSub serverPubSub = ServerPubSub.attach(server.getServer(), config, options);
    attached.add(serverPubSub);
    try {
      serverPubSub.startup().get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
    return serverPubSub;
  }

  private ServerPubSub attachDiagnostics(TestSksServer server, PubSubConfig config) {
    return attach(
        server,
        config,
        ServerPubSubOptions.builder()
            .exposeInformationModel(true)
            .diagnosticsEnabled(true)
            .build());
  }

  private OpcUaClient connect(TestSksServer server) throws Exception {
    List<EndpointDescription> endpoints =
        DiscoveryClient.getEndpoints(server.getEndpointUrl())
            .get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);

    EndpointDescription endpoint =
        endpoints.stream()
            .filter(e -> e.getSecurityMode() == MessageSecurityMode.None)
            .findFirst()
            .orElseThrow(() -> new IllegalStateException("no None endpoint"));

    OpcUaClientConfigBuilder configBuilder = OpcUaClientConfig.builder();
    configBuilder.setEndpoint(endpoint);
    configBuilder.setApplicationName(LocalizedText.english("wp-t5b diagnostics client"));
    configBuilder.setApplicationUri("urn:eclipse:milo:pubsub:wp-t5b-client");
    configBuilder.setRequestTimeout(uint(TIMEOUT.toMillis()));

    OpcUaClient client = OpcUaClient.create(configBuilder.build());
    client.connect();
    clients.add(client);
    return client;
  }

  private static NodeId fragmentNodeId(TestSksServer server, String identifier) {
    return new NodeId(server.getServer().getServerNamespace().getNamespaceIndex(), identifier);
  }

  private static DataValue readValue(OpcUaClient client, NodeId nodeId) throws UaException {
    return client.readValues(0.0, TimestampsToReturn.Both, List.of(nodeId)).get(0);
  }

  private static @Nullable Object readValueOrThrow(OpcUaClient client, NodeId nodeId)
      throws UaException {
    DataValue value = readValue(client, nodeId);
    if (value.getStatusCode().isBad()) {
      fail("read of " + nodeId + " failed: " + value.getStatusCode());
    }
    return value.getValue().getValue();
  }

  private static StatusCode call(
      OpcUaClient client, NodeId objectId, NodeId methodId, Variant... args) throws UaException {
    var request = new CallMethodRequest(objectId, methodId, args);
    CallMethodResult[] results = client.call(List.of(request)).getResults();
    assertNotNull(results);
    assertEquals(1, results.length);
    return results[0].getStatusCode();
  }

  private static List<String> browseChildNames(OpcUaClient client, NodeId nodeId)
      throws UaException {
    BrowseResult result =
        client.browse(
            new BrowseDescription(
                nodeId,
                BrowseDirection.Forward,
                NodeIds.HierarchicalReferences,
                true,
                uint(0),
                uint(63)));

    ReferenceDescription[] references = result.getReferences();
    var names = new ArrayList<String>();
    if (references != null) {
      for (ReferenceDescription reference : references) {
        names.add(reference.getBrowseName().getName());
      }
    }
    return names;
  }

  private static int enumValue(@Nullable Object value) {
    if (value instanceof UaEnumeratedType enumerated) {
      return enumerated.getValue();
    }
    if (value instanceof Number number) {
      return number.intValue();
    }
    throw new AssertionError("not an enum or numeric value: " + value);
  }

  /**
   * A short quiescence window after a freeze so a final in-flight publish cannot race the reads.
   */
  private static void settle() throws InterruptedException {
    Thread.sleep(150);
  }

  private void awaitEngineNetworkMessagesSent(
      ServerPubSub serverPubSub, String path, long threshold) throws InterruptedException {
    long deadline = System.nanoTime() + TIMEOUT.toNanos();
    long last = 0;
    while (true) {
      last =
          serverPubSub
              .runtime()
              .diagnostics()
              .component(path)
              .map(ComponentDiagnostics::networkMessagesSent)
              .orElse(0L);
      if (last > threshold) {
        return;
      }
      if (System.nanoTime() >= deadline) {
        fail("networkMessagesSent for " + path + " did not exceed " + threshold + "; last=" + last);
      }
      Thread.sleep(25);
    }
  }

  private void awaitState(TestSksServer server, String componentPath, PubSubState state)
      throws InterruptedException {
    awaitStateValue(server, componentPath, state::equals, "State == " + state);
  }

  private void awaitStateNot(TestSksServer server, String componentPath, PubSubState state)
      throws InterruptedException {
    awaitStateValue(server, componentPath, value -> !state.equals(value), "State != " + state);
  }

  private void awaitStateValue(
      TestSksServer server, String componentPath, Predicate<Object> predicate, String description)
      throws InterruptedException {

    NodeId stateId = fragmentNodeId(server, componentPath + "/Status/State");
    long deadline = System.nanoTime() + TIMEOUT.toNanos();
    Object last = null;
    while (true) {
      Optional<UaNode> managed =
          server.getServer().getAddressSpaceManager().getManagedNode(stateId);
      if (managed.isPresent()) {
        last = ((UaVariableNode) managed.get()).getValue().value().value();
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

  private static PubSubConfig disabledConfig() {
    return PubSubConfig.builder()
        .publishedDataSet(publishedDataSet(false))
        .connection(disabledConnection("c1", "wg1", "w1"))
        .build();
  }

  private static PubSubConfig sksConfig() {
    return PubSubConfig.builder()
        .securityGroup(
            SecurityGroupConfig.builder("GroupA")
                .securityPolicyUri(PubSubSecurityPolicy.Aes128Ctr.getUri())
                .keyLifeTime(Duration.ofHours(1))
                .maxFutureKeyCount(uint(3))
                .build())
        .publishedDataSet(publishedDataSet(false))
        .connection(disabledConnection("c1", "wg1", "w1"))
        .build();
  }

  private static PublishedDataSetConfig publishedDataSet(boolean extraField) {
    PublishedDataSetConfig.Builder builder =
        PublishedDataSetConfig.builder("ds1")
            .field(
                FieldDefinition.builder("value")
                    .source(nodeAddress(SOURCE))
                    .dataType(NodeIds.DateTime)
                    .dataSetFieldId(new UUID(0L, 1L))
                    .build());
    if (extraField) {
      builder.field(
          FieldDefinition.builder("value2")
              .source(nodeAddress(SOURCE))
              .dataType(NodeIds.DateTime)
              .dataSetFieldId(new UUID(0L, 2L))
              .build());
    }
    return builder.build();
  }

  private static PubSubConnectionConfig disabledConnection(
      String connection, String group, String writer) {
    // disabled connections never bind a socket, so fixed deterministic ports keep the config stable
    // across reconfigures (component config equality drives the incremental R10 rebuild)
    int base = 41000 + Math.floorMod(connection.hashCode(), 1000) * 2;
    // each connection is its own publisher-id scope so the reused writerGroupId/dataSetWriterId in
    // a
    // multi-connection config (the rebuild test's c1 + c2) do not collide
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
                .publishingInterval(Duration.ofMillis(100))
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

  private static PubSubConfig enabledPublisherConfig() throws SocketException {
    PublishedDataSetConfig dataSet = publishedDataSet(false);
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
                .readerGroup(ReaderGroupConfig.builder("rg1").build())
                .build())
        .build();
  }

  private static NodeFieldAddress nodeAddress(NodeId nodeId) {
    // the source is a ns0 node, so a bare NamespaceTable (index 0 = the OPC UA namespace) suffices
    // to encode its address; the server resolves the same URI back to index 0 at attach/read time
    return NodeFieldAddress.of(nodeId, AttributeId.Value, new NamespaceTable());
  }

  private static int freeUdpPort() throws SocketException {
    try (DatagramSocket socket = new DatagramSocket(0)) {
      return socket.getLocalPort();
    }
  }

  /** A {@link PubSubConfigurationStore} that counts {@code save} invocations. */
  private static final class CountingStore implements PubSubConfigurationStore {

    private volatile int saveCount;

    @Override
    public @Nullable PubSubConfiguration2DataType load() {
      return null;
    }

    @Override
    public void save(PubSubConfiguration2DataType value) {
      saveCount++;
    }
  }

  // endregion
}
