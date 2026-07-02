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

import java.net.DatagramSocket;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;
import java.util.function.Predicate;
import org.eclipse.milo.opcua.sdk.client.OpcUaClient;
import org.eclipse.milo.opcua.sdk.client.subscriptions.EventFilterBuilder;
import org.eclipse.milo.opcua.sdk.client.subscriptions.OpcUaMonitoredItem;
import org.eclipse.milo.opcua.sdk.client.subscriptions.OpcUaSubscription;
import org.eclipse.milo.opcua.sdk.pubsub.ComponentType;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubDiagnosticsEvent;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubHandle;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubService;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubStateChangeEvent;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubStateChangeEvent.Cause;
import org.eclipse.milo.opcua.sdk.pubsub.config.DataSetReaderConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.PubSubConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.PubSubConnectionConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.PublisherId;
import org.eclipse.milo.opcua.sdk.pubsub.config.ReaderGroupConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.UdpDatagramAddress;
import org.eclipse.milo.opcua.sdk.server.OpcUaServer;
import org.eclipse.milo.opcua.sdk.server.model.objects.BaseEventTypeNode;
import org.eclipse.milo.opcua.sdk.server.model.objects.PubSubStatusEventTypeNode;
import org.eclipse.milo.opcua.stack.core.NodeIds;
import org.eclipse.milo.opcua.stack.core.StatusCodes;
import org.eclipse.milo.opcua.stack.core.types.builtin.ByteString;
import org.eclipse.milo.opcua.stack.core.types.builtin.DateTime;
import org.eclipse.milo.opcua.stack.core.types.builtin.ExtensionObject;
import org.eclipse.milo.opcua.stack.core.types.builtin.LocalizedText;
import org.eclipse.milo.opcua.stack.core.types.builtin.NodeId;
import org.eclipse.milo.opcua.stack.core.types.builtin.QualifiedName;
import org.eclipse.milo.opcua.stack.core.types.builtin.StatusCode;
import org.eclipse.milo.opcua.stack.core.types.builtin.Variant;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UShort;
import org.eclipse.milo.opcua.stack.core.types.enumerated.FilterOperator;
import org.eclipse.milo.opcua.stack.core.types.enumerated.PubSubState;
import org.eclipse.milo.opcua.stack.core.types.structured.ContentFilter;
import org.eclipse.milo.opcua.stack.core.types.structured.ContentFilterElement;
import org.eclipse.milo.opcua.stack.core.types.structured.EventFilter;
import org.eclipse.milo.opcua.stack.core.types.structured.LiteralOperand;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

/**
 * CLIENT-SIDE reception of Part 14 §9.1.13 PubSub status events over a <b>real</b> {@link
 * OpcUaClient} event Subscription against a started, endpoint-bound embedded {@link OpcUaServer}.
 *
 * <p>Complements {@link PubSubStatusEventTest}, which observes the {@link PubSubStatusEventBridge}
 * through a direct {@code EventNotifier} listener on an endpoint-less, never-started fixture: that
 * proves the bridge <em>fires</em> the right events; this proves a real client subscribed to Events
 * on the Server Object ({@code i=2253}) with an {@code OfType(i=15535)} filter <em>receives</em>
 * them — the abstract base {@code PubSubStatusEventType} state changes and, via subtype-aware
 * {@code OfType} matching, the {@code PubSubCommunicationFailureEventType} ({@code i=15563})
 * subtype — with the §9.1.13 fields (SourceNode/ConnectionId/GroupId/State/Error/Severity) intact
 * end-to-end through UA encoding and the event filter.
 *
 * <p>Two drive mechanisms are used deliberately:
 *
 * <ul>
 *   <li><b>Fully engine-driven</b> (real {@link ServerPubSub} + {@code runtime()} enable/disable):
 *       state-change events, the {@code statusEventsEnabled} gate, and clean teardown. This is the
 *       true end-to-end path (engine transition → bridge → EventNotifier → client).
 *   <li><b>Bridge public listener entry point</b> ({@link PubSubStatusEventBridge#onStateChange} /
 *       {@link PubSubStatusEventBridge#onDiagnosticsEvent}, the same seam {@link
 *       PubSubStatusEventTest} uses): communication-failure reception, un-flattened {@code Error}
 *       code, first-failure-per-episode suppression, and DISPOSE suppression. A genuine engine send
 *       failure cannot be produced deterministically and CI-safely through {@code ServerPubSub}
 *       (its only built-in transport is connectionless UDP, whose loopback sends do not fail, and
 *       it exposes no transport-provider injection point); the engine's production of an
 *       un-flattened "failed to send" diagnostics event is covered by the sdk-pubsub engine unit
 *       tests. Here the real bridge does its real discrimination, field mapping, and emission, and
 *       the assertion is on client reception.
 * </ul>
 *
 * <p>The server is shared across tests (PER_CLASS); each test creates and deletes its own
 * subscription and attaches/closes its own {@link ServerPubSub} or bridge, so no state leaks
 * between tests. Reception is asserted by polling the collected events with a generous deadline —
 * never a fixed sleep as a timing assertion — because event delivery is asynchronous (Publish
 * cycle).
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class PubSubStatusEventClientTest {

  private static final Duration TIMEOUT = Duration.ofSeconds(15);

  /** A code that is not the historically-flattened {@code Bad_CommunicationError}. */
  private static final StatusCode UNFLATTENED = new StatusCode(StatusCodes.Bad_ConnectionClosed);

  // Select-clause indices (fixed order built in newStatusEventSubscription).
  private static final int EVENT_TYPE = 0;
  private static final int SEVERITY = 1;
  private static final int SOURCE_NODE = 2;
  private static final int STATE = 4;
  private static final int CONNECTION_ID = 5;
  private static final int GROUP_ID = 6;
  private static final int ERROR = 7;

  private EmbeddedClientServer harness;
  private OpcUaServer server;
  private OpcUaClient client;
  private UShort ns;

  @BeforeAll
  void startClientServer() throws Exception {
    harness = EmbeddedClientServer.start();
    server = harness.server();
    client = harness.client();
    // the bridge builds NodeIds in the server (application) namespace; mirror that for assertions
    ns = server.getServerNamespace().getNamespaceIndex();
  }

  @AfterAll
  void stopClientServer() throws Exception {
    if (harness != null) {
      harness.close();
    }
  }

  // region both subtypes via a single OfType filter (bridge entry points, real emission)

  @Test
  void clientReceivesBothStatusEventSubtypesViaSingleOfTypeFilter() throws Exception {
    PubSubService service = PubSubService.create(readerConfig("both"));
    var bridge = new PubSubStatusEventBridge(server, service);
    var collector = new EventCollector();
    OpcUaSubscription subscription = newStatusEventSubscription(collector);
    try {
      // a base-type state change (i=15535) and a subtype communication failure (i=15563), both
      // for the same writer group, over ONE OfType(i=15535) subscription
      bridge.onStateChange(
          stateChange(ComponentType.WRITER_GROUP, "both/wg", PubSubState.Operational));
      bridge.onDiagnosticsEvent(sendFailure("both/wg", UNFLATTENED));

      Variant[] stateEvent =
          awaitEvent(
              collector,
              e ->
                  NodeIds.PubSubStatusEventType.equals(eventType(e))
                      && componentNodeId("both/wg").equals(sourceNode(e)));
      assertNotNull(stateEvent, "base PubSubStatusEventType state change not received");
      assertEquals(componentNodeId("both"), connectionId(stateEvent));
      assertEquals(componentNodeId("both/wg"), groupId(stateEvent));
      assertEquals(PubSubState.Operational.getValue(), stateValue(stateEvent));
      assertTrue(
          isInformational(severity(stateEvent)),
          "non-Error state change must be informational (<=333)");

      Variant[] failureEvent =
          awaitEvent(
              collector, e -> NodeIds.PubSubCommunicationFailureEventType.equals(eventType(e)));
      assertNotNull(
          failureEvent,
          "PubSubCommunicationFailureEventType (i=15563) subtype not received via OfType(i=15535)");
      assertEquals(componentNodeId("both/wg"), sourceNode(failureEvent));
      assertEquals(componentNodeId("both"), connectionId(failureEvent));
      assertEquals(componentNodeId("both/wg"), groupId(failureEvent));
      // the real un-flattened transport StatusCode is surfaced verbatim in Error
      assertEquals(
          UNFLATTENED, error(failureEvent), "Error must carry the un-flattened StatusCode");
      // State reflects the last tracked state (Operational from the prior transition)
      assertEquals(PubSubState.Operational.getValue(), stateValue(failureEvent));
      assertTrue(
          isErrorBand(severity(failureEvent)),
          "communication failure must be Error-band severity (334-666)");
    } finally {
      deleteQuietly(subscription);
      service.close();
    }
  }

  // endregion

  // region fully engine-driven state changes (real ServerPubSub)

  @Test
  void clientReceivesEngineDrivenStateChangeEvents() throws Exception {
    ServerPubSub serverPubSub =
        ServerPubSub.attach(
            server,
            readerConfig("engine"),
            ServerPubSubOptions.builder().statusEventsEnabled(true).build());
    serverPubSub.startup().get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);

    var collector = new EventCollector();
    OpcUaSubscription subscription = newStatusEventSubscription(collector);
    try {
      PubSubHandle readerGroup =
          serverPubSub.runtime().components().readerGroup("engine", "grp").orElseThrow();

      // disable -> Disabled (informational, base type), driven by the engine through the bridge
      serverPubSub.runtime().disable(readerGroup);
      Variant[] disabled =
          awaitEvent(
              collector,
              e ->
                  componentNodeId("engine/grp").equals(sourceNode(e))
                      && stateValue(e) == PubSubState.Disabled.getValue());
      assertNotNull(disabled, "Disabled state-change event for the reader group not received");
      assertEquals(NodeIds.PubSubStatusEventType, eventType(disabled));
      assertEquals(componentNodeId("engine"), connectionId(disabled));
      assertEquals(componentNodeId("engine/grp"), groupId(disabled));
      assertTrue(isInformational(severity(disabled)), "Disabled entry must be informational");

      // re-enable -> the group completes startup synchronously back to Operational
      serverPubSub.runtime().enable(readerGroup);
      Variant[] operational =
          awaitEvent(
              collector,
              e ->
                  componentNodeId("engine/grp").equals(sourceNode(e))
                      && stateValue(e) == PubSubState.Operational.getValue());
      assertNotNull(
          operational, "Operational state-change event for the reader group not received");
      assertEquals(NodeIds.PubSubStatusEventType, eventType(operational));
      assertTrue(
          isInformational(severity(operational)),
          "Operational entry must be informational (<=333)");
    } finally {
      deleteQuietly(subscription);
      serverPubSub.close();
    }
  }

  // endregion

  // region DISPOSE suppression (bridge entry point, real emission)

  @Test
  void clientReceivesNoEventForDisposeDrivenTransition() throws Exception {
    PubSubService service = PubSubService.create(readerConfig("disp"));
    var bridge = new PubSubStatusEventBridge(server, service);
    var collector = new EventCollector();
    OpcUaSubscription subscription = newStatusEventSubscription(collector);
    try {
      // a DISPOSE-cause teardown transition (reconfigure-removal / shutdown) must NOT emit an event
      bridge.onStateChange(
          new PubSubStateChangeEvent(
              new PubSubHandle(ComponentType.DATA_SET_READER, "disp/grp/r2"),
              PubSubState.PreOperational,
              PubSubState.Disabled,
              StatusCode.GOOD,
              Cause.DISPOSE));

      // a following non-DISPOSE transition on a sibling IS emitted; its arrival at the client is
      // the ordering sentinel that guarantees any dispose event would already have been delivered
      bridge.onStateChange(
          stateChange(ComponentType.DATA_SET_READER, "disp/grp/r1", PubSubState.Disabled));

      Variant[] sentinel =
          awaitEvent(collector, e -> componentNodeId("disp/grp/r1").equals(sourceNode(e)));
      assertNotNull(sentinel, "sentinel state-change event not received");

      boolean disposeLeaked =
          collector.events.stream()
              .anyMatch(e -> componentNodeId("disp/grp/r2").equals(sourceNode(e)));
      assertFalse(disposeLeaked, "a DISPOSE-cause teardown must produce no client event");
    } finally {
      deleteQuietly(subscription);
      service.close();
    }
  }

  // endregion

  // region communication-failure suppression + recovery re-arm (bridge entry point)

  @Test
  void clientCommunicationFailureIsSuppressedPerEpisodeAndReArmsOnRecovery() throws Exception {
    PubSubService service = PubSubService.create(readerConfig("epi"));
    var bridge = new PubSubStatusEventBridge(server, service);
    var collector = new EventCollector();
    OpcUaSubscription subscription = newStatusEventSubscription(collector);
    try {
      // two send failures for the same path, back-to-back within the re-arm window: only the first
      // fires; the second is suppressed (no storm)
      bridge.onDiagnosticsEvent(sendFailure("epi/wg", UNFLATTENED));
      bridge.onDiagnosticsEvent(sendFailure("epi/wg", UNFLATTENED));

      // a failure on a DIFFERENT path is a fresh episode and fires; its receipt bounds the count of
      // "epi/wg" failures delivered so far
      bridge.onDiagnosticsEvent(sendFailure("epi/other", UNFLATTENED));
      Variant[] sentinel =
          awaitEvent(
              collector,
              e ->
                  NodeIds.PubSubCommunicationFailureEventType.equals(eventType(e))
                      && componentNodeId("epi/other").equals(sourceNode(e)));
      assertNotNull(sentinel, "communication-failure sentinel for the other path not received");

      assertEquals(
          1,
          countCommFailures(collector, "epi/wg"),
          "sustained failures in one episode must yield exactly one event");

      // recovery to Operational re-arms suppression for the path
      bridge.onStateChange(
          stateChange(ComponentType.WRITER_GROUP, "epi/wg", PubSubState.Operational));
      // a fresh failure after recovery notifies again
      bridge.onDiagnosticsEvent(sendFailure("epi/wg", UNFLATTENED));

      boolean reArmed = awaitTrue(() -> countCommFailures(collector, "epi/wg") == 2);
      assertTrue(reArmed, "a failure after recovery must re-notify (second event expected)");
    } finally {
      deleteQuietly(subscription);
      service.close();
    }
  }

  // endregion

  // region the statusEventsEnabled gate (independent of diagnosticsEnabled)

  @Test
  void statusEventsDisabledDeliversNoStatusEventsToClient() throws Exception {
    // statusEventsEnabled is false (no bridge is constructed) even though diagnostics are on: the
    // two options are independent (diagnosticsEnabled requires exposeInformationModel; status
    // events do not and fire at the Server Object)
    ServerPubSub serverPubSub =
        ServerPubSub.attach(
            server,
            readerConfig("off"),
            ServerPubSubOptions.builder()
                .statusEventsEnabled(false)
                .diagnosticsEnabled(true)
                .exposeInformationModel(true)
                .build());
    serverPubSub.startup().get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);

    var collector = new EventCollector();
    OpcUaSubscription subscription = newStatusEventSubscription(collector);
    try {
      PubSubHandle readerGroup =
          serverPubSub.runtime().components().readerGroup("off", "grp").orElseThrow();
      serverPubSub.runtime().disable(readerGroup);

      // prove the subscription is live and WOULD deliver a §9.1.13 event by firing one directly;
      // its receipt then guarantees that any event the disable produced would also have arrived
      NodeId sentinelSource = componentNodeId("__gate_sentinel__");
      fireSentinelStatusEvent(sentinelSource);
      Variant[] sentinel = awaitEvent(collector, e -> sentinelSource.equals(sourceNode(e)));
      assertNotNull(sentinel, "sentinel PubSub status event not received — subscription not live");

      boolean groupEventLeaked =
          collector.events.stream().anyMatch(e -> componentNodeId("off/grp").equals(sourceNode(e)));
      assertFalse(
          groupEventLeaked,
          "no status events must fire while statusEventsEnabled is false (diagnostics on)");
    } finally {
      deleteQuietly(subscription);
      serverPubSub.close();
    }
  }

  // endregion

  // region clean teardown: closing ServerPubSub delivers no further status events

  @Test
  void closingServerPubSubDeliversNoFurtherStatusEvents() throws Exception {
    ServerPubSub serverPubSub =
        ServerPubSub.attach(
            server,
            readerConfig("leak"),
            ServerPubSubOptions.builder().statusEventsEnabled(true).build());
    serverPubSub.startup().get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);

    var collector = new EventCollector();
    OpcUaSubscription subscription = newStatusEventSubscription(collector);
    try {
      PubSubHandle readerGroup =
          serverPubSub.runtime().components().readerGroup("leak", "grp").orElseThrow();

      // confirm the bridge is wired and the client is receiving
      serverPubSub.runtime().disable(readerGroup);
      Variant[] control =
          awaitEvent(
              collector,
              e ->
                  componentNodeId("leak/grp").equals(sourceNode(e))
                      && stateValue(e) == PubSubState.Disabled.getValue());
      assertNotNull(control, "control state-change event not received before close");

      // let the disable cascade settle so the baseline is stable, then close
      awaitStable(collector);
      int beforeClose = collector.events.size();
      serverPubSub.close();

      // fire a sentinel AFTER close completes; ordered delivery means any leaked teardown events
      // would appear before it in the tail
      NodeId sentinelSource = componentNodeId("__after_close__");
      fireSentinelStatusEvent(sentinelSource);
      Variant[] sentinel = awaitEvent(collector, e -> sentinelSource.equals(sourceNode(e)));
      assertNotNull(sentinel, "post-close sentinel not received");

      List<Variant[]> tail = collector.events.subList(beforeClose, collector.events.size());
      boolean onlySentinel = tail.stream().allMatch(e -> sentinelSource.equals(sourceNode(e)));
      assertTrue(
          onlySentinel,
          "closing ServerPubSub must remove the bridge listeners and deliver no teardown events");
    } finally {
      deleteQuietly(subscription);
      serverPubSub.close();
    }
  }

  // endregion

  // region helpers

  /** Collects the event-field arrays delivered to a client event MonitoredItem. */
  private static final class EventCollector implements OpcUaMonitoredItem.EventValueListener {

    final List<Variant[]> events = new CopyOnWriteArrayList<>();

    @Override
    public void onEventReceived(OpcUaMonitoredItem item, Variant[] eventValues) {
      events.add(eventValues);
    }
  }

  /**
   * Create a client Subscription with one event MonitoredItem on the Server Object, filtered {@code
   * OfType(i=15535)} (matches the base type and both concrete subtypes), selecting the
   * BaseEventType and §9.1.13 fields in the fixed index order used by the accessors.
   */
  private OpcUaSubscription newStatusEventSubscription(EventCollector collector) throws Exception {
    var subscription = new OpcUaSubscription(client, 200.0);
    subscription.create();

    EventFilter filter =
        new EventFilterBuilder()
            .select(NodeIds.BaseEventType, new QualifiedName(0, "EventType"))
            .select(NodeIds.BaseEventType, new QualifiedName(0, "Severity"))
            .select(NodeIds.BaseEventType, new QualifiedName(0, "SourceNode"))
            .select(NodeIds.BaseEventType, new QualifiedName(0, "Message"))
            .select(NodeIds.PubSubStatusEventType, new QualifiedName(0, "State"))
            .select(NodeIds.PubSubStatusEventType, new QualifiedName(0, "ConnectionId"))
            .select(NodeIds.PubSubStatusEventType, new QualifiedName(0, "GroupId"))
            .select(NodeIds.PubSubCommunicationFailureEventType, new QualifiedName(0, "Error"))
            .where(ofType(NodeIds.PubSubStatusEventType))
            .build();

    var item = OpcUaMonitoredItem.newEventItem(NodeIds.Server, filter);
    item.setQueueSize(uint(1000));
    item.setEventValueListener(collector);

    subscription.addMonitoredItem(item);
    subscription.synchronizeMonitoredItems();

    StatusCode createResult =
        item.getCreateResult().orElseThrow(() -> new IllegalStateException("no create result"));
    assertTrue(createResult.isGood(), "event MonitoredItem create failed: " + createResult);

    return subscription;
  }

  /** A {@code ContentFilter} of a single {@code OfType(typeId)} element. */
  private ContentFilter ofType(NodeId typeId) {
    ExtensionObject operand =
        ExtensionObject.encode(
            client.getStaticEncodingContext(), new LiteralOperand(new Variant(typeId)));

    return new ContentFilter(
        new ContentFilterElement[] {
          new ContentFilterElement(FilterOperator.OfType, new ExtensionObject[] {operand})
        });
  }

  /** Fire a base {@code PubSubStatusEventType} directly through the server's EventNotifier. */
  private void fireSentinelStatusEvent(NodeId sourceNode) throws Exception {
    BaseEventTypeNode event =
        server.getEventFactory().createEvent(newEventNodeId(), NodeIds.PubSubStatusEventType);
    try {
      event.setBrowseName(new QualifiedName(ns, "sentinel"));
      event.setDisplayName(LocalizedText.english("sentinel"));
      event.setEventId(newEventId());
      event.setEventType(NodeIds.PubSubStatusEventType);
      event.setSourceNode(sourceNode);
      event.setSourceName("sentinel");
      event.setTime(DateTime.now());
      event.setReceiveTime(DateTime.now());
      event.setMessage(LocalizedText.english("sentinel"));
      event.setSeverity(ushort(1));

      var status = (PubSubStatusEventTypeNode) event;
      status.setConnectionId(NodeId.NULL_VALUE);
      status.setGroupId(NodeId.NULL_VALUE);
      status.setState(PubSubState.Operational);

      server.getEventNotifier().fire(event);
    } finally {
      event.delete();
    }
  }

  private NodeId newEventNodeId() {
    return new NodeId(ns, UUID.randomUUID());
  }

  private static ByteString newEventId() {
    UUID uuid = UUID.randomUUID();
    ByteBuffer buffer = ByteBuffer.allocate(16);
    buffer.putLong(uuid.getMostSignificantBits());
    buffer.putLong(uuid.getLeastSignificantBits());
    return ByteString.of(buffer.array());
  }

  private long countCommFailures(EventCollector collector, String path) {
    NodeId source = componentNodeId(path);
    return collector.events.stream()
        .filter(
            e ->
                NodeIds.PubSubCommunicationFailureEventType.equals(eventType(e))
                    && source.equals(sourceNode(e)))
        .count();
  }

  private @Nullable Variant[] awaitEvent(EventCollector collector, Predicate<Variant[]> match) {
    long deadline = System.nanoTime() + TIMEOUT.toNanos();
    while (System.nanoTime() < deadline) {
      for (Variant[] event : collector.events) {
        if (match.test(event)) {
          return event;
        }
      }
      sleepQuietly(20);
    }
    return null;
  }

  private boolean awaitTrue(BooleanSupplier condition) {
    long deadline = System.nanoTime() + TIMEOUT.toNanos();
    while (System.nanoTime() < deadline) {
      if (condition.getAsBoolean()) {
        return true;
      }
      sleepQuietly(20);
    }
    return condition.getAsBoolean();
  }

  /** Wait until the collector stops growing for a short quiet window (bounded by the deadline). */
  private void awaitStable(EventCollector collector) {
    long deadline = System.nanoTime() + TIMEOUT.toNanos();
    int last = -1;
    int stableChecks = 0;
    while (System.nanoTime() < deadline && stableChecks < 5) {
      int size = collector.events.size();
      stableChecks = (size == last) ? stableChecks + 1 : 0;
      last = size;
      sleepQuietly(50);
    }
  }

  private static void deleteQuietly(OpcUaSubscription subscription) {
    try {
      subscription.delete();
    } catch (Exception e) {
      // best-effort teardown; the shared client/server outlives the subscription
    }
  }

  private static void sleepQuietly(long millis) {
    try {
      Thread.sleep(millis);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new RuntimeException(e);
    }
  }

  // event-field accessors (fixed select-clause order)

  private static @Nullable NodeId eventType(Variant[] event) {
    return (NodeId) event[EVENT_TYPE].value();
  }

  private static int severity(Variant[] event) {
    return ((Number) event[SEVERITY].value()).intValue();
  }

  private static @Nullable NodeId sourceNode(Variant[] event) {
    return (NodeId) event[SOURCE_NODE].value();
  }

  private static int stateValue(Variant[] event) {
    return ((Number) event[STATE].value()).intValue();
  }

  private static @Nullable NodeId connectionId(Variant[] event) {
    return (NodeId) event[CONNECTION_ID].value();
  }

  private static @Nullable NodeId groupId(Variant[] event) {
    return (NodeId) event[GROUP_ID].value();
  }

  private static @Nullable StatusCode error(Variant[] event) {
    Object value = event[ERROR].value();
    return value instanceof StatusCode statusCode ? statusCode : null;
  }

  private static boolean isInformational(int severity) {
    return severity >= 1 && severity <= 333;
  }

  private static boolean isErrorBand(int severity) {
    return severity >= 334 && severity <= 666;
  }

  private NodeId componentNodeId(String path) {
    return new NodeId(ns, "PubSub/" + path);
  }

  private static PubSubDiagnosticsEvent sendFailure(String path, StatusCode code) {
    return new PubSubDiagnosticsEvent(
        path, code, "failed to send NetworkMessage: transport unreachable", null);
  }

  private static PubSubStateChangeEvent stateChange(
      ComponentType type, String path, PubSubState newState) {
    return new PubSubStateChangeEvent(
        new PubSubHandle(type, path),
        PubSubState.PreOperational,
        newState,
        StatusCode.GOOD,
        Cause.ERROR_RECOVERY);
  }

  /** One UDP connection with a single reader group and reader; nothing publishes. */
  private static PubSubConfig readerConfig(String connectionName) {
    return PubSubConfig.builder()
        .connection(
            PubSubConnectionConfig.udp(connectionName)
                .address(UdpDatagramAddress.unicast("127.0.0.1", freeUdpPort()))
                .discoveryAddress(UdpDatagramAddress.unicast("127.0.0.1", freeUdpPort()))
                .readerGroup(
                    ReaderGroupConfig.builder("grp")
                        .dataSetReader(
                            DataSetReaderConfig.builder("reader")
                                .publisherId(PublisherId.uint16(ushort(4730)))
                                .dataSetWriterId(ushort(1))
                                .build())
                        .build())
                .build())
        .build();
  }

  private static int freeUdpPort() {
    try (DatagramSocket socket = new DatagramSocket(0)) {
      return socket.getLocalPort();
    } catch (SocketException e) {
      throw new RuntimeException(e);
    }
  }

  // endregion
}
