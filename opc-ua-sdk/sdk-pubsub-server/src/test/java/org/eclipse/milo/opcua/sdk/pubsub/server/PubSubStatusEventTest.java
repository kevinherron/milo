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

import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.ushort;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.DatagramSocket;
import java.net.SocketException;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Predicate;
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
import org.eclipse.milo.opcua.sdk.server.EventListener;
import org.eclipse.milo.opcua.sdk.server.model.objects.BaseEventTypeNode;
import org.eclipse.milo.opcua.sdk.server.model.objects.PubSubCommunicationFailureEventTypeNode;
import org.eclipse.milo.opcua.sdk.server.model.objects.PubSubStatusEventTypeNode;
import org.eclipse.milo.opcua.stack.core.NodeIds;
import org.eclipse.milo.opcua.stack.core.StatusCodes;
import org.eclipse.milo.opcua.stack.core.types.builtin.LocalizedText;
import org.eclipse.milo.opcua.stack.core.types.builtin.NodeId;
import org.eclipse.milo.opcua.stack.core.types.builtin.StatusCode;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UShort;
import org.eclipse.milo.opcua.stack.core.types.enumerated.PubSubState;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * R17 status-event bridge behavior: state changes emitted as the base {@code PubSubStatusEventType}
 * ({@code i=15535}), send failures as {@code PubSubCommunicationFailureEventType} ({@code
 * i=15563}), DISPOSE suppression, first-failure-per-episode suppression with recovery re-arm,
 * severity bands, field mapping, and the {@code statusEventsEnabled} gate.
 *
 * <p>Events are captured directly off the server's {@code EventNotifier} (the fixture server is
 * never started, so client subscriptions are unavailable; the notifier fan-out is what a Server
 * Object event subscription is routed to). The engine delivers listener callbacks on a serialized
 * executor, so the whitebox tests drive the two listener entry points ({@link
 * PubSubStatusEventBridge#onStateChange} / {@link PubSubStatusEventBridge#onDiagnosticsEvent})
 * directly for deterministic assertions, while the two {@link ServerPubSub}-driven tests exercise
 * the real wiring end-to-end.
 */
class PubSubStatusEventTest {

  private static final Duration TIMEOUT = Duration.ofSeconds(10);

  private TestPubSubServer testServer;
  private UShort ns;

  @BeforeEach
  void startServer() {
    testServer = TestPubSubServer.create();
    ns = testServer.getServer().getServerNamespace().getNamespaceIndex();
    // the fixture server is never started; start the EventFactory explicitly so createEvent and
    // fire behave exactly as on a running server (server.startup() would fail with no endpoints)
    testServer.getServer().getEventFactory().startup();
  }

  @AfterEach
  void stopServer() {
    testServer.close();
  }

  // region whitebox: bridge listener behavior

  @Test
  void sendFailureEmitsCommunicationFailureEvent() {
    PubSubService service = PubSubService.create(readerConfig("wb"));
    try {
      var bridge = new PubSubStatusEventBridge(testServer.getServer(), service);
      Capture capture = register();

      StatusCode error = new StatusCode(StatusCodes.Bad_ServerNotConnected);
      bridge.onDiagnosticsEvent(
          new PubSubDiagnosticsEvent(
              "wb/grp", error, "failed to send NetworkMessage: unreachable", null));

      List<Captured> failures = capture.ofType(NodeIds.PubSubCommunicationFailureEventType);
      assertEquals(1, failures.size(), "exactly one communication-failure event");

      Captured event = failures.get(0);
      assertEquals(componentNodeId("wb/grp"), event.sourceNode);
      assertEquals("grp", event.sourceName);
      assertEquals(componentNodeId("wb"), event.connectionId);
      assertEquals(componentNodeId("wb/grp"), event.groupId);
      assertEquals(PubSubState.Operational, event.state, "default state when none is tracked");
      assertEquals(error, event.error, "the un-flattened transport status is surfaced verbatim");
      assertTrue(isErrorSeverity(event.severity), "comm failure is Error-band severity");
    } finally {
      service.close();
    }
  }

  @Test
  void nonSendFailureDiagnosticsProduceNoEvent() {
    PubSubService service = PubSubService.create(readerConfig("wb"));
    try {
      var bridge = new PubSubStatusEventBridge(testServer.getServer(), service);
      Capture capture = register();

      StatusCode code = new StatusCode(StatusCodes.Bad_CommunicationError);
      // an encode failure and a source-read failure are not communication failures
      bridge.onDiagnosticsEvent(
          new PubSubDiagnosticsEvent("wb/grp", code, "failed to encode NetworkMessage: x", null));
      bridge.onDiagnosticsEvent(
          new PubSubDiagnosticsEvent("wb/grp/reader", code, "failed to read source: x", null));

      assertTrue(capture.events.isEmpty(), "non-send diagnostics emit no events");
    } finally {
      service.close();
    }
  }

  @Test
  void communicationFailureSuppressedPerEpisodeAndReArmsOnRecovery() {
    PubSubService service = PubSubService.create(readerConfig("wb"));
    try {
      var bridge = new PubSubStatusEventBridge(testServer.getServer(), service);
      Capture capture = register();

      StatusCode error = new StatusCode(StatusCodes.Bad_ConnectionClosed);
      bridge.onDiagnosticsEvent(sendFailure("wb/grp", error));
      bridge.onDiagnosticsEvent(sendFailure("wb/grp", error));

      assertEquals(
          1,
          capture.ofType(NodeIds.PubSubCommunicationFailureEventType).size(),
          "one event per failure episode");

      // recovery to Operational re-arms suppression (an intermediate Error does not)
      bridge.onStateChange(stateChange(ComponentType.WRITER_GROUP, "wb/grp", PubSubState.Error));
      bridge.onStateChange(
          stateChange(ComponentType.WRITER_GROUP, "wb/grp", PubSubState.Operational));

      capture.events.clear();
      bridge.onDiagnosticsEvent(sendFailure("wb/grp", error));

      assertEquals(
          1,
          capture.ofType(NodeIds.PubSubCommunicationFailureEventType).size(),
          "a fresh episode after recovery emits again");
    } finally {
      service.close();
    }
  }

  @Test
  void communicationFailureReArmsAfterWindowElapses() {
    PubSubService service = PubSubService.create(readerConfig("wb"));
    try {
      // drive the re-arm clock deterministically instead of System.nanoTime
      var clock = new AtomicLong(0);
      var bridge = new PubSubStatusEventBridge(testServer.getServer(), service, clock::get);
      Capture capture = register();

      StatusCode error = new StatusCode(StatusCodes.Bad_ConnectionClosed);
      // a transient failure that never drives the component out of Operational
      bridge.onDiagnosticsEvent(sendFailure("wb/grp", error));
      // a second failure within the re-arm window is still suppressed (no storm)
      clock.addAndGet(TimeUnit.SECONDS.toNanos(30));
      bridge.onDiagnosticsEvent(sendFailure("wb/grp", error));

      assertEquals(
          1,
          capture.ofType(NodeIds.PubSubCommunicationFailureEventType).size(),
          "within the re-arm window only one event fires");

      // once the window elapses a fresh failure re-notifies, even with no state transition at all
      clock.addAndGet(TimeUnit.MINUTES.toNanos(2));
      bridge.onDiagnosticsEvent(sendFailure("wb/grp", error));

      assertEquals(
          2,
          capture.ofType(NodeIds.PubSubCommunicationFailureEventType).size(),
          "a later episode re-notifies without an Operational transition once the window elapses");
    } finally {
      service.close();
    }
  }

  @Test
  void disposeStateChangeProducesNoEvent() {
    PubSubService service = PubSubService.create(readerConfig("wb"));
    try {
      var bridge = new PubSubStatusEventBridge(testServer.getServer(), service);
      Capture capture = register();

      bridge.onStateChange(
          new PubSubStateChangeEvent(
              new PubSubHandle(ComponentType.WRITER_GROUP, "wb/grp"),
              PubSubState.Operational,
              PubSubState.Disabled,
              StatusCode.GOOD,
              Cause.DISPOSE));

      assertTrue(capture.events.isEmpty(), "dispose-driven teardown emits no events");
    } finally {
      service.close();
    }
  }

  @Test
  void severityMapsToBandByState() {
    PubSubService service = PubSubService.create(readerConfig("wb"));
    try {
      var bridge = new PubSubStatusEventBridge(testServer.getServer(), service);
      Capture capture = register();

      bridge.onStateChange(stateChange(ComponentType.CONNECTION, "wb", PubSubState.Error));
      bridge.onStateChange(stateChange(ComponentType.CONNECTION, "wb", PubSubState.Operational));

      List<Captured> events = capture.ofType(NodeIds.PubSubStatusEventType);
      assertEquals(2, events.size());
      assertTrue(isErrorSeverity(events.get(0).severity), "Error entry is Error-band");
      assertTrue(isInformationalSeverity(events.get(1).severity), "Operational is informational");
    } finally {
      service.close();
    }
  }

  @Test
  void stateChangeFieldMapping() {
    PubSubService service = PubSubService.create(readerConfig("wb"));
    try {
      var bridge = new PubSubStatusEventBridge(testServer.getServer(), service);
      Capture capture = register();

      // a connection-sourced event has a Null GroupId (Part 14 §9.1.13.1)
      bridge.onStateChange(stateChange(ComponentType.CONNECTION, "wb", PubSubState.Disabled));
      // a reader-sourced event carries its parent reader group as GroupId
      bridge.onStateChange(
          stateChange(ComponentType.DATA_SET_READER, "wb/rg/reader", PubSubState.Operational));

      List<Captured> events = capture.ofType(NodeIds.PubSubStatusEventType);
      assertEquals(2, events.size());

      Captured connectionEvent = events.get(0);
      assertEquals(componentNodeId("wb"), connectionEvent.sourceNode);
      assertEquals(componentNodeId("wb"), connectionEvent.connectionId);
      assertEquals(
          NodeId.NULL_VALUE, connectionEvent.groupId, "connection source has Null GroupId");
      assertEquals(PubSubState.Disabled, connectionEvent.state);

      Captured readerEvent = events.get(1);
      assertEquals(componentNodeId("wb/rg/reader"), readerEvent.sourceNode);
      assertEquals("reader", readerEvent.sourceName);
      assertEquals(componentNodeId("wb"), readerEvent.connectionId);
      assertEquals(componentNodeId("wb/rg"), readerEvent.groupId);
      assertEquals(PubSubState.Operational, readerEvent.state);
    } finally {
      service.close();
    }
  }

  @Test
  void untrackedComponentTypeProducesNoEvent() {
    PubSubService service = PubSubService.create(readerConfig("wb"));
    try {
      var bridge = new PubSubStatusEventBridge(testServer.getServer(), service);
      Capture capture = register();

      // PublishedDataSets are outside the §9.1.13.1 source set
      bridge.onStateChange(
          stateChange(ComponentType.PUBLISHED_DATA_SET, "pds", PubSubState.Operational));

      assertTrue(capture.events.isEmpty());
    } finally {
      service.close();
    }
  }

  // endregion

  // region integration: ServerPubSub wiring + the statusEventsEnabled gate

  @Test
  void statusEventsEnabledEmitsStateChangeEventOnDisable() throws Exception {
    ServerPubSub serverPubSub =
        ServerPubSub.attach(
            testServer.getServer(),
            readerConfig("evt"),
            ServerPubSubOptions.builder().statusEventsEnabled(true).build());
    try {
      serverPubSub.startup().get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);

      Capture capture = new Capture();
      testServer.getServer().getEventNotifier().register(capture);

      PubSubHandle reader =
          serverPubSub.runtime().components().dataSetReader("evt", "grp", "reader").orElseThrow();
      serverPubSub.runtime().disable(reader);

      // poll for the specific disable event: residual startup transitions may also be delivered
      Captured event =
          awaitEvent(
              capture,
              c ->
                  c.sourceNode.equals(componentNodeId("evt/grp/reader"))
                      && c.state == PubSubState.Disabled,
              TIMEOUT);

      assertNotNull(event, "a state-change event for the disabled reader");
      assertEquals(NodeIds.PubSubStatusEventType, event.eventType);
      assertEquals(componentNodeId("evt"), event.connectionId);
      assertEquals(componentNodeId("evt/grp"), event.groupId);
      assertTrue(isInformationalSeverity(event.severity));
    } finally {
      serverPubSub.close();
    }
  }

  @Test
  void statusEventsDisabledEmitsNoEvent() throws Exception {
    // default options: statusEventsEnabled is false, so no bridge is installed
    ServerPubSub serverPubSub = ServerPubSub.attach(testServer.getServer(), readerConfig("off"));
    try {
      serverPubSub.startup().get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);

      Capture capture = new Capture();
      testServer.getServer().getEventNotifier().register(capture);

      // register a state listener after startup; the bridge (if it existed) would have registered
      // before service startup, so it runs earlier on the serialized queue for the same transition
      // — when this listener sees the transition, any bridge event has already been fired
      var stateSeen = new CountDownLatch(1);
      serverPubSub
          .runtime()
          .addStateListener(
              e -> {
                if (e.component().componentType() == ComponentType.DATA_SET_READER
                    && e.newState() == PubSubState.Disabled) {
                  stateSeen.countDown();
                }
              });

      PubSubHandle reader =
          serverPubSub.runtime().components().dataSetReader("off", "grp", "reader").orElseThrow();
      serverPubSub.runtime().disable(reader);

      assertTrue(stateSeen.await(TIMEOUT.toSeconds(), TimeUnit.SECONDS), "transition dispatched");
      assertTrue(capture.events.isEmpty(), "no status events when statusEventsEnabled is false");
    } finally {
      serverPubSub.close();
    }
  }

  // endregion

  // region helpers

  private Capture register() {
    Capture capture = new Capture();
    testServer.getServer().getEventNotifier().register(capture);
    return capture;
  }

  private static @Nullable Captured awaitEvent(
      Capture capture, Predicate<Captured> match, Duration timeout) throws InterruptedException {

    long deadline = System.nanoTime() + timeout.toNanos();
    while (System.nanoTime() < deadline) {
      Captured found = capture.events.stream().filter(match).findFirst().orElse(null);
      if (found != null) {
        return found;
      }
      Thread.sleep(20);
    }
    return null;
  }

  private NodeId componentNodeId(String path) {
    return new NodeId(ns, "PubSub/" + path);
  }

  private static PubSubDiagnosticsEvent sendFailure(String path, StatusCode code) {
    return new PubSubDiagnosticsEvent(path, code, "failed to send NetworkMessage: down", null);
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

  private static boolean isInformationalSeverity(UShort severity) {
    int value = severity.intValue();
    return value >= 1 && value <= 333;
  }

  private static boolean isErrorSeverity(UShort severity) {
    int value = severity.intValue();
    return value >= 334 && value <= 666;
  }

  /** One UDP connection with a single reader; nothing publishes. */
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

  /** A snapshot of a captured PubSub status event; the source node is deleted after firing. */
  private record Captured(
      NodeId eventType,
      NodeId sourceNode,
      String sourceName,
      UShort severity,
      LocalizedText message,
      PubSubState state,
      NodeId connectionId,
      NodeId groupId,
      @Nullable StatusCode error) {}

  /**
   * Captures fired PubSub status events, snapshotting their fields inside {@code onEvent} (the
   * event node is deleted immediately after {@code fire} returns).
   */
  private static final class Capture implements EventListener {

    final List<Captured> events = new CopyOnWriteArrayList<>();

    @Override
    public void onEvent(BaseEventTypeNode node) {
      if (node instanceof PubSubStatusEventTypeNode status) {
        StatusCode error =
            node instanceof PubSubCommunicationFailureEventTypeNode failure
                ? failure.getError()
                : null;
        events.add(
            new Captured(
                node.getEventType(),
                node.getSourceNode(),
                node.getSourceName(),
                node.getSeverity(),
                node.getMessage(),
                status.getState(),
                status.getConnectionId(),
                status.getGroupId(),
                error));
      }
    }

    List<Captured> ofType(NodeId eventType) {
      return events.stream().filter(c -> c.eventType.equals(eventType)).toList();
    }
  }
}
