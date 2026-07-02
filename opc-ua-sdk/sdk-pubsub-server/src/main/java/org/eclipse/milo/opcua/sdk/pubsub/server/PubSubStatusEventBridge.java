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

import java.nio.ByteBuffer;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.LongSupplier;
import org.eclipse.milo.opcua.sdk.pubsub.ComponentType;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubDiagnosticsEvent;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubDiagnosticsListener;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubService;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubStateChangeEvent;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubStateListener;
import org.eclipse.milo.opcua.sdk.server.OpcUaServer;
import org.eclipse.milo.opcua.sdk.server.model.objects.BaseEventTypeNode;
import org.eclipse.milo.opcua.sdk.server.model.objects.PubSubCommunicationFailureEventTypeNode;
import org.eclipse.milo.opcua.sdk.server.model.objects.PubSubStatusEventTypeNode;
import org.eclipse.milo.opcua.stack.core.NodeIds;
import org.eclipse.milo.opcua.stack.core.types.builtin.ByteString;
import org.eclipse.milo.opcua.stack.core.types.builtin.DateTime;
import org.eclipse.milo.opcua.stack.core.types.builtin.LocalizedText;
import org.eclipse.milo.opcua.stack.core.types.builtin.NodeId;
import org.eclipse.milo.opcua.stack.core.types.builtin.QualifiedName;
import org.eclipse.milo.opcua.stack.core.types.builtin.StatusCode;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UShort;
import org.eclipse.milo.opcua.stack.core.types.enumerated.PubSubState;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Bridges {@link PubSubService} state changes and communication failures into OPC UA events (Part
 * 14 §9.1.13, pin R17), firing them through the server's {@link
 * org.eclipse.milo.opcua.sdk.server.EventNotifier EventNotifier} so that clients subscribed to
 * Events on the Server Object (or, when the information model is exposed, on the PubSub component
 * nodes) receive them.
 *
 * <p>Two of the three §9.1.13 event types are emitted (option B+C; {@code
 * PubSubTransportLimitsExceedEventType} is not, because the engine has no message-size-limit
 * detection point):
 *
 * <ul>
 *   <li><b>State changes</b> as the abstract base {@code PubSubStatusEventType} ({@code i=15535}) —
 *       abstract EventTypes are reportable (OPC 10000-3 §4.7.2). Sourced from every {@link
 *       PubSubStateChangeEvent} of a connection, group, DataSetWriter, or DataSetReader (the
 *       §9.1.13.1 source set), except transitions with cause {@code DISPOSE} (subtree teardown on
 *       reconfigure-removal or shutdown produces no events).
 *   <li><b>Communication failures</b> as {@code PubSubCommunicationFailureEventType} ({@code
 *       i=15563}), discriminated from the diagnostics-event stream (send failures carry the
 *       WP-W-un-flattened transport {@link StatusCode}, surfaced verbatim in the {@code Error}
 *       property).
 * </ul>
 *
 * <p>Both listeners are delivered on the {@link PubSubService}'s serialized listener executor (the
 * transport executor, one event at a time, in emission order — never the publish or engine thread),
 * so building and firing event nodes here is safe. Event construction runs inline on that queue,
 * delaying subsequent listener deliveries; that cost is accepted (§9.1.13 imposes no rate).
 *
 * <p>Communication-failure events are suppressed after the first one per failure episode per
 * component, so a persistently failing component (e.g. a down broker or unreachable target
 * publishing every cycle) does not storm the event bus. Suppression re-arms immediately when the
 * component recovers to {@link PubSubState#Operational}, and otherwise once {@link
 * #REARM_WINDOW_NANOS} has elapsed since the last emitted failure. The time-based re-arm matters
 * for a component that keeps failing without ever leaving {@link PubSubState#Operational} — most
 * importantly a connectionless UDP target, whose send failures never drive a state transition
 * (there is no transport-state signal and a later successful publish is not a listener event
 * either): a genuinely new failure episode is still reported at most once per window instead of
 * being dropped for the service lifetime. A dedicated engine send-recovery signal (a WP-W
 * follow-up) would allow exact per-episode re-arm; until then the window bounds the worst-case
 * silence.
 *
 * <p>Gated by {@link ServerPubSubOptions#isStatusEventsEnabled()} (independent of {@link
 * ServerPubSubOptions#isDiagnosticsEnabled()} and {@link
 * ServerPubSubOptions#isExposeInformationModel()}): this bridge is only constructed and started
 * when status events are enabled. Listeners are registered at {@link #startup()} and removed at
 * {@link #shutdown()} for a clean lifecycle.
 */
final class PubSubStatusEventBridge implements PubSubStateListener, PubSubDiagnosticsListener {

  private static final Logger LOGGER = LoggerFactory.getLogger(PubSubStatusEventBridge.class);

  /**
   * The component-node NodeId prefix, matching {@code PubSubInfoModelFragment.NODE_ID_PREFIX}: a
   * component at path {@code "conn/group/writer"} is exposed at {@code
   * ServerNamespace:"PubSub/conn/group/writer"}. Kept in sync with the fragment by convention (the
   * two classes are in the same package but the constant is private to each).
   */
  private static final String NODE_ID_PREFIX = "PubSub";

  /**
   * The message prefix the engine's send-failure diagnostics share ("failed to send NetworkMessage
   * ...", "failed to send DataSetMetaData message ...", "failed to send discovery ..."), used to
   * pick communication failures out of the broader diagnostics-event stream (source-read failures,
   * encode failures, and decryption errors do not start with it).
   */
  private static final String SEND_FAILURE_MESSAGE_PREFIX = "failed to send";

  /** Severity for state changes that are not an entry into {@code Error} (OPC 10000-5 §6.4.2). */
  private static final UShort SEVERITY_INFORMATIONAL = ushort(100);

  /** Severity for an entry into {@code Error} and for communication failures (334-666 band). */
  private static final UShort SEVERITY_ERROR = ushort(500);

  /**
   * The interval after which communication-failure suppression re-arms without a state transition,
   * so a component that keeps failing while staying {@link PubSubState#Operational} re-notifies
   * periodically instead of exactly once for the service lifetime.
   */
  private static final long REARM_WINDOW_NANOS = TimeUnit.MINUTES.toNanos(1);

  /** Last observed state per tracked component path, for the {@code State} property of failures. */
  private final ConcurrentMap<String, PubSubState> lastStates = new ConcurrentHashMap<>();

  /**
   * The {@link #nanoClock} timestamp of the most recent communication-failure event emitted per
   * component path. A path present here is currently suppressed; it re-arms when the entry is
   * removed (recovery to {@link PubSubState#Operational}, or dispose) or once {@link
   * #REARM_WINDOW_NANOS} has elapsed since the recorded timestamp.
   */
  private final ConcurrentMap<String, Long> commFailureLastEmitNanos = new ConcurrentHashMap<>();

  private final AtomicBoolean started = new AtomicBoolean(false);

  private final OpcUaServer server;
  private final PubSubService service;
  private final UShort namespaceIndex;

  /**
   * Monotonic clock driving the comm-failure re-arm window; overridable for deterministic tests.
   */
  private final LongSupplier nanoClock;

  PubSubStatusEventBridge(OpcUaServer server, PubSubService service) {
    this(server, service, System::nanoTime);
  }

  /** Test seam: inject the {@code nanoTime} source that drives the {@link #REARM_WINDOW_NANOS}. */
  PubSubStatusEventBridge(OpcUaServer server, PubSubService service, LongSupplier nanoClock) {
    this.server = server;
    this.service = service;
    this.namespaceIndex = server.getServerNamespace().getNamespaceIndex();
    this.nanoClock = nanoClock;
  }

  /** Register the state-change and diagnostics listeners. Idempotent. */
  void startup() {
    if (started.compareAndSet(false, true)) {
      service.addStateListener(this);
      service.addDiagnosticsListener(this);
    }
  }

  /** Remove the listeners so no further events are fired. Idempotent. */
  void shutdown() {
    if (started.compareAndSet(true, false)) {
      service.removeStateListener(this);
      service.removeDiagnosticsListener(this);
    }
  }

  @Override
  public void onStateChange(PubSubStateChangeEvent event) {
    if (!isTrackedComponentType(event.component().componentType())) {
      // PublishedDataSets, standalone datasets, and security groups are outside the §9.1.13.1
      // source set (connection / group / writer / reader)
      return;
    }

    String path = event.component().path();

    if (event.cause() == PubSubStateChangeEvent.Cause.DISPOSE) {
      // dispose-driven teardown (reconfigure-removal or shutdown) produces no status events; drop
      // tracking so a component rebuilt at the same path starts a fresh failure episode
      lastStates.remove(path);
      commFailureLastEmitNanos.remove(path);
      return;
    }

    PubSubState newState = event.newState();
    lastStates.put(path, newState);
    if (newState == PubSubState.Operational) {
      // recovered: re-arm communication-failure suppression for this component
      commFailureLastEmitNanos.remove(path);
    }

    UShort severity = newState == PubSubState.Error ? SEVERITY_ERROR : SEVERITY_INFORMATIONAL;
    LocalizedText message =
        LocalizedText.english(
            "PubSub component '%s' changed state to %s (%s)"
                .formatted(path, newState, event.statusCode()));

    emit(NodeIds.PubSubStatusEventType, path, newState, message, severity, null);
  }

  @Override
  public void onDiagnosticsEvent(PubSubDiagnosticsEvent event) {
    if (!isSendFailure(event)) {
      // only send failures map to PubSubCommunicationFailureEventType ("a NetworkMessage could not
      // be published because of a communication failure"); other diagnostics are not events here
      return;
    }

    String path = event.path();
    if (path.isEmpty()) {
      return;
    }

    long now = nanoClock.getAsLong();
    Long lastEmit = commFailureLastEmitNanos.get(path);
    if (lastEmit != null && now - lastEmit < REARM_WINDOW_NANOS) {
      // already reported for this component's current failure episode, within the re-arm window
      return;
    }
    commFailureLastEmitNanos.put(path, now);

    PubSubState state = lastStates.getOrDefault(path, PubSubState.Operational);
    LocalizedText message = LocalizedText.english(event.message());

    emit(
        NodeIds.PubSubCommunicationFailureEventType,
        path,
        state,
        message,
        SEVERITY_ERROR,
        event.statusCode());
  }

  /**
   * Build an event of {@code typeId}, populate the BaseEventType and §9.1.13 fields, fire it
   * through the server's EventNotifier, and delete the transient node. Never throws: an emission
   * failure is logged so it cannot break listener delivery.
   *
   * @param error the {@code Error} property for a communication failure, or {@code null} for a
   *     plain state-change event.
   */
  private void emit(
      NodeId typeId,
      String path,
      PubSubState state,
      LocalizedText message,
      UShort severity,
      @Nullable StatusCode error) {

    try {
      BaseEventTypeNode eventNode = server.getEventFactory().createEvent(newEventNodeId(), typeId);
      try {
        String sourceName = lastSegment(path);
        eventNode.setBrowseName(new QualifiedName(namespaceIndex, sourceName));
        eventNode.setDisplayName(LocalizedText.english(sourceName));
        eventNode.setEventId(newEventId());
        eventNode.setEventType(typeId);
        eventNode.setSourceNode(componentNodeId(path));
        eventNode.setSourceName(sourceName);
        eventNode.setTime(DateTime.now());
        eventNode.setReceiveTime(DateTime.now());
        eventNode.setMessage(message);
        eventNode.setSeverity(severity);

        var statusEvent = (PubSubStatusEventTypeNode) eventNode;
        statusEvent.setConnectionId(connectionNodeId(path));
        NodeId groupId = groupNodeId(path);
        statusEvent.setGroupId(groupId != null ? groupId : NodeId.NULL_VALUE);
        statusEvent.setState(state);

        if (error != null && eventNode instanceof PubSubCommunicationFailureEventTypeNode failure) {
          failure.setError(error);
        }

        server.getEventNotifier().fire(eventNode);
      } finally {
        eventNode.delete();
      }
    } catch (Exception e) {
      LOGGER.warn("Failed to emit PubSub status event for '{}'", path, e);
    }
  }

  private NodeId newEventNodeId() {
    return new NodeId(namespaceIndex, UUID.randomUUID());
  }

  /** The SourceNode: the PubSub component node for {@code path}. */
  private NodeId componentNodeId(String path) {
    return new NodeId(namespaceIndex, NODE_ID_PREFIX + "/" + path);
  }

  /** The ConnectionId property: the connection node (first path segment). */
  private NodeId connectionNodeId(String path) {
    return new NodeId(namespaceIndex, NODE_ID_PREFIX + "/" + firstSegment(path));
  }

  /**
   * The GroupId property: the group node (first two path segments), or {@code null} for a
   * connection-sourced event (§9.1.13.1: "GroupId is Null if a PubSubConnection is the source").
   */
  private @Nullable NodeId groupNodeId(String path) {
    String[] segments = path.split("/", -1);
    if (segments.length < 2) {
      return null;
    }
    return new NodeId(namespaceIndex, NODE_ID_PREFIX + "/" + segments[0] + "/" + segments[1]);
  }

  private static String firstSegment(String path) {
    int slash = path.indexOf('/');
    return slash < 0 ? path : path.substring(0, slash);
  }

  private static String lastSegment(String path) {
    int slash = path.lastIndexOf('/');
    return slash < 0 ? path : path.substring(slash + 1);
  }

  private static boolean isSendFailure(PubSubDiagnosticsEvent event) {
    return event.message().startsWith(SEND_FAILURE_MESSAGE_PREFIX);
  }

  private static boolean isTrackedComponentType(ComponentType componentType) {
    return switch (componentType) {
      case CONNECTION, WRITER_GROUP, DATA_SET_WRITER, READER_GROUP, DATA_SET_READER -> true;
      default -> false;
    };
  }

  private static ByteString newEventId() {
    UUID uuid = UUID.randomUUID();
    ByteBuffer buffer = ByteBuffer.allocate(16);
    buffer.putLong(uuid.getMostSignificantBits());
    buffer.putLong(uuid.getLeastSignificantBits());
    return ByteString.of(buffer.array());
  }
}
