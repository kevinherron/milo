/*
 * Copyright (c) 2026 the Eclipse Milo Authors
 *
 * This program and the accompanying materials are made
 * available under the terms of the Eclipse Public License 2.0
 * which is available at https://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 */

package org.eclipse.milo.opcua.sdk.pubsub.internal;

import java.util.Collections;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.atomic.LongAdder;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubDiagnostics;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubDiagnostics.ComponentDiagnostics;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubDiagnostics.Counter;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubDiagnosticsEvent;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubStateChangeEvent.Cause;
import org.eclipse.milo.opcua.stack.core.StatusCodes;
import org.eclipse.milo.opcua.stack.core.types.builtin.DateTime;
import org.eclipse.milo.opcua.stack.core.types.builtin.StatusCode;
import org.eclipse.milo.opcua.stack.core.types.enumerated.PubSubState;
import org.jspecify.annotations.Nullable;

/**
 * Per-component diagnostic counters, keyed by component path, and the {@link PubSubDiagnostics}
 * view over them.
 *
 * <p>Counters are lock-free ({@link LongAdder}); each also records the {@link
 * PubSubDiagnostics.Counter} TimeFirstChange (when it first left 0), set once via a CAS on the
 * first non-zero increment and cleared by {@link #reset(String)}. {@link #snapshot()} produces an
 * immutable point-in-time copy. Error recordings additionally emit a {@link PubSubDiagnosticsEvent}
 * through the {@link EventDispatcher}.
 *
 * <p>Entries are created by {@link #register(String)} only (startup and reconfigure register every
 * component path); increments for unregistered paths are dropped, so a late in-flight increment
 * cannot resurrect the entry of a component removed by reconfiguration.
 */
final class DiagnosticsCollector implements PubSubDiagnostics {

  private final ConcurrentMap<String, Counters> countersByPath = new ConcurrentHashMap<>();

  private final EventDispatcher events;

  DiagnosticsCollector(EventDispatcher events) {
    this.events = events;
  }

  /** Ensure a (zeroed) entry exists for the component at {@code path}. */
  void register(String path) {
    countersByPath.computeIfAbsent(path, Counters::new);
  }

  /** Remove the entry for a component removed by reconfiguration. */
  void remove(String path) {
    countersByPath.remove(path);
  }

  private void increment(String path, Counter counter) {
    add(path, counter, 1);
  }

  private void add(String path, Counter counter, long delta) {
    Counters counters = countersByPath.get(path);
    if (counters != null) {
      counters.add(counter, delta);
    }
  }

  void networkMessageSent(String path) {
    increment(path, Counter.NETWORK_MESSAGES_SENT);
  }

  void networkMessageReceived(String path) {
    increment(path, Counter.NETWORK_MESSAGES_RECEIVED);
  }

  void dataSetMessagesSent(String path, int count) {
    add(path, Counter.DATA_SET_MESSAGES_SENT, count);
  }

  void dataSetMessageReceived(String path) {
    increment(path, Counter.DATA_SET_MESSAGES_RECEIVED);
  }

  /**
   * Record a DataSetMessage dropped by a reader's Part 14 §7.2.3 sequence-number window as older
   * than or duplicating the last processed message. A normal-operation counter: no {@code
   * lastError} and no diagnostics event ("shall be ignored" is not an error condition).
   */
  void staleSequenceMessage(String path) {
    increment(path, Counter.STALE_SEQUENCE_MESSAGES);
  }

  /**
   * Record a DataSetMessage dropped by a reader's Part 14 §7.2.3 sequence-number window with a
   * recency result in the invalid band (neither provably newer nor older). A normal-operation
   * counter: no {@code lastError} and no diagnostics event.
   */
  void invalidSequenceMessage(String path) {
    increment(path, Counter.INVALID_SEQUENCE_MESSAGES);
  }

  /**
   * Record a NetworkMessage a secured WriterGroup failed to encode: encryption, signing, and nonce
   * composition are inline with the encode of a secured NetworkMessage, so any encode failure of a
   * secured publish cycle counts here. Also records the error and emits a diagnostics event. The
   * per-writer {@code FailedDataSetMessages} attribution is recorded separately via {@link
   * #failedDataSetMessage(String)} by the caller.
   */
  void encryptionError(
      String path, StatusCode statusCode, String message, @Nullable Throwable error) {
    increment(path, Counter.ENCRYPTION_ERRORS);
    error(path, statusCode, message, error);
  }

  /**
   * Record a received secured NetworkMessage whose signature verified but whose decrypted payload
   * could not be parsed. Also records the error and emits a diagnostics event.
   */
  void decryptionError(
      String path, StatusCode statusCode, String message, @Nullable Throwable error) {
    increment(path, Counter.DECRYPTION_ERRORS);
    error(path, statusCode, message, error);
  }

  /**
   * Record a received secured NetworkMessage dropped whole because its signature did not verify
   * (Part 14 §7.2.4.4.3.2). Also records the error and emits a diagnostics event.
   */
  void invalidSignatureMessage(
      String path, StatusCode statusCode, String message, @Nullable Throwable error) {
    increment(path, Counter.INVALID_SIGNATURE_MESSAGES);
    error(path, statusCode, message, error);
  }

  /**
   * Record a received secured NetworkMessage dropped because its SecurityTokenId is not in the key
   * window (Part 14 §8.3.2 unknown token; a single key refresh is triggered by the key manager). A
   * normal-operation counter: no {@code lastError} and no diagnostics event (expected transiently
   * around key rollover).
   */
  void unknownTokenMessage(String path) {
    increment(path, Counter.UNKNOWN_TOKEN_MESSAGES);
  }

  /**
   * Record a received secured NetworkMessage dropped because its key is expired beyond twice the
   * KeyLifetime or names a past key no longer held (Part 14 §6.2.12.2). A normal-operation counter:
   * no {@code lastError} and no diagnostics event.
   */
  void staleKeyMessage(String path) {
    increment(path, Counter.STALE_KEY_MESSAGES);
  }

  /**
   * Record a NetworkMessage dropped for a reader whose configured security mode the received mode
   * does not satisfy (Part 14 §7.2.4.3), or that has no SecurityGroup to supply keys for a secured
   * message. A normal-operation counter: no {@code lastError} and no diagnostics event ("counted,
   * not log-stormed").
   */
  void securityModeRejectedMessage(String path) {
    increment(path, Counter.SECURITY_MODE_REJECTED_MESSAGES);
  }

  /** Record a dropped message (decode failure, version mismatch, invalid message). */
  void decodeError(String path, StatusCode statusCode, String message, @Nullable Throwable error) {
    increment(path, Counter.DECODE_ERRORS);
    error(path, statusCode, message, error);
  }

  /** Record a {@code PublishedDataSetSource} read failure. */
  void sourceError(String path, StatusCode statusCode, String message, @Nullable Throwable error) {
    increment(path, Counter.SOURCE_ERRORS);
    error(path, statusCode, message, error);
  }

  /**
   * Record a NetworkMessage a WriterGroup failed to transmit — a synchronous or asynchronous send
   * failure carrying the transport's real status, or a plaintext encode failure — that occurred
   * while operating (not while the publisher channel is closing on shutdown, disable, or
   * reconfigure-removal; the caller filters teardown noise before calling this). Increments {@code
   * FailedTransmissions}, records the error, and emits a diagnostics event. The per-writer {@code
   * FailedDataSetMessages} attribution is recorded separately via {@link
   * #failedDataSetMessage(String)}.
   */
  void failedTransmission(
      String path, StatusCode statusCode, String message, @Nullable Throwable error) {
    increment(path, Counter.FAILED_TRANSMISSIONS);
    error(path, statusCode, message, error);
  }

  /**
   * Record, at a DataSetWriter path, a DataSetMessage that was never sent because the
   * NetworkMessage carrying it failed to encode or send (Part 14 Table 328 {@code
   * FailedDataSetMessages}, attributed per contributing writer). A counter-only attribution: the
   * WriterGroup's {@link #failedTransmission} or {@link #encryptionError} already carried the error
   * and event.
   */
  void failedDataSetMessage(String path) {
    increment(path, Counter.FAILED_DATA_SET_MESSAGES);
  }

  /**
   * Record the Part 14 Table 311 state-machine counter for a transition, if any applies. Called
   * under the engine lock from the state-change listener.
   *
   * @param path the component path.
   * @param oldState the state transitioned from.
   * @param newState the state transitioned to.
   * @param cause the trigger category of this transition.
   * @param operationalTrigger the remembered trigger ({@code METHOD}/{@code PARENT}) that moved the
   *     component into {@code PreOperational}, used to attribute the final {@code Operational} hop;
   *     {@code null} if none was recorded.
   */
  void recordStateChange(
      String path,
      PubSubState oldState,
      PubSubState newState,
      Cause cause,
      @Nullable Cause operationalTrigger) {

    Counters counters = countersByPath.get(path);
    if (counters == null) {
      return;
    }

    switch (newState) {
      case Error -> counters.add(Counter.STATE_ERROR, 1);
      case Operational -> {
        if (oldState == PubSubState.Error) {
          counters.add(Counter.STATE_OPERATIONAL_FROM_ERROR, 1);
        } else if (operationalTrigger == Cause.PARENT) {
          counters.add(Counter.STATE_OPERATIONAL_BY_PARENT, 1);
        } else {
          // METHOD, or no remembered trigger: an Operational transition not from Error and not
          // from a parent recompute followed an explicit enable
          counters.add(Counter.STATE_OPERATIONAL_BY_METHOD, 1);
        }
      }
      case Paused -> counters.add(Counter.STATE_PAUSED_BY_PARENT, 1);
      case Disabled -> {
        // a Disabled transition from subtree disposal (reconfigure-removal/shutdown) is not a
        // Disable Method call (Part 14 §9.1.11)
        if (cause == Cause.METHOD) {
          counters.add(Counter.STATE_DISABLED_BY_METHOD, 1);
        }
      }
      default -> {
        // PreOperational: no state counter
      }
    }
  }

  /**
   * Record an error and emit a diagnostics event for it. The event is emitted even when {@code
   * path} is no longer registered.
   */
  void error(String path, StatusCode statusCode, String message, @Nullable Throwable error) {
    Counters counters = countersByPath.get(path);
    if (counters != null) {
      counters.lastError = statusCode;
    }
    events.notifyDiagnostics(new PubSubDiagnosticsEvent(path, statusCode, message, error));
  }

  /** Record a listener failure; no event is emitted (the failing listener may be the cause). */
  void listenerError(String path) {
    Counters counters = countersByPath.get(path);
    if (counters != null) {
      counters.lastError = new StatusCode(StatusCodes.Bad_InternalError);
    }
  }

  @Override
  public Map<String, ComponentDiagnostics> snapshot() {
    var snapshot = new LinkedHashMap<String, ComponentDiagnostics>(countersByPath.size());
    countersByPath.forEach((path, counters) -> snapshot.put(path, counters.snapshot()));
    return Collections.unmodifiableMap(snapshot);
  }

  @Override
  public void reset(String path) {
    Counters counters = countersByPath.get(path);
    if (counters != null) {
      counters.resetCounters();
    }
  }

  private static final class CounterState {

    final LongAdder value = new LongAdder();
    final AtomicReference<DateTime> firstChange = new AtomicReference<>();

    void add(long delta) {
      if (delta == 0) {
        return;
      }
      value.add(delta);
      if (firstChange.get() == null) {
        // set once (until reset); a benign race sets a near-identical timestamp
        firstChange.compareAndSet(null, DateTime.now());
      }
    }

    void reset() {
      value.reset();
      firstChange.set(null);
    }
  }

  private static final class Counters {

    // pre-populated with every counter at construction, so the map is never structurally mutated
    // afterwards and its per-counter states can be read/written concurrently without locking
    private final EnumMap<Counter, CounterState> states = new EnumMap<>(Counter.class);

    volatile @Nullable StatusCode lastError;

    private final String path;

    private Counters(String path) {
      this.path = path;
      for (Counter counter : Counter.values()) {
        states.put(counter, new CounterState());
      }
    }

    void add(Counter counter, long delta) {
      states.get(counter).add(delta);
    }

    void resetCounters() {
      states.values().forEach(CounterState::reset);
    }

    ComponentDiagnostics snapshot() {
      var values = new EnumMap<Counter, Long>(Counter.class);
      var firstChanges = new EnumMap<Counter, DateTime>(Counter.class);

      for (Map.Entry<Counter, CounterState> entry : states.entrySet()) {
        CounterState state = entry.getValue();
        long sum = state.value.sum();
        if (sum != 0) {
          values.put(entry.getKey(), sum);
        }
        DateTime firstChange = state.firstChange.get();
        if (firstChange != null) {
          firstChanges.put(entry.getKey(), firstChange);
        }
      }

      return new ComponentDiagnostics(path, values, firstChanges, lastError);
    }
  }
}
