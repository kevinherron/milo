/*
 * Copyright (c) 2026 the Eclipse Milo Authors
 *
 * This program and the accompanying materials are made
 * available under the terms of the Eclipse Public License 2.0
 * which is available at https://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 */

package org.eclipse.milo.opcua.sdk.pubsub;

import java.util.Map;
import java.util.Optional;
import org.eclipse.milo.opcua.stack.core.types.builtin.DateTime;
import org.eclipse.milo.opcua.stack.core.types.builtin.StatusCode;
import org.jspecify.annotations.Nullable;

/**
 * Diagnostics view of a {@link PubSubService}: immutable per-component counter snapshots, keyed by
 * component path.
 *
 * <p>Counters that do not apply to a component type, e.g. {@code networkMessagesReceived} on a
 * WriterGroup, remain zero. The engine keeps every counter as an unbounded 64-bit value; the Part
 * 14 §9.1.11.5 UInt32 saturation (values cap at {@code 0xFFFFFFFF} while their SourceTimestamp
 * keeps updating) is applied only where the counters are exposed in the information model — see
 * {@link ComponentDiagnostics#toUInt32Saturating(long)}.
 */
public interface PubSubDiagnostics {

  /**
   * Get an immutable snapshot of the diagnostics of every component, keyed by component path, e.g.
   * {@code "conn/group/writer"}.
   *
   * @return an immutable snapshot of the diagnostics of every component.
   */
  Map<String, ComponentDiagnostics> snapshot();

  /**
   * Get an immutable snapshot of the diagnostics of the component at {@code path}.
   *
   * @param path the path of the component, e.g. {@code "conn/group/writer"}.
   * @return the component diagnostics, or empty if no component exists at {@code path}.
   */
  default Optional<ComponentDiagnostics> component(String path) {
    return Optional.ofNullable(snapshot().get(path));
  }

  /**
   * Reset (zero) every counter of the component at {@code path}, clearing each counter's {@link
   * ComponentDiagnostics#timeFirstChange(Counter) TimeFirstChange}. This is the Part 14 §9.1.11.3
   * Reset semantics: it acts on a single diagnostics object (not recursively on children) and
   * touches counters only — {@code lastError} is left unchanged (Reset is specified for counters,
   * and per-target write-error tracking lives outside this view). A {@code path} with no registered
   * component is a no-op.
   *
   * @param path the path of the component whose counters to reset.
   */
  void reset(String path);

  /**
   * The diagnostic counters of one PubSub component. Each maps to a Part 14 §9.1.11 counter where
   * one exists; the rest are Milo vendor counters (documented on {@link ComponentDiagnostics}).
   */
  enum Counter {

    /** NetworkMessages sent. */
    NETWORK_MESSAGES_SENT,

    /** NetworkMessages received (see {@link ComponentDiagnostics#networkMessagesReceived()}). */
    NETWORK_MESSAGES_RECEIVED,

    /** DataSetMessages sent. */
    DATA_SET_MESSAGES_SENT,

    /** DataSetMessages received. */
    DATA_SET_MESSAGES_RECEIVED,

    /** Messages dropped because they could not be decoded or were not accepted. */
    DECODE_ERRORS,

    /** {@link PublishedDataSetSource} read failures. */
    SOURCE_ERRORS,

    /** DataSetMessages dropped by a reader's §7.2.3 window as stale (older/duplicate). */
    STALE_SEQUENCE_MESSAGES,

    /** DataSetMessages dropped by a reader's §7.2.3 window as invalid (out-of-band recency). */
    INVALID_SEQUENCE_MESSAGES,

    /**
     * NetworkMessages a secured WriterGroup failed to encode (Table 322 {@code EncryptionErrors}).
     */
    ENCRYPTION_ERRORS,

    /**
     * Received secured NetworkMessages whose payload could not be parsed ({@code
     * DecryptionErrors}).
     */
    DECRYPTION_ERRORS,

    /** Received secured NetworkMessages dropped because their signature did not verify. */
    INVALID_SIGNATURE_MESSAGES,

    /** Received secured NetworkMessages dropped for an out-of-window SecurityTokenId. */
    UNKNOWN_TOKEN_MESSAGES,

    /** Received secured NetworkMessages dropped for an expired/retired key. */
    STALE_KEY_MESSAGES,

    /** Received NetworkMessages dropped for a security-mode mismatch. */
    SECURITY_MODE_REJECTED_MESSAGES,

    /**
     * NetworkMessages that failed to transmit — send or encode failures (Table 322 {@code
     * FailedTransmissions}).
     */
    FAILED_TRANSMISSIONS,

    /**
     * DataSetMessages never sent due to an encode/send failure, per writer (Table 328 {@code
     * FailedDataSetMessages}).
     */
    FAILED_DATA_SET_MESSAGES,

    /** State machine changed to {@code Error} (Table 311 {@code StateError}). */
    STATE_ERROR,

    /**
     * State changed to {@code Operational} triggered by an Enable Method call ({@code
     * StateOperationalByMethod}).
     */
    STATE_OPERATIONAL_BY_METHOD,

    /**
     * State changed to {@code Operational} triggered by an operational parent ({@code
     * StateOperationalByParent}).
     */
    STATE_OPERATIONAL_BY_PARENT,

    /**
     * State changed from {@code Error} to {@code Operational} ({@code StateOperationalFromError}).
     */
    STATE_OPERATIONAL_FROM_ERROR,

    /**
     * State changed to {@code Paused} triggered by a paused/disabled parent ({@code
     * StatePausedByParent}).
     */
    STATE_PAUSED_BY_PARENT,

    /**
     * State changed to {@code Disabled} triggered by a Disable Method call ({@code
     * StateDisabledByMethod}).
     */
    STATE_DISABLED_BY_METHOD
  }

  /**
   * An immutable snapshot of the diagnostic counters of one PubSub component.
   *
   * <p>Counter values are the engine's unbounded 64-bit sums; use {@link #counter(Counter)} for
   * uniform access or the named accessors below, and {@link #toUInt32Saturating(long)} to obtain
   * the Part 14 §9.1.11.5 UInt32-clamped value for information-model exposure. {@link
   * #timeFirstChange(Counter)} reports when a counter first left 0 (the §9.1.11.5 optional
   * TimeFirstChange), cleared by {@link PubSubDiagnostics#reset(String)}.
   *
   * <p>Counter semantics:
   *
   * <ul>
   *   <li>{@code networkMessagesReceived}: on a connection, one tick per received datagram or
   *       broker message before decoding and regardless of outcome, plus (for UADP discovery
   *       endpoints) one tick per discovery-socket datagram that decoded to a probe or
   *       announcement; on a reader group, one tick per NetworkMessage that matched at least one of
   *       the group's readers.
   *   <li>{@code decodeErrors}: undecodable/truncated input and unsupported chunked NetworkMessages
   *       at the connection; oversize NetworkMessages at a reader group; version mismatches,
   *       invalid DataSetMessages, and unconvertible DataSetMetaData announcements at the reader.
   *   <li>{@code staleSequenceMessages}/{@code invalidSequenceMessages}: DataSetMessages dropped by
   *       a DataSetReader's Part 14 §7.2.3 sequence-number window; per-reader, one tick per dropped
   *       DataSetMessage; a normal-operation counter (no {@code lastError}). Milo vendor counters.
   *   <li>{@code encryptionErrors}/{@code decryptionErrors}: the Part 14 Table 322/328
   *       EncryptionErrors/DecryptionErrors feed (secured encode failures at a WriterGroup; secured
   *       payload-parse failures at a matching ReaderGroup or the connection). Set {@code
   *       lastError}.
   *   <li>{@code invalidSignatureMessages}/{@code unknownTokenMessages}/{@code
   *       staleKeyMessages}/{@code securityModeRejectedMessages}: Milo vendor security-drop
   *       counters; the last three are normal-operation (no {@code lastError}).
   *   <li>{@code failedTransmissions}: NetworkMessages a WriterGroup failed to transmit — a
   *       synchronous or asynchronous send failure carrying the transport's real status, or an
   *       encode failure. Send failures that occur while the connection's publisher channel is
   *       closing on a clean shutdown, disable, or reconfigure-removal are not counted
   *       (channel-teardown noise, not an operational failure). Sets {@code lastError}. The Part 14
   *       Table 322 {@code FailedTransmissions} feed. Oversize (maxNetworkMessageSize) skips are
   *       recorded as {@code Bad_EncodingLimitsExceeded} decode-limit diagnostics, not here.
   *   <li>{@code failedDataSetMessages}: DataSetMessages never sent because the NetworkMessage
   *       carrying them failed to encode or send, attributed once per contributing writer at
   *       DataSetWriter paths (the Part 14 Table 328 {@code FailedDataSetMessages} feed). A
   *       counter-only attribution: the WriterGroup's {@code failedTransmissions} already carried
   *       the error and event. Reader-side FailedDataSetMessages are folded into {@code
   *       decodeErrors}.
   *   <li>{@code stateError}/{@code stateOperationalByMethod}/{@code
   *       stateOperationalByParent}/{@code stateOperationalFromError}/{@code
   *       statePausedByParent}/{@code stateDisabledByMethod}: the six Part 14 Table 311
   *       state-machine counters, present on every component. {@code
   *       StateOperationalByMethod}/{@code ByParent} are attributed on the final {@code
   *       PreOperational -> Operational} hop from the remembered enable/parent trigger; a {@code
   *       Disabled} transition from subtree teardown (reconfigure-removal/shutdown) is not counted
   *       as {@code stateDisabledByMethod}.
   * </ul>
   *
   * @param path the path of the component, e.g. {@code "conn/group/writer"}.
   * @param counters the counter values by {@link Counter}; absent entries are 0.
   * @param timeFirstChanges the timestamp each counter first left 0, by {@link Counter}; absent
   *     entries mean the counter is still 0 (or was reset).
   * @param lastError the status code of the most recent error, or {@code null} if none has
   *     occurred.
   */
  record ComponentDiagnostics(
      String path,
      Map<Counter, Long> counters,
      Map<Counter, DateTime> timeFirstChanges,
      @Nullable StatusCode lastError) {

    /** The Part 14 §9.1.11.5 UInt32 counter maximum. */
    public static final long UINT32_MAX = 0xFFFF_FFFFL;

    public ComponentDiagnostics {
      counters = Map.copyOf(counters);
      timeFirstChanges = Map.copyOf(timeFirstChanges);
    }

    /**
     * Get the value of {@code counter}, or 0 if it has never been incremented.
     *
     * @param counter the counter to read.
     * @return the counter's unbounded 64-bit value.
     */
    public long counter(Counter counter) {
      Long value = counters.get(counter);
      return value != null ? value : 0L;
    }

    /**
     * Get when {@code counter} first left 0, the Part 14 §9.1.11.5 TimeFirstChange.
     *
     * @param counter the counter to read.
     * @return the timestamp of the counter's first increment, or empty while it is still 0.
     */
    public Optional<DateTime> timeFirstChange(Counter counter) {
      return Optional.ofNullable(timeFirstChanges.get(counter));
    }

    /**
     * Clamp a 64-bit counter value to the Part 14 §9.1.11.5 UInt32 range: values at or above {@code
     * 0xFFFFFFFF} report {@code 0xFFFFFFFF}. The information-model exposure keeps updating a
     * clamped counter's SourceTimestamp on every further increment (detected from the unbounded
     * 64-bit value still climbing), so the value freezes at the cap while its timestamp does not.
     *
     * @param value the unbounded 64-bit counter value.
     * @return the value clamped to {@code [0, 0xFFFFFFFF]}.
     */
    public static long toUInt32Saturating(long value) {
      return Math.min(value, UINT32_MAX);
    }

    public long networkMessagesSent() {
      return counter(Counter.NETWORK_MESSAGES_SENT);
    }

    public long networkMessagesReceived() {
      return counter(Counter.NETWORK_MESSAGES_RECEIVED);
    }

    public long dataSetMessagesSent() {
      return counter(Counter.DATA_SET_MESSAGES_SENT);
    }

    public long dataSetMessagesReceived() {
      return counter(Counter.DATA_SET_MESSAGES_RECEIVED);
    }

    public long decodeErrors() {
      return counter(Counter.DECODE_ERRORS);
    }

    public long sourceErrors() {
      return counter(Counter.SOURCE_ERRORS);
    }

    public long staleSequenceMessages() {
      return counter(Counter.STALE_SEQUENCE_MESSAGES);
    }

    public long invalidSequenceMessages() {
      return counter(Counter.INVALID_SEQUENCE_MESSAGES);
    }

    public long encryptionErrors() {
      return counter(Counter.ENCRYPTION_ERRORS);
    }

    public long decryptionErrors() {
      return counter(Counter.DECRYPTION_ERRORS);
    }

    public long invalidSignatureMessages() {
      return counter(Counter.INVALID_SIGNATURE_MESSAGES);
    }

    public long unknownTokenMessages() {
      return counter(Counter.UNKNOWN_TOKEN_MESSAGES);
    }

    public long staleKeyMessages() {
      return counter(Counter.STALE_KEY_MESSAGES);
    }

    public long securityModeRejectedMessages() {
      return counter(Counter.SECURITY_MODE_REJECTED_MESSAGES);
    }

    public long failedTransmissions() {
      return counter(Counter.FAILED_TRANSMISSIONS);
    }

    public long failedDataSetMessages() {
      return counter(Counter.FAILED_DATA_SET_MESSAGES);
    }

    public long stateError() {
      return counter(Counter.STATE_ERROR);
    }

    public long stateOperationalByMethod() {
      return counter(Counter.STATE_OPERATIONAL_BY_METHOD);
    }

    public long stateOperationalByParent() {
      return counter(Counter.STATE_OPERATIONAL_BY_PARENT);
    }

    public long stateOperationalFromError() {
      return counter(Counter.STATE_OPERATIONAL_FROM_ERROR);
    }

    public long statePausedByParent() {
      return counter(Counter.STATE_PAUSED_BY_PARENT);
    }

    public long stateDisabledByMethod() {
      return counter(Counter.STATE_DISABLED_BY_METHOD);
    }
  }
}
