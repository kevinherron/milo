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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.eclipse.milo.opcua.sdk.pubsub.PubSubDiagnostics.ComponentDiagnostics;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubDiagnostics.Counter;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubStateChangeEvent.Cause;
import org.eclipse.milo.opcua.stack.core.StatusCodes;
import org.eclipse.milo.opcua.stack.core.types.builtin.StatusCode;
import org.eclipse.milo.opcua.stack.core.types.enumerated.PubSubState;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for the Phase 5 R12 {@link DiagnosticsCollector} enrichment: the six Part 14 Table 311
 * state counters attributed by transition cause and remembered trigger, {@code
 * FailedTransmissions}/{@code FailedDataSetMessages}, per-counter TimeFirstChange, {@code
 * reset(path)} (counters only, lastError preserved), and the exposure-time UInt32 saturation clamp
 * over the engine's unbounded 64-bit counters.
 */
class DiagnosticsCollectorTest {

  private final DiagnosticsCollector collector =
      new DiagnosticsCollector(new EventDispatcher(Runnable::run));

  private ComponentDiagnostics diag(String path) {
    ComponentDiagnostics cd = collector.snapshot().get(path);
    assertNotNull(cd, path);
    return cd;
  }

  @Test
  void stateCountersAttributedByTransitionAndRememberedTrigger() {
    collector.register("c");

    // final PreOperational -> Operational hop reported as STARTUP: attribution uses the remembered
    // trigger (METHOD vs PARENT)
    collector.recordStateChange(
        "c", PubSubState.PreOperational, PubSubState.Operational, Cause.STARTUP, Cause.METHOD);
    collector.recordStateChange(
        "c", PubSubState.PreOperational, PubSubState.Operational, Cause.STARTUP, Cause.PARENT);
    // Error and recovery
    collector.recordStateChange(
        "c", PubSubState.Operational, PubSubState.Error, Cause.ERROR_RECOVERY, null);
    collector.recordStateChange(
        "c", PubSubState.Error, PubSubState.Operational, Cause.ERROR_RECOVERY, Cause.METHOD);
    // Paused always counts as by-parent
    collector.recordStateChange(
        "c", PubSubState.Operational, PubSubState.Paused, Cause.PARENT, null);
    // Disabled by method vs by dispose (dispose is not counted)
    collector.recordStateChange(
        "c", PubSubState.Operational, PubSubState.Disabled, Cause.METHOD, null);
    collector.recordStateChange(
        "c", PubSubState.Operational, PubSubState.Disabled, Cause.DISPOSE, null);
    // PreOperational entry has no state counter
    collector.recordStateChange(
        "c", PubSubState.Disabled, PubSubState.PreOperational, Cause.METHOD, null);

    ComponentDiagnostics c = diag("c");
    assertEquals(1, c.stateOperationalByMethod());
    assertEquals(1, c.stateOperationalByParent());
    assertEquals(1, c.stateError());
    assertEquals(1, c.stateOperationalFromError());
    assertEquals(1, c.statePausedByParent());
    assertEquals(1, c.stateDisabledByMethod(), "dispose must not count as StateDisabledByMethod");
  }

  @Test
  void failedTransmissionAndFailedDataSetMessageCounters() {
    collector.register("c/g");
    collector.register("c/g/w");

    collector.failedTransmission(
        "c/g", new StatusCode(StatusCodes.Bad_Timeout), "send failed", null);
    collector.failedDataSetMessage("c/g/w");
    collector.failedDataSetMessage("c/g/w");

    assertEquals(1, diag("c/g").failedTransmissions());
    // FailedTransmissions carries lastError (it emitted the diagnostics event)
    assertEquals(new StatusCode(StatusCodes.Bad_Timeout), diag("c/g").lastError());
    // FailedDataSetMessages is a counter-only per-writer attribution: no lastError
    assertEquals(2, diag("c/g/w").failedDataSetMessages());
    assertNull(diag("c/g/w").lastError());
  }

  @Test
  void timeFirstChangeSetOnFirstIncrementAndClearedByReset() {
    collector.register("c");
    assertTrue(diag("c").timeFirstChange(Counter.DECODE_ERRORS).isEmpty());

    collector.decodeError("c", new StatusCode(StatusCodes.Bad_DecodingError), "bad", null);

    assertTrue(diag("c").timeFirstChange(Counter.DECODE_ERRORS).isPresent());
    assertEquals(1, diag("c").decodeErrors());

    collector.reset("c");

    assertEquals(0, diag("c").decodeErrors());
    assertTrue(
        diag("c").timeFirstChange(Counter.DECODE_ERRORS).isEmpty(),
        "reset must clear TimeFirstChange");
  }

  @Test
  void resetZeroesCountersButKeepsLastError() {
    collector.register("c");
    collector.decodeError("c", new StatusCode(StatusCodes.Bad_DecodingError), "bad", null);
    collector.networkMessageReceived("c");

    collector.reset("c");

    ComponentDiagnostics c = diag("c");
    assertEquals(0, c.decodeErrors());
    assertEquals(0, c.networkMessagesReceived());
    // Reset is specified for counters only; lastError is left untouched
    assertEquals(new StatusCode(StatusCodes.Bad_DecodingError), c.lastError());
  }

  @Test
  void resetUnknownPathIsNoOp() {
    collector.reset("does/not/exist");
    assertNull(collector.snapshot().get("does/not/exist"));
  }

  @Test
  void countersAreUnboundedAndClampSaturatesAtUInt32Max() {
    collector.register("c");
    // exceed 2^32 with two int-max adds: the engine keeps the true 64-bit sum
    collector.dataSetMessagesSent("c", Integer.MAX_VALUE);
    collector.dataSetMessagesSent("c", Integer.MAX_VALUE);
    collector.dataSetMessagesSent("c", 4);

    long raw = diag("c").dataSetMessagesSent();
    assertEquals(2L * Integer.MAX_VALUE + 4L, raw);
    assertTrue(raw > ComponentDiagnostics.UINT32_MAX, "engine counter must be unbounded 64-bit");

    // the information-model exposure clamps to UInt32
    assertEquals(ComponentDiagnostics.UINT32_MAX, ComponentDiagnostics.toUInt32Saturating(raw));
    assertEquals(0L, ComponentDiagnostics.toUInt32Saturating(0L));
    assertEquals(100L, ComponentDiagnostics.toUInt32Saturating(100L));
    assertEquals(
        ComponentDiagnostics.UINT32_MAX,
        ComponentDiagnostics.toUInt32Saturating(ComponentDiagnostics.UINT32_MAX));
    assertEquals(
        ComponentDiagnostics.UINT32_MAX,
        ComponentDiagnostics.toUInt32Saturating(ComponentDiagnostics.UINT32_MAX + 1));
  }

  @Test
  void incrementsForUnregisteredPathsAreDropped() {
    collector.networkMessageSent("ghost");
    collector.recordStateChange(
        "ghost", PubSubState.PreOperational, PubSubState.Operational, Cause.STARTUP, Cause.METHOD);
    assertNull(collector.snapshot().get("ghost"));
  }
}
