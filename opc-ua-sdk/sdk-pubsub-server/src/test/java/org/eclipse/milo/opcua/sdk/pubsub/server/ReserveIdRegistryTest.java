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
import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.ulong;
import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.ushort;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Supplier;
import org.eclipse.milo.opcua.stack.core.StatusCodes;
import org.eclipse.milo.opcua.stack.core.UaException;
import org.eclipse.milo.opcua.stack.core.types.builtin.NodeId;
import org.eclipse.milo.opcua.stack.core.types.builtin.Variant;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.ULong;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UShort;
import org.eclipse.milo.opcua.stack.core.types.enumerated.MessageSecurityMode;
import org.eclipse.milo.opcua.stack.core.types.structured.DataSetWriterDataType;
import org.eclipse.milo.opcua.stack.core.types.structured.PubSubConfiguration2DataType;
import org.eclipse.milo.opcua.stack.core.types.structured.PubSubConnectionDataType;
import org.eclipse.milo.opcua.stack.core.types.structured.WriterGroupDataType;
import org.junit.jupiter.api.Test;

/** Tests for the per-Session {@link ReserveIdRegistry}. */
class ReserveIdRegistryTest {

  private static final ULong DEFAULT_PUBLISHER_ID = ulong(0xAABBCCDDL);
  private static final NodeId SESSION_A = new NodeId(1, "session-a");
  private static final NodeId SESSION_B = new NodeId(1, "session-b");

  private static final PubSubConfiguration2DataType EMPTY_CONFIG =
      new PubSubConfiguration2DataType(
          null, new PubSubConnectionDataType[0], true, null, null, null, null, null, uint(0), null);

  private static ReserveIdRegistry registry(Supplier<PubSubConfiguration2DataType> config) {
    return new ReserveIdRegistry(config, DEFAULT_PUBLISHER_ID);
  }

  private static PubSubConfiguration2DataType configWithIds(
      int writerGroupId, int dataSetWriterId) {
    var writer =
        new DataSetWriterDataType(
            "w", true, ushort(dataSetWriterId), null, null, null, null, null, null);
    var group =
        new WriterGroupDataType(
            "wg",
            true,
            MessageSecurityMode.None,
            null,
            null,
            null,
            null,
            ushort(writerGroupId),
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            new DataSetWriterDataType[] {writer});
    var connection =
        new PubSubConnectionDataType(
            "c",
            true,
            Variant.NULL_VALUE,
            ReserveIdRegistry.UDP_UADP,
            null,
            null,
            null,
            new WriterGroupDataType[] {group},
            null);
    return new PubSubConfiguration2DataType(
        null,
        new PubSubConnectionDataType[] {connection},
        true,
        null,
        null,
        null,
        null,
        null,
        uint(0),
        null);
  }

  @Test
  void reservesIdsInTheInternalRangeWithADatagramDefaultPublisherId() throws Exception {
    ReserveIdRegistry registry = registry(() -> EMPTY_CONFIG);

    ReserveIdRegistry.Reservation reservation =
        registry.reserve(SESSION_A, ReserveIdRegistry.UDP_UADP, 2, 3);

    assertEquals(DEFAULT_PUBLISHER_ID, reservation.defaultPublisherId());
    assertEquals(2, reservation.writerGroupIds().length);
    assertEquals(3, reservation.dataSetWriterIds().length);
    for (UShort id : reservation.writerGroupIds()) {
      assertTrue(id.intValue() >= ReserveIdRegistry.MIN_INTERNAL_ID);
      assertTrue(id.intValue() <= ReserveIdRegistry.MAX_INTERNAL_ID);
    }
  }

  @Test
  void jsonProfileDefaultPublisherIdIsTheStringConversion() throws Exception {
    ReserveIdRegistry registry = registry(() -> EMPTY_CONFIG);

    ReserveIdRegistry.Reservation reservation =
        registry.reserve(SESSION_A, ReserveIdRegistry.MQTT_JSON, 1, 0);

    assertEquals(DEFAULT_PUBLISHER_ID.toString(), reservation.defaultPublisherId());
  }

  @Test
  void unknownTransportProfileIsInvalidArgument() {
    ReserveIdRegistry registry = registry(() -> EMPTY_CONFIG);

    UaException e =
        assertThrows(UaException.class, () -> registry.reserve(SESSION_A, "urn:bogus", 1, 1));
    assertEquals(StatusCodes.Bad_InvalidArgument, e.getStatusCode().getValue());
  }

  @Test
  void reservationsAvoidIdsUsedByTheLiveConfiguration() throws Exception {
    ReserveIdRegistry registry = registry(() -> configWithIds(0x8000, 0x8000));

    ReserveIdRegistry.Reservation reservation =
        registry.reserve(SESSION_A, ReserveIdRegistry.UDP_UADP, 1, 1);

    assertNotEquals(0x8000, reservation.writerGroupIds()[0].intValue());
    assertNotEquals(0x8000, reservation.dataSetWriterIds()[0].intValue());
  }

  @Test
  void reservationsAcrossSessionsAreDisjoint() throws Exception {
    ReserveIdRegistry registry = registry(() -> EMPTY_CONFIG);

    ReserveIdRegistry.Reservation a = registry.reserve(SESSION_A, ReserveIdRegistry.UDP_UADP, 3, 0);
    ReserveIdRegistry.Reservation b = registry.reserve(SESSION_B, ReserveIdRegistry.UDP_UADP, 3, 0);

    Set<Integer> aIds = new HashSet<>();
    Arrays.stream(a.writerGroupIds()).forEach(id -> aIds.add(id.intValue()));
    for (UShort id : b.writerGroupIds()) {
      assertTrue(aIds.add(id.intValue()), "id " + id + " reserved twice");
    }
  }

  @Test
  void anUnsatisfiableRequestIsResourceUnavailable() {
    ReserveIdRegistry registry = registry(() -> EMPTY_CONFIG);

    UaException e =
        assertThrows(
            UaException.class,
            () -> registry.reserve(SESSION_A, ReserveIdRegistry.UDP_UADP, 40000, 0));
    assertEquals(StatusCodes.Bad_ResourceUnavailable, e.getStatusCode().getValue());
  }

  @Test
  void releaseUsedFreesReservationsPresentInTheAppliedConfiguration() throws Exception {
    ReserveIdRegistry registry = registry(() -> EMPTY_CONFIG);

    ReserveIdRegistry.Reservation reservation =
        registry.reserve(SESSION_A, ReserveIdRegistry.UDP_UADP, 1, 1);
    int reservedWg = reservation.writerGroupIds()[0].intValue();

    // the reserved WriterGroupId is now used in the applied config
    registry.releaseUsed(SESSION_A, configWithIds(reservedWg, 0x1234));

    // a fresh reservation may now hand out the (released) id again if it is otherwise free;
    // the outstanding-reservation set no longer blocks it
    assertTrue(registry.allReservedWriterGroupIds().stream().noneMatch(id -> id == reservedWg));
  }

  @Test
  void evictSessionDropsAllReservations() throws Exception {
    ReserveIdRegistry registry = registry(() -> EMPTY_CONFIG);
    registry.reserve(SESSION_A, ReserveIdRegistry.UDP_UADP, 2, 2);

    registry.evictSession(SESSION_A);

    assertTrue(registry.allReservedWriterGroupIds().isEmpty());
    assertTrue(registry.allReservedDataSetWriterIds().isEmpty());
  }
}
