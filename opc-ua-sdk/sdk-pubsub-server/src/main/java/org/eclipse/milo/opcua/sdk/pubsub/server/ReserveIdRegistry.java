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

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;
import org.eclipse.milo.opcua.sdk.pubsub.transport.udp.UdpTransportProvider;
import org.eclipse.milo.opcua.stack.core.StatusCodes;
import org.eclipse.milo.opcua.stack.core.UaException;
import org.eclipse.milo.opcua.stack.core.types.builtin.NodeId;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.ULong;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UShort;
import org.eclipse.milo.opcua.stack.core.types.structured.DataSetWriterDataType;
import org.eclipse.milo.opcua.stack.core.types.structured.PubSubConfiguration2DataType;
import org.eclipse.milo.opcua.stack.core.types.structured.PubSubConnectionDataType;
import org.eclipse.milo.opcua.stack.core.types.structured.WriterGroupDataType;

/**
 * The per-Session {@code ReserveIds} registry (OPC UA Part 14 §9.1.3.7.5): reserves unique
 * WriterGroupIds and DataSetWriterIds from the internal-assignment range {@code 0x8000-0xFFFF} and
 * returns the transport-profile default PublisherId (§6.2.7.1).
 *
 * <p>Reservations are valid while the Session lives; uniqueness spans the live configuration and
 * all outstanding reservations (from every Session); reservations are released when the reserved id
 * appears in the applied configuration ({@link #releaseUsed}) or when the Session closes ({@link
 * #evictSession}). The allocator owns {@code 0x8000-0xFFFF}; an unknown TransportProfileUri is
 * {@code Bad_InvalidArgument}; a request that cannot be satisfied is {@code
 * Bad_ResourceUnavailable}.
 *
 * <p>All methods are synchronized on this instance.
 */
final class ReserveIdRegistry {

  static final int MIN_INTERNAL_ID = 0x8000;
  static final int MAX_INTERNAL_ID = 0xFFFF;

  static final String UDP_UADP = UdpTransportProvider.TRANSPORT_PROFILE_URI;
  static final String MQTT_UADP = "http://opcfoundation.org/UA-Profile/Transport/pubsub-mqtt-uadp";
  static final String MQTT_JSON = "http://opcfoundation.org/UA-Profile/Transport/pubsub-mqtt-json";

  /** Per-Session reserved ids (aggregated across transport profiles for uniqueness). */
  private final Map<NodeId, SessionReservation> reservations = new HashMap<>();

  private final Supplier<PubSubConfiguration2DataType> currentConfigSupplier;

  /** The datagram/UADP default PublisherId (UInt64), MAC+port derived (§6.2.7.1). */
  private final ULong defaultDatagramPublisherId;

  ReserveIdRegistry(
      Supplier<PubSubConfiguration2DataType> currentConfigSupplier,
      ULong defaultDatagramPublisherId) {

    this.currentConfigSupplier = currentConfigSupplier;
    this.defaultDatagramPublisherId = defaultDatagramPublisherId;
  }

  /**
   * The reserved ids and the transport-profile default PublisherId returned to a {@code ReserveIds}
   * caller.
   */
  record Reservation(
      Object defaultPublisherId, UShort[] writerGroupIds, UShort[] dataSetWriterIds) {}

  /**
   * Reserve {@code numWriterGroupIds} WriterGroupIds and {@code numDataSetWriterIds}
   * DataSetWriterIds for {@code sessionId} under {@code transportProfileUri}.
   *
   * @throws UaException {@code Bad_InvalidArgument} for an unknown TransportProfileUri, or {@code
   *     Bad_ResourceUnavailable} if the internal-assignment range cannot satisfy the request.
   */
  synchronized Reservation reserve(
      NodeId sessionId, String transportProfileUri, int numWriterGroupIds, int numDataSetWriterIds)
      throws UaException {

    Object defaultPublisherId = defaultPublisherIdFor(transportProfileUri);

    Set<Integer> usedWriterGroupIds = new HashSet<>();
    Set<Integer> usedDataSetWriterIds = new HashSet<>();
    collectConfigIds(currentConfigSupplier.get(), usedWriterGroupIds, usedDataSetWriterIds);
    for (SessionReservation reservation : reservations.values()) {
      usedWriterGroupIds.addAll(reservation.writerGroupIds);
      usedDataSetWriterIds.addAll(reservation.dataSetWriterIds);
    }

    // allocate both sets before recording either, so a partial failure reserves nothing
    Set<Integer> newWriterGroupIds = allocate(numWriterGroupIds, usedWriterGroupIds);
    Set<Integer> newDataSetWriterIds = allocate(numDataSetWriterIds, usedDataSetWriterIds);

    SessionReservation reservation =
        reservations.computeIfAbsent(sessionId, id -> new SessionReservation());
    reservation.writerGroupIds.addAll(newWriterGroupIds);
    reservation.dataSetWriterIds.addAll(newDataSetWriterIds);

    return new Reservation(
        defaultPublisherId, toUShortArray(newWriterGroupIds), toUShortArray(newDataSetWriterIds));
  }

  /**
   * Release reservations for {@code sessionId} that are now present in {@code appliedConfig} (Part
   * 14 §9.1.3.7.5: "The reservation is only valid until the ID is used in the configuration").
   */
  synchronized void releaseUsed(NodeId sessionId, PubSubConfiguration2DataType appliedConfig) {
    SessionReservation reservation = reservations.get(sessionId);
    if (reservation == null) {
      return;
    }

    Set<Integer> configWriterGroupIds = new HashSet<>();
    Set<Integer> configDataSetWriterIds = new HashSet<>();
    collectConfigIds(appliedConfig, configWriterGroupIds, configDataSetWriterIds);

    reservation.writerGroupIds.removeAll(configWriterGroupIds);
    reservation.dataSetWriterIds.removeAll(configDataSetWriterIds);

    if (reservation.writerGroupIds.isEmpty() && reservation.dataSetWriterIds.isEmpty()) {
      reservations.remove(sessionId);
    }
  }

  /** Drop all reservations owned by {@code sessionId} (Session close). */
  synchronized void evictSession(NodeId sessionId) {
    reservations.remove(sessionId);
  }

  /** All WriterGroupIds reserved by any Session (for the CloseAndUpdate allocator to avoid). */
  synchronized Set<Integer> allReservedWriterGroupIds() {
    var ids = new HashSet<Integer>();
    for (SessionReservation reservation : reservations.values()) {
      ids.addAll(reservation.writerGroupIds);
    }
    return ids;
  }

  /** All DataSetWriterIds reserved by any Session. */
  synchronized Set<Integer> allReservedDataSetWriterIds() {
    var ids = new HashSet<Integer>();
    for (SessionReservation reservation : reservations.values()) {
      ids.addAll(reservation.dataSetWriterIds);
    }
    return ids;
  }

  private Object defaultPublisherIdFor(String transportProfileUri) throws UaException {
    return switch (transportProfileUri) {
      case UDP_UADP, MQTT_UADP -> defaultDatagramPublisherId;
      // JSON message mapping: the UInt64 value converted to a String (§6.2.7.1)
      case MQTT_JSON -> defaultDatagramPublisherId.toString();
      default ->
          throw new UaException(
              StatusCodes.Bad_InvalidArgument,
              "unsupported TransportProfileUri: " + transportProfileUri);
    };
  }

  private static Set<Integer> allocate(int count, Set<Integer> used) throws UaException {
    var allocated = new HashSet<Integer>();
    for (int id = MIN_INTERNAL_ID; id <= MAX_INTERNAL_ID && allocated.size() < count; id++) {
      if (!used.contains(id)) {
        allocated.add(id);
        used.add(id);
      }
    }
    if (allocated.size() < count) {
      throw new UaException(
          StatusCodes.Bad_ResourceUnavailable,
          "cannot reserve " + count + " ids in the internal-assignment range");
    }
    return allocated;
  }

  private static void collectConfigIds(
      PubSubConfiguration2DataType config,
      Set<Integer> writerGroupIds,
      Set<Integer> dataSetWriterIds) {

    if (config == null) {
      return;
    }
    PubSubConnectionDataType[] connections = config.getConnections();
    if (connections == null) {
      return;
    }
    for (PubSubConnectionDataType connection : connections) {
      if (connection == null) {
        continue;
      }
      WriterGroupDataType[] writerGroups = connection.getWriterGroups();
      if (writerGroups == null) {
        continue;
      }
      for (WriterGroupDataType group : writerGroups) {
        if (group == null) {
          continue;
        }
        if (group.getWriterGroupId() != null) {
          writerGroupIds.add(group.getWriterGroupId().intValue());
        }
        DataSetWriterDataType[] writers = group.getDataSetWriters();
        if (writers != null) {
          for (DataSetWriterDataType writer : writers) {
            if (writer != null && writer.getDataSetWriterId() != null) {
              dataSetWriterIds.add(writer.getDataSetWriterId().intValue());
            }
          }
        }
      }
    }
  }

  private static UShort[] toUShortArray(Set<Integer> ids) {
    return ids.stream().sorted().map(id -> ushort(id)).toArray(UShort[]::new);
  }

  private static final class SessionReservation {
    final Set<Integer> writerGroupIds = new HashSet<>();
    final Set<Integer> dataSetWriterIds = new HashSet<>();
  }
}
