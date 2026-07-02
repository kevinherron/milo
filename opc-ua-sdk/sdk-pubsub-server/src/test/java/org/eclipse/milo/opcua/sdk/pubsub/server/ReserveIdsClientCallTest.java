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

import static org.eclipse.milo.opcua.sdk.pubsub.server.RemoteConfigClientSupport.RESERVE_IDS;
import static org.eclipse.milo.opcua.sdk.pubsub.server.RemoteConfigClientSupport.TIMEOUT;
import static org.eclipse.milo.opcua.sdk.pubsub.server.RemoteConfigClientSupport.awaitTrue;
import static org.eclipse.milo.opcua.sdk.pubsub.server.RemoteConfigClientSupport.call;
import static org.eclipse.milo.opcua.sdk.pubsub.server.RemoteConfigClientSupport.connect;
import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.ushort;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import org.eclipse.milo.opcua.sdk.client.OpcUaClient;
import org.eclipse.milo.opcua.stack.core.StatusCodes;
import org.eclipse.milo.opcua.stack.core.types.builtin.Variant;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.ULong;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UShort;
import org.eclipse.milo.opcua.stack.core.types.structured.CallMethodResult;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * The Part 14 §9.1.3.7.5 {@code ReserveIds} method driven end-to-end by a real {@link OpcUaClient}
 * {@code Call} — pin R5. {@link ReserveIdRegistryTest} unit-tests the allocator; this class runs it
 * through the wire, so the per-{@link org.eclipse.milo.opcua.sdk.server.Session} keying, the
 * transport-profile default PublisherId typing that returns over the wire as a {@code BaseDataType}
 * out-argument, and the {@code SessionListener} release-on-close all exercise the real session
 * path.
 */
class ReserveIdsClientCallTest {

  private static final String UDP_UADP =
      "http://opcfoundation.org/UA-Profile/Transport/pubsub-udp-uadp";
  private static final String MQTT_JSON =
      "http://opcfoundation.org/UA-Profile/Transport/pubsub-mqtt-json";

  private static final int MIN_INTERNAL_ID = 0x8000;
  private static final int MAX_INTERNAL_ID = 0xFFFF;
  private static final int RANGE_SIZE = MAX_INTERNAL_ID - MIN_INTERNAL_ID + 1;

  private static TestSksServer sks;

  @BeforeAll
  static void startServer() throws Exception {
    sks = TestSksServer.create();
  }

  @AfterAll
  static void stopServer() throws Exception {
    if (sks != null) {
      sks.close();
    }
  }

  private static ServerPubSub attach() throws Exception {
    ServerPubSub serverPubSub =
        ServerPubSub.attach(
            sks.getServer(),
            org.eclipse.milo.opcua.sdk.pubsub.config.PubSubConfig.builder().build(),
            ServerPubSubOptions.builder().allowRemoteConfiguration(true).build());
    serverPubSub.startup().get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);
    return serverPubSub;
  }

  private static CallMethodResult reserve(
      OpcUaClient client, String profile, int numWriterGroups, int numDataSetWriters)
      throws Exception {
    return call(
        client,
        RESERVE_IDS,
        new Variant(profile),
        new Variant(ushort(numWriterGroups)),
        new Variant(ushort(numDataSetWriters)));
  }

  @Test
  void reservesIdsInTheInternalRangeWithADatagramDefaultPublisherId() throws Exception {
    try (ServerPubSub ignored = attach()) {
      OpcUaClient client = connect(sks);
      try {
        CallMethodResult result = reserve(client, UDP_UADP, 2, 3);
        assertTrue(result.getStatusCode().isGood(), result.toString());

        Variant[] out = result.getOutputArguments();
        // §9.1.3.7.5 out-args: DefaultPublisherId, WriterGroupIds, DataSetWriterIds
        assertInstanceOf(ULong.class, out[0].getValue()); // UInt64 for datagram transports

        UShort[] writerGroupIds = (UShort[]) out[1].getValue();
        UShort[] dataSetWriterIds = (UShort[]) out[2].getValue();
        assertEquals(2, writerGroupIds.length);
        assertEquals(3, dataSetWriterIds.length);

        for (UShort id : writerGroupIds) {
          assertTrue(id.intValue() >= MIN_INTERNAL_ID && id.intValue() <= MAX_INTERNAL_ID, "" + id);
        }
        for (UShort id : dataSetWriterIds) {
          assertTrue(id.intValue() >= MIN_INTERNAL_ID && id.intValue() <= MAX_INTERNAL_ID, "" + id);
        }
      } finally {
        client.disconnect();
      }
    }
  }

  @Test
  void jsonProfileReturnsAStringDefaultPublisherId() throws Exception {
    try (ServerPubSub ignored = attach()) {
      OpcUaClient client = connect(sks);
      try {
        CallMethodResult result = reserve(client, MQTT_JSON, 1, 0);
        assertTrue(result.getStatusCode().isGood(), result.toString());
        // §6.2.7.1: JSON message mapping uses the UInt64 default converted to a String
        assertInstanceOf(String.class, result.getOutputArguments()[0].getValue());
      } finally {
        client.disconnect();
      }
    }
  }

  @Test
  void unknownTransportProfileIsInvalidArgument() throws Exception {
    try (ServerPubSub ignored = attach()) {
      OpcUaClient client = connect(sks);
      try {
        CallMethodResult result = reserve(client, "urn:bogus:profile", 1, 1);
        assertEquals(StatusCodes.Bad_InvalidArgument, result.getStatusCode().getValue());
      } finally {
        client.disconnect();
      }
    }
  }

  @Test
  void reservationsAcrossSessionsAreDisjoint() throws Exception {
    try (ServerPubSub ignored = attach()) {
      OpcUaClient a = connect(sks);
      OpcUaClient b = connect(sks);
      try {
        UShort[] aIds = (UShort[]) reserve(a, UDP_UADP, 4, 0).getOutputArguments()[1].getValue();
        UShort[] bIds = (UShort[]) reserve(b, UDP_UADP, 4, 0).getOutputArguments()[1].getValue();

        // uniqueness spans all outstanding reservations from every session (pin R5)
        Set<Integer> seen = new HashSet<>();
        Arrays.stream(aIds).forEach(id -> seen.add(id.intValue()));
        for (UShort id : bIds) {
          assertTrue(seen.add(id.intValue()), "id " + id + " reserved to two sessions");
        }
      } finally {
        a.disconnect();
        b.disconnect();
      }
    }
  }

  @Test
  void anUnsatisfiableRequestIsResourceUnavailable() throws Exception {
    try (ServerPubSub ignored = attach()) {
      OpcUaClient client = connect(sks);
      try {
        // more WriterGroupIds than the internal-assignment range holds
        CallMethodResult result = reserve(client, UDP_UADP, RANGE_SIZE + 1, 0);
        assertEquals(StatusCodes.Bad_ResourceUnavailable, result.getStatusCode().getValue());
      } finally {
        client.disconnect();
      }
    }
  }

  @Test
  void reservationsAreReleasedWhenTheSessionCloses() throws Exception {
    try (ServerPubSub ignored = attach()) {
      OpcUaClient a = connect(sks);
      OpcUaClient b = connect(sks);
      try {
        // A reserves the entire internal-assignment range
        assertTrue(reserve(a, UDP_UADP, RANGE_SIZE, 0).getStatusCode().isGood());

        // while A's reservation stands, B cannot reserve even one id
        assertEquals(
            StatusCodes.Bad_ResourceUnavailable,
            reserve(b, UDP_UADP, 1, 0).getStatusCode().getValue());

        // dropping A's session releases every id A reserved (§9.1.3.7.5), so B eventually succeeds
        a.disconnect();
        awaitTrue(
            () -> {
              try {
                return reserve(b, UDP_UADP, 1, 0).getStatusCode().isGood();
              } catch (Exception e) {
                return false;
              }
            },
            "B can reserve an id once A's session closes and frees the range");
      } finally {
        try {
          a.disconnect();
        } catch (Exception ignore) {
          // already disconnected above
        }
        b.disconnect();
      }
    }
  }

  @Test
  void reserveIdsRequiresConfigureAuthorization() throws Exception {
    ServerPubSubOptions options =
        ServerPubSubOptions.builder()
            .allowRemoteConfiguration(true)
            .methodAuthorizer(DenyingAuthorizer.INSTANCE)
            .build();
    ServerPubSub serverPubSub =
        ServerPubSub.attach(
            sks.getServer(),
            org.eclipse.milo.opcua.sdk.pubsub.config.PubSubConfig.builder().build(),
            options);
    serverPubSub.startup().get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);
    try {
      OpcUaClient client = connect(sks);
      try {
        // pin R9 / §9.1.3.7.5: an unauthorized caller is Bad_UserAccessDenied
        CallMethodResult result = reserve(client, UDP_UADP, 1, 0);
        assertEquals(StatusCodes.Bad_UserAccessDenied, result.getStatusCode().getValue());
      } finally {
        client.disconnect();
      }
    } finally {
      serverPubSub.close();
    }
  }
}
