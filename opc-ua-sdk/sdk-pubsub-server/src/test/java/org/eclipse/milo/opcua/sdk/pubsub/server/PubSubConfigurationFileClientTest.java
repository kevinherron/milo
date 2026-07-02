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

import static org.eclipse.milo.opcua.sdk.pubsub.server.RemoteConfigClientSupport.CLOSE;
import static org.eclipse.milo.opcua.sdk.pubsub.server.RemoteConfigClientSupport.GET_POSITION;
import static org.eclipse.milo.opcua.sdk.pubsub.server.RemoteConfigClientSupport.OPEN;
import static org.eclipse.milo.opcua.sdk.pubsub.server.RemoteConfigClientSupport.READ;
import static org.eclipse.milo.opcua.sdk.pubsub.server.RemoteConfigClientSupport.SET_POSITION;
import static org.eclipse.milo.opcua.sdk.pubsub.server.RemoteConfigClientSupport.TIMEOUT;
import static org.eclipse.milo.opcua.sdk.pubsub.server.RemoteConfigClientSupport.WRITE;
import static org.eclipse.milo.opcua.sdk.pubsub.server.RemoteConfigClientSupport.awaitTrue;
import static org.eclipse.milo.opcua.sdk.pubsub.server.RemoteConfigClientSupport.call;
import static org.eclipse.milo.opcua.sdk.pubsub.server.RemoteConfigClientSupport.connect;
import static org.eclipse.milo.opcua.sdk.pubsub.server.RemoteConfigClientSupport.open;
import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.ubyte;
import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.uint;
import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.ulong;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.DatagramSocket;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.eclipse.milo.opcua.sdk.client.OpcUaClient;
import org.eclipse.milo.opcua.sdk.pubsub.config.PubSubConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.PubSubConfigFiles;
import org.eclipse.milo.opcua.sdk.pubsub.config.PubSubConnectionConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.UdpDatagramAddress;
import org.eclipse.milo.opcua.sdk.server.OpcUaServer;
import org.eclipse.milo.opcua.stack.core.NodeIds;
import org.eclipse.milo.opcua.stack.core.StatusCodes;
import org.eclipse.milo.opcua.stack.core.encoding.EncodingContext;
import org.eclipse.milo.opcua.stack.core.types.builtin.ByteString;
import org.eclipse.milo.opcua.stack.core.types.builtin.NodeId;
import org.eclipse.milo.opcua.stack.core.types.builtin.Variant;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UInteger;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.ULong;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UShort;
import org.eclipse.milo.opcua.stack.core.types.enumerated.TimestampsToReturn;
import org.eclipse.milo.opcua.stack.core.types.structured.CallMethodResult;
import org.eclipse.milo.opcua.stack.core.types.structured.PubSubConfiguration2DataType;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * The Part 20 §4.2 / Part 14 §9.1.3.7.1 FileType state machine of {@code
 * PublishSubscribe/PubSubConfiguration} ({@code i=25451}), driven end-to-end by a real {@link
 * OpcUaClient} {@code Call} against an embedded {@link OpcUaServer}.
 *
 * <p>{@link FileHandleManagerTest} exercises the same rules as direct unit calls; this class
 * deepens them by running each one through the wire: the server-side access controller, method
 * dispatch, {@link RemoteConfigurationServer} session extraction and authorization, the {@code
 * OpenCount}/{@code Size} node updates, and the {@link org.eclipse.milo.opcua.sdk.server.Session}
 * scoping and {@code SessionListener} eviction that the manager-level unit tests can only simulate
 * with synthetic session ids.
 *
 * <p>Network safety: the fixture binds loopback {@code opc.tcp} endpoints on an ephemeral port and
 * PubSub configurations pin explicit loopback {@code discoveryAddress}es, so no default PubSub
 * multicast group is ever touched.
 */
class PubSubConfigurationFileClientTest {

  private static final int MODE_READ = 0x01;
  private static final int MODE_READ_WRITE = 0x03;
  private static final int MODE_WRITE_ERASE = 0x06;

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

  // region fixtures

  private static ServerPubSub attach(PubSubConfig config) throws Exception {
    ServerPubSubOptions options =
        ServerPubSubOptions.builder().allowRemoteConfiguration(true).build();
    ServerPubSub serverPubSub = ServerPubSub.attach(sks.getServer(), config, options);
    serverPubSub.startup().get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);
    return serverPubSub;
  }

  private static ServerPubSub attach() throws Exception {
    return attach(PubSubConfig.builder().build());
  }

  private static int freeUdpPort() throws Exception {
    try (DatagramSocket socket = new DatagramSocket(0)) {
      return socket.getLocalPort();
    }
  }

  private static Object appPropertyValue(OpcUaClient client, String browsePath) throws Exception {
    UShort appNs = sks.getServer().getServerNamespace().getNamespaceIndex();
    return client
        .readValues(
            0.0,
            TimestampsToReturn.Both,
            List.of(new NodeId(appNs, "PubSub/PubSubConfiguration/" + browsePath)))
        .get(0)
        .getValue()
        .getValue();
  }

  private static Object ns0Value(OpcUaClient client, NodeId nodeId) throws Exception {
    return client
        .readValues(0.0, TimestampsToReturn.Both, List.of(nodeId))
        .get(0)
        .getValue()
        .getValue();
  }

  // endregion

  @Test
  void openAcceptsTheThreeValidModesAndReturnsDistinctHandles() throws Exception {
    try (ServerPubSub ignored = attach()) {
      OpcUaClient client = connect(sks);
      try {
        // each write mode is exclusive, so open and close them one at a time
        UInteger read = open(client, MODE_READ);
        call(client, CLOSE, new Variant(read));

        UInteger readWrite = open(client, MODE_READ_WRITE);
        call(client, CLOSE, new Variant(readWrite));

        UInteger writeErase = open(client, MODE_WRITE_ERASE);
        call(client, CLOSE, new Variant(writeErase));

        // handles are server-generated and unique for the session
        assertNotEquals(read, readWrite);
        assertNotEquals(readWrite, writeErase);
      } finally {
        client.disconnect();
      }
    }
  }

  @Test
  void openRejectsModesOutsideThePart14Set() throws Exception {
    try (ServerPubSub ignored = attach()) {
      OpcUaClient client = connect(sks);
      try {
        // 0x00 (neither), 0x02 (bare Write), 0x04 (bare Erase), 0x05 (Read+Erase),
        // 0x07 (Read+Write+Erase), 0x08 (Append), 0x10 (a reserved bit)
        for (int mode : new int[] {0x00, 0x02, 0x04, 0x05, 0x07, 0x08, 0x10}) {
          CallMethodResult result = call(client, OPEN, new Variant(ubyte(mode)));
          assertEquals(
              StatusCodes.Bad_InvalidArgument,
              result.getStatusCode().getValue(),
              "mode 0x" + Integer.toHexString(mode));
        }
      } finally {
        client.disconnect();
      }
    }
  }

  @Test
  void readReturnsTheOpenSnapshotThenSignalsEndOfFile() throws Exception {
    // a group-less UDP connection is socket-free but distinguishes the read snapshot from empty
    PubSubConfig config =
        PubSubConfig.builder()
            .connection(
                PubSubConnectionConfig.udp("snapshot-conn")
                    .address(UdpDatagramAddress.unicast("127.0.0.1", freeUdpPort()))
                    .discoveryAddress(UdpDatagramAddress.unicast("127.0.0.1", freeUdpPort()))
                    .build())
            .build();

    try (ServerPubSub ignored = attach(config)) {
      OpcUaClient client = connect(sks);
      try {
        EncodingContext ctx = client.getStaticEncodingContext();
        UInteger handle = open(client, MODE_READ);

        CallMethodResult read = call(client, READ, new Variant(handle), new Variant(1024 * 1024));
        assertTrue(read.getStatusCode().isGood(), read.toString());
        ByteString data = (ByteString) read.getOutputArguments()[0].getValue();
        assertTrue(data.length() > 0);

        // the read stream is a valid UABinaryFile whose body round-trips to the live config
        PubSubConfiguration2DataType decoded = PubSubConfigFiles.read(data.bytesOrEmpty(), ctx);
        assertEquals(1, decoded.getConnections().length);
        assertEquals("snapshot-conn", decoded.getConnections()[0].getName());

        // a subsequent read at end of file returns an empty ByteString (Part 20 §4.2.4)
        CallMethodResult eof = call(client, READ, new Variant(handle), new Variant(1024));
        assertTrue(eof.getStatusCode().isGood());
        assertEquals(0, ((ByteString) eof.getOutputArguments()[0].getValue()).length());

        call(client, CLOSE, new Variant(handle));
      } finally {
        client.disconnect();
      }
    }
  }

  @Test
  void readRejectsNonPositiveLength() throws Exception {
    try (ServerPubSub ignored = attach()) {
      OpcUaClient client = connect(sks);
      try {
        UInteger handle = open(client, MODE_READ);
        CallMethodResult result = call(client, READ, new Variant(handle), new Variant(0));
        assertEquals(StatusCodes.Bad_InvalidArgument, result.getStatusCode().getValue());
      } finally {
        client.disconnect();
      }
    }
  }

  @Test
  void readOnAWriteEraseHandleIsInvalidState() throws Exception {
    try (ServerPubSub ignored = attach()) {
      OpcUaClient client = connect(sks);
      try {
        UInteger handle = open(client, MODE_WRITE_ERASE);
        CallMethodResult result = call(client, READ, new Variant(handle), new Variant(16));
        assertEquals(StatusCodes.Bad_InvalidState, result.getStatusCode().getValue());
      } finally {
        client.disconnect();
      }
    }
  }

  @Test
  void getAndSetPositionClampToEndOfFile() throws Exception {
    try (ServerPubSub ignored = attach()) {
      OpcUaClient client = connect(sks);
      try {
        UInteger handle = open(client, MODE_READ);

        // read to end, then confirm the position is the file size
        CallMethodResult read = call(client, READ, new Variant(handle), new Variant(1024 * 1024));
        int size = ((ByteString) read.getOutputArguments()[0].getValue()).length();
        ULong afterRead = getPosition(client, handle);
        assertEquals(ulong(size), afterRead);

        // SetPosition(0) rewinds
        call(client, SET_POSITION, new Variant(handle), new Variant(ulong(0)));
        assertEquals(ulong(0), getPosition(client, handle));

        // SetPosition past the end clamps to the file size rather than erroring (Part 20 §4.2.7)
        call(client, SET_POSITION, new Variant(handle), new Variant(ulong(9_999_999L)));
        assertEquals(ulong(size), getPosition(client, handle));

        call(client, CLOSE, new Variant(handle));
      } finally {
        client.disconnect();
      }
    }
  }

  @Test
  void writeExtendsAndAdvancesThePosition() throws Exception {
    try (ServerPubSub ignored = attach()) {
      OpcUaClient client = connect(sks);
      try {
        UInteger handle = open(client, MODE_WRITE_ERASE);

        CallMethodResult first =
            call(
                client,
                WRITE,
                new Variant(handle),
                new Variant(ByteString.of(new byte[] {1, 2, 3})));
        assertTrue(first.getStatusCode().isGood(), first.toString());
        assertEquals(ulong(3), getPosition(client, handle));

        // an empty write is a Good no-op with no effect on the position (Part 20 §4.2.5)
        CallMethodResult empty =
            call(client, WRITE, new Variant(handle), new Variant(ByteString.NULL_VALUE));
        assertTrue(empty.getStatusCode().isGood());
        assertEquals(ulong(3), getPosition(client, handle));

        CallMethodResult second =
            call(client, WRITE, new Variant(handle), new Variant(ByteString.of(new byte[] {4, 5})));
        assertTrue(second.getStatusCode().isGood());
        assertEquals(ulong(5), getPosition(client, handle));

        call(client, CLOSE, new Variant(handle));
      } finally {
        client.disconnect();
      }
    }
  }

  @Test
  void closeInvalidatesTheHandle() throws Exception {
    try (ServerPubSub ignored = attach()) {
      OpcUaClient client = connect(sks);
      try {
        UInteger handle = open(client, MODE_READ);
        CallMethodResult close = call(client, CLOSE, new Variant(handle));
        assertTrue(close.getStatusCode().isGood());

        // the handle is no longer valid
        CallMethodResult read = call(client, READ, new Variant(handle), new Variant(16));
        assertEquals(StatusCodes.Bad_InvalidArgument, read.getStatusCode().getValue());
      } finally {
        client.disconnect();
      }
    }
  }

  @Test
  void openForWriteIsExclusive() throws Exception {
    try (ServerPubSub ignored = attach()) {
      OpcUaClient client = connect(sks);
      try {
        UInteger writer = open(client, MODE_READ_WRITE);

        // a second write open (even from the same session) requires zero existing handles
        CallMethodResult secondWriter = call(client, OPEN, new Variant(ubyte(MODE_READ_WRITE)));
        assertEquals(StatusCodes.Bad_NotWritable, secondWriter.getStatusCode().getValue());

        // and a read open fails while a writer holds the file
        CallMethodResult reader = call(client, OPEN, new Variant(ubyte(MODE_READ)));
        assertEquals(StatusCodes.Bad_NotReadable, reader.getStatusCode().getValue());

        call(client, CLOSE, new Variant(writer));
      } finally {
        client.disconnect();
      }
    }
  }

  @Test
  void aHandleFromAnotherSessionIsRejected() throws Exception {
    try (ServerPubSub ignored = attach()) {
      OpcUaClient a = connect(sks);
      OpcUaClient b = connect(sks);
      try {
        UInteger handleA = open(a, MODE_READ);

        // (session, handle) identity: session B cannot use session A's handle number
        CallMethodResult foreign = call(b, READ, new Variant(handleA), new Variant(16));
        assertEquals(StatusCodes.Bad_InvalidArgument, foreign.getStatusCode().getValue());

        // still valid for its owner
        assertTrue(call(a, READ, new Variant(handleA), new Variant(16)).getStatusCode().isGood());
        call(a, CLOSE, new Variant(handleA));
      } finally {
        a.disconnect();
        b.disconnect();
      }
    }
  }

  @Test
  void closingTheSessionEvictsHandlesAndReleasesTheWriteLock() throws Exception {
    try (ServerPubSub ignored = attach()) {
      OpcUaClient a = connect(sks);
      OpcUaClient b = connect(sks);
      try {
        // A holds the exclusive write lock
        open(a, MODE_READ_WRITE);
        assertEquals(
            UShort.valueOf(1), ns0Value(b, NodeIds.PublishSubscribe_PubSubConfiguration_OpenCount));

        // dropping A's session must evict its handle and release the write lock
        a.disconnect();
        awaitTrue(
            () -> {
              try {
                return UShort.valueOf(0)
                    .equals(ns0Value(b, NodeIds.PublishSubscribe_PubSubConfiguration_OpenCount));
              } catch (Exception e) {
                return false;
              }
            },
            "OpenCount returns to 0 after A's session closes");

        // B can now take the write lock that A's dropped session released
        UInteger writer = open(b, MODE_READ_WRITE);
        call(b, CLOSE, new Variant(writer));
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
  void openCountNodeReflectsTheNumberOfOpenHandles() throws Exception {
    try (ServerPubSub ignored = attach()) {
      OpcUaClient client = connect(sks);
      try {
        assertEquals(
            UShort.valueOf(0),
            ns0Value(client, NodeIds.PublishSubscribe_PubSubConfiguration_OpenCount));

        UInteger first = open(client, MODE_READ);
        UInteger second = open(client, MODE_READ); // parallel readers are allowed
        assertEquals(
            UShort.valueOf(2),
            ns0Value(client, NodeIds.PublishSubscribe_PubSubConfiguration_OpenCount));

        call(client, CLOSE, new Variant(first));
        call(client, CLOSE, new Variant(second));
        assertEquals(
            UShort.valueOf(0),
            ns0Value(client, NodeIds.PublishSubscribe_PubSubConfiguration_OpenCount));
      } finally {
        client.disconnect();
      }
    }
  }

  @Test
  void theFileTypePropertiesAreAdvertisedToClients() throws Exception {
    try (ServerPubSub ignored = attach()) {
      OpcUaClient client = connect(sks);
      try {
        // Part 5 §12.36: a UABinaryFile FileType shall carry this MimeType
        assertEquals("application/opcua+uabinary", appPropertyValue(client, "MimeType"));

        // the read/write buffer bound the file model advertises (1 MiB default)
        assertEquals(
            uint(FileHandleManager.DEFAULT_MAX_BYTE_STRING_LENGTH),
            appPropertyValue(client, "MaxByteStringLength"));

        // remote configuration is enabled, so the file is writable to any user
        assertEquals(
            Boolean.TRUE, ns0Value(client, NodeIds.PublishSubscribe_PubSubConfiguration_Writable));
        assertEquals(
            Boolean.TRUE,
            ns0Value(client, NodeIds.PublishSubscribe_PubSubConfiguration_UserWritable));
      } finally {
        client.disconnect();
      }
    }
  }

  private static ULong getPosition(OpcUaClient client, UInteger handle) throws Exception {
    CallMethodResult result = call(client, GET_POSITION, new Variant(handle));
    assertTrue(result.getStatusCode().isGood(), result.toString());
    return (ULong) result.getOutputArguments()[0].getValue();
  }
}
