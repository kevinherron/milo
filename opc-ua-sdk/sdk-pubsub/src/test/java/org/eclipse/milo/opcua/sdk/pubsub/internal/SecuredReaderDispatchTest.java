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

import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.uint;
import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.ushort;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import java.net.DatagramSocket;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;
import org.eclipse.milo.opcua.sdk.pubsub.DataSetReaderRef;
import org.eclipse.milo.opcua.sdk.pubsub.DataSetReceivedEvent;
import org.eclipse.milo.opcua.sdk.pubsub.DataSetSnapshot;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubBindings;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubDiagnostics;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubHandle;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubService;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubServiceConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.DataSetReaderConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.DataSetWriterConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.FieldDefinition;
import org.eclipse.milo.opcua.sdk.pubsub.config.MessageSecurityConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.PubSubConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.PubSubConnectionConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.PublishedDataSetConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.PublishedDataSetRef;
import org.eclipse.milo.opcua.sdk.pubsub.config.PublisherId;
import org.eclipse.milo.opcua.sdk.pubsub.config.ReaderGroupConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.SecurityGroupConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.SecurityGroupRef;
import org.eclipse.milo.opcua.sdk.pubsub.config.UadpWriterGroupSettings;
import org.eclipse.milo.opcua.sdk.pubsub.config.UdpConnectionConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.UdpDatagramAddress;
import org.eclipse.milo.opcua.sdk.pubsub.config.WriterGroupConfig;
import org.eclipse.milo.opcua.sdk.pubsub.security.MessageSecurityContext;
import org.eclipse.milo.opcua.sdk.pubsub.security.PubSubSecurityPolicy;
import org.eclipse.milo.opcua.sdk.pubsub.security.SecurityKeyMaterial;
import org.eclipse.milo.opcua.sdk.pubsub.security.StaticSecurityKeyProvider;
import org.eclipse.milo.opcua.sdk.pubsub.transport.PublisherChannel;
import org.eclipse.milo.opcua.sdk.pubsub.transport.PublisherTransportContext;
import org.eclipse.milo.opcua.sdk.pubsub.transport.SubscriberChannel;
import org.eclipse.milo.opcua.sdk.pubsub.transport.SubscriberTransportContext;
import org.eclipse.milo.opcua.sdk.pubsub.transport.TransportProvider;
import org.eclipse.milo.opcua.sdk.pubsub.uadp.DataSetMessageDraft;
import org.eclipse.milo.opcua.sdk.pubsub.uadp.DecodeContext;
import org.eclipse.milo.opcua.sdk.pubsub.uadp.DecodedNetworkMessage;
import org.eclipse.milo.opcua.sdk.pubsub.uadp.EncodeContext;
import org.eclipse.milo.opcua.sdk.pubsub.uadp.EncodedNetworkMessage;
import org.eclipse.milo.opcua.sdk.pubsub.uadp.UadpMessageMapping;
import org.eclipse.milo.opcua.stack.core.NodeIds;
import org.eclipse.milo.opcua.stack.core.UaException;
import org.eclipse.milo.opcua.stack.core.encoding.DefaultEncodingContext;
import org.eclipse.milo.opcua.stack.core.types.builtin.ByteString;
import org.eclipse.milo.opcua.stack.core.types.builtin.DataValue;
import org.eclipse.milo.opcua.stack.core.types.builtin.StatusCode;
import org.eclipse.milo.opcua.stack.core.types.builtin.Variant;
import org.eclipse.milo.opcua.stack.core.types.enumerated.MessageSecurityMode;
import org.eclipse.milo.opcua.stack.core.types.enumerated.PubSubState;
import org.eclipse.milo.opcua.stack.core.types.structured.ConfigurationVersionDataType;
import org.eclipse.milo.opcua.stack.core.types.structured.UadpNetworkMessageContentMask;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * Engine-level message security dispatch tests through {@link PubSubService} with a stub transport:
 * the sequence-window regression (a NetworkMessage that fails signature verification — or is
 * rejected by the per-reader mode gate — must not advance any §7.2.3 sequence window), the mode
 * matrix basics (drop below configured counted; None-configured reader drops secured counted;
 * process above configured when keys resolve), the unknown-token counting, and secured publisher
 * emission with the per-cycle {@link MessageSecurityContext}.
 */
class SecuredReaderDispatchTest {

  private static final PubSubSecurityPolicy POLICY = PubSubSecurityPolicy.Aes256Ctr;

  /** The pre-shared key data both sides use (SigningKey || EncryptingKey || KeyNonce). */
  private static final ByteString KEY_DATA = sequentialKeyData();

  private static final byte[] FIXED_NONCE = {1, 2, 3, 4, 5, 0, 0, 0};

  /** NM mask 0x67: PublisherId | GroupHeader | WriterGroupId | SequenceNumber | PayloadHeader. */
  private static final UadpNetworkMessageContentMask NM_MASK =
      new UadpNetworkMessageContentMask(uint(0x67));

  private @Nullable PubSubService service;
  private @Nullable ExecutorService transportExecutor;

  @AfterEach
  void shutdownService() throws Exception {
    if (service != null) {
      service.close();
      service = null;
    }
    if (transportExecutor != null) {
      transportExecutor.shutdown();
      assertTrue(transportExecutor.awaitTermination(10, TimeUnit.SECONDS));
      transportExecutor = null;
    }
  }

  // region fixture

  /** A transport that never touches the network: captures sends, exposes datagram injection. */
  private static final class StubTransport implements TransportProvider {

    final BlockingQueue<byte[]> sent = new LinkedBlockingQueue<>();
    final AtomicReference<Consumer<ByteBuf>> consumer = new AtomicReference<>();

    @Override
    public String transportProfileUri() {
      return "urn:eclipse:milo:test:stub-transport";
    }

    @Override
    public boolean supports(PubSubConnectionConfig connection) {
      return true;
    }

    @Override
    public PublisherChannel openPublisher(PublisherTransportContext context) {
      return new PublisherChannel() {
        @Override
        public CompletableFuture<Void> send(ByteBuf message) {
          try {
            sent.add(ByteBufUtil.getBytes(message));
          } finally {
            message.release();
          }
          return CompletableFuture.completedFuture(null);
        }

        @Override
        public CompletableFuture<Void> closeAsync() {
          return CompletableFuture.completedFuture(null);
        }
      };
    }

    @Override
    public SubscriberChannel openSubscriber(SubscriberTransportContext context) {
      consumer.set(context.messageConsumer());
      return () -> CompletableFuture.completedFuture(null);
    }

    void inject(byte[] datagram) {
      Consumer<ByteBuf> messageConsumer = consumer.get();
      assertNotNull(messageConsumer, "subscriber channel was never opened");
      ByteBuf buffer = Unpooled.wrappedBuffer(datagram);
      try {
        messageConsumer.accept(buffer);
      } finally {
        buffer.release();
      }
    }
  }

  private static void awaitTrue(String description, BooleanSupplier condition)
      throws InterruptedException {
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
    while (System.nanoTime() < deadline) {
      if (condition.getAsBoolean()) {
        return;
      }
      Thread.sleep(5);
    }
    fail("timed out waiting for: " + description);
  }

  private static ByteString sequentialKeyData() {
    byte[] bytes = new byte[PubSubSecurityPolicy.Aes256Ctr.getKeyDataLength()];
    for (int i = 0; i < bytes.length; i++) {
      bytes[i] = (byte) i;
    }
    return ByteString.of(bytes);
  }

  private static SecurityKeyMaterial material() {
    return SecurityKeyMaterial.of(POLICY, KEY_DATA);
  }

  private static int freeUdpPort() throws Exception {
    try (DatagramSocket socket = new DatagramSocket(0)) {
      return socket.getLocalPort();
    }
  }

  private long counter(
      String path, java.util.function.ToLongFunction<PubSubDiagnostics.ComponentDiagnostics> get) {
    PubSubDiagnostics.ComponentDiagnostics diagnostics = service.diagnostics().snapshot().get(path);
    return diagnostics != null ? get.applyAsLong(diagnostics) : -1L;
  }

  // endregion

  // region frame encoding (publisher side of the wire, built directly against the codec)

  /**
   * Encode one NetworkMessage with GroupHeader + NM SequenceNumber, one key-frame DataSetMessage
   * from DataSetWriterId 1 carrying an Int32 value, secured per {@code mode} ({@code null} = the
   * plain unsecured layout).
   */
  private static byte[] encodeFrame(
      int networkMessageSequence,
      int dataSetMessageSequence,
      int value,
      @Nullable MessageSecurityMode mode,
      long securityTokenId)
      throws UaException {

    DataSetWriterConfig writer =
        DataSetWriterConfig.builder("EncodeW")
            .dataSet(new PublishedDataSetRef("EncodePDS"))
            .dataSetWriterId(ushort(1))
            .build();

    WriterGroupConfig group =
        WriterGroupConfig.builder("EncodeWG")
            .writerGroupId(ushort(1))
            .messageSettings(
                UadpWriterGroupSettings.builder().networkMessageContentMask(NM_MASK).build())
            .dataSetWriter(writer)
            .build();

    var draft =
        DataSetMessageDraft.of(
            writer,
            uint(dataSetMessageSequence),
            null,
            null,
            new ConfigurationVersionDataType(uint(0), uint(0)),
            false,
            List.of(new DataValue(Variant.ofInt32(value), StatusCode.GOOD, null)));

    MessageSecurityContext securityContext =
        mode != null
            ? MessageSecurityContext.of(
                mode, POLICY, uint(securityTokenId), material(), () -> FIXED_NONCE.clone())
            : null;

    List<EncodedNetworkMessage> encoded =
        new UadpMessageMapping()
            .encode(
                EncodeContext.of(
                    new DefaultEncodingContext(),
                    PublisherId.uint16(ushort(1)),
                    group,
                    uint(0),
                    ushort(1),
                    ushort(networkMessageSequence),
                    null,
                    List.of(draft),
                    securityContext));

    ByteBuf data = encoded.get(0).data();
    try {
      return ByteBufUtil.getBytes(data);
    } finally {
      data.release();
    }
  }

  /** Flip one payload byte of an encoded secured frame so its signature no longer verifies. */
  private static byte[] tamper(byte[] frame) {
    byte[] tampered = frame.clone();
    tampered[tampered.length - POLICY.getSignatureLength() - 1] ^= 0x01;
    return tampered;
  }

  // endregion

  private StubTransport startSubscriberService() throws Exception {
    var transport = new StubTransport();
    transportExecutor = Executors.newSingleThreadExecutor();

    UdpConnectionConfig connection =
        UdpConnectionConfig.builder("conn")
            .address(UdpDatagramAddress.unicast("127.0.0.1", freeUdpPort()))
            .readerGroup(
                ReaderGroupConfig.builder("RG")
                    .messageSecurity(
                        MessageSecurityConfig.builder()
                            .mode(MessageSecurityMode.Sign)
                            .securityGroup(new SecurityGroupRef("SG"))
                            .build())
                    .dataSetReader(DataSetReaderConfig.builder("R1").build())
                    .build())
            .readerGroup(
                ReaderGroupConfig.builder("RGN")
                    .dataSetReader(DataSetReaderConfig.builder("RN").build())
                    .build())
            .build();

    PubSubConfig config =
        PubSubConfig.builder()
            .securityGroup(SecurityGroupConfig.builder("SG").build())
            .connection(connection)
            .build();

    PubSubBindings bindings =
        PubSubBindings.builder()
            .securityKeys(
                new SecurityGroupRef("SG"), StaticSecurityKeyProvider.of(POLICY, KEY_DATA))
            .build();

    PubSubServiceConfig serviceConfig =
        PubSubServiceConfig.builder()
            .transportProvider(transport)
            .transportExecutor(transportExecutor)
            .build();

    service = PubSubService.create(config, bindings, serviceConfig);
    service.startup().get(10, TimeUnit.SECONDS);

    // the secured reader group stays PreOperational until the (static, immediate) key fetch
    // lands; its readers activate right after
    PubSubHandle r1 = service.components().dataSetReader("conn", "RG", "R1").orElseThrow();
    awaitTrue(
        "secured reader activates after the key fetch",
        () -> service.state(r1) == PubSubState.PreOperational);

    return transport;
  }

  @Test
  void securedDispatchMatrix() throws Exception {
    StubTransport transport = startSubscriberService();

    var securedEvents = new LinkedBlockingQueue<DataSetReceivedEvent>();
    var plainEvents = new LinkedBlockingQueue<DataSetReceivedEvent>();
    service.addDataSetListener(new DataSetReaderRef("conn", "RG", "R1"), securedEvents::add);
    service.addDataSetListener(new DataSetReaderRef("conn", "RGN", "RN"), plainEvents::add);

    // 1. a valid signed key frame is verified, resolved (token 1), and delivered to the Sign
    //    reader; the None reader drops it, counted (no SecurityGroup to supply keys)
    transport.inject(encodeFrame(10, 0, 1, MessageSecurityMode.Sign, 1));
    DataSetReceivedEvent event = securedEvents.poll(10, TimeUnit.SECONDS);
    assertNotNull(event);
    assertEquals(uint(0), event.dataSetMessageSequenceNumber());

    // 2. A tampered frame consuming NM sequence 11 is dropped whole with an
    //    invalid signature and must NOT advance the NetworkMessage window...
    transport.inject(tamper(encodeFrame(11, 1, 99, MessageSecurityMode.Sign, 1)));
    awaitTrue(
        "invalid signature counted at the secured reader group",
        () ->
            counter("conn/RG", PubSubDiagnostics.ComponentDiagnostics::invalidSignatureMessages)
                == 1);

    // ...so the authentic NetworkMessage with the SAME sequence number 11 is NEW, not stale
    transport.inject(encodeFrame(11, 1, 2, MessageSecurityMode.Sign, 1));
    event = securedEvents.poll(10, TimeUnit.SECONDS);
    assertNotNull(event, "verified frame after a tampered one must be delivered");
    assertEquals(uint(1), event.dataSetMessageSequenceNumber());
    assertEquals(Variant.ofInt32(2), event.fields().get(0).value().getValue());

    // 3. SHALL: an unsecured frame at the Sign-configured reader is dropped and counted —
    //    BEFORE the window, so it must not advance it either; the None reader receives it
    transport.inject(encodeFrame(12, 2, 3, null, 0));
    DataSetReceivedEvent plainEvent = plainEvents.poll(10, TimeUnit.SECONDS);
    assertNotNull(plainEvent, "the None-configured reader receives unsecured frames");
    assertEquals(
        1L,
        counter(
            "conn/RG/R1", PubSubDiagnostics.ComponentDiagnostics::securityModeRejectedMessages));
    assertNull(securedEvents.poll(50, TimeUnit.MILLISECONDS));

    // the secured frame with the same NM sequence 12 is still NEW for the Sign reader
    transport.inject(encodeFrame(12, 2, 4, MessageSecurityMode.Sign, 1));
    event = securedEvents.poll(10, TimeUnit.SECONDS);
    assertNotNull(event, "gate-rejected unsecured frame must not advance the window");
    assertEquals(uint(2), event.dataSetMessageSequenceNumber());

    // 4. An unknown SecurityTokenId drops the message and counts at the group; the window
    //    again does not move
    transport.inject(encodeFrame(13, 3, 98, MessageSecurityMode.Sign, 99));
    awaitTrue(
        "unknown token counted at the secured reader group",
        () ->
            counter("conn/RG", PubSubDiagnostics.ComponentDiagnostics::unknownTokenMessages) == 1);

    transport.inject(encodeFrame(13, 3, 5, MessageSecurityMode.Sign, 1));
    event = securedEvents.poll(10, TimeUnit.SECONDS);
    assertNotNull(event, "unresolved-keys drop must not advance the window");
    assertEquals(uint(3), event.dataSetMessageSequenceNumber());

    // 5. MAY: a SignAndEncrypt frame at the Sign-configured reader is processed when its
    //    SecurityGroup supplies the keys
    transport.inject(encodeFrame(14, 4, 6, MessageSecurityMode.SignAndEncrypt, 1));
    event = securedEvents.poll(10, TimeUnit.SECONDS);
    assertNotNull(event, "processing above the configured mode is allowed when keys resolve");
    assertEquals(uint(4), event.dataSetMessageSequenceNumber());
    assertEquals(Variant.ofInt32(6), event.fields().get(0).value().getValue());

    // Counting for the None-configured reader: one tick per secured NetworkMessage it
    // matched — the five decoded secured frames (steps 1-5) plus the unknown-token drop; the
    // tampered frame is not mode-counted (it is the invalid-signature count)
    assertEquals(
        6L,
        counter(
            "conn/RGN/RN", PubSubDiagnostics.ComponentDiagnostics::securityModeRejectedMessages));

    // and nothing secured ever reached the None reader
    assertNull(plainEvents.poll(50, TimeUnit.MILLISECONDS));
  }

  @Test
  void securedWriterGroupPublishesSignedNetworkMessages() throws Exception {
    var transport = new StubTransport();
    transportExecutor = Executors.newSingleThreadExecutor();

    PublishedDataSetConfig dataSet =
        PublishedDataSetConfig.builder("PDS")
            .field(FieldDefinition.builder("F1").dataType(NodeIds.Int32).build())
            .build();

    UdpConnectionConfig connection =
        UdpConnectionConfig.builder("conn")
            .publisherId(PublisherId.uint16(ushort(7)))
            .address(UdpDatagramAddress.unicast("127.0.0.1", freeUdpPort()))
            .discoveryAddress(UdpDatagramAddress.unicast("127.0.0.1", freeUdpPort()))
            .writerGroup(
                WriterGroupConfig.builder("WG")
                    .writerGroupId(ushort(1))
                    .publishingInterval(Duration.ofMillis(50))
                    .messageSecurity(
                        MessageSecurityConfig.builder()
                            .mode(MessageSecurityMode.Sign)
                            .securityGroup(new SecurityGroupRef("SG"))
                            .build())
                    .dataSetWriter(
                        DataSetWriterConfig.builder("W1")
                            .dataSet(dataSet.ref())
                            .dataSetWriterId(ushort(1))
                            .build())
                    .build())
            .build();

    PubSubConfig config =
        PubSubConfig.builder()
            .publishedDataSet(dataSet)
            .securityGroup(SecurityGroupConfig.builder("SG").build())
            .connection(connection)
            .build();

    PubSubBindings bindings =
        PubSubBindings.builder()
            .source(
                dataSet.ref(),
                context ->
                    DataSetSnapshot.builder(context)
                        .field("F1", new DataValue(Variant.ofInt32(42)))
                        .build())
            .securityKeys(
                new SecurityGroupRef("SG"), StaticSecurityKeyProvider.of(POLICY, KEY_DATA))
            .build();

    PubSubServiceConfig serviceConfig =
        PubSubServiceConfig.builder()
            .transportProvider(transport)
            .transportExecutor(transportExecutor)
            .build();

    service = PubSubService.create(config, bindings, serviceConfig);
    service.startup().get(10, TimeUnit.SECONDS);

    // the group stays PreOperational until the first (immediate, static) key fetch, then
    // publishes secured NetworkMessages every cycle
    PubSubHandle group = service.components().writerGroup("conn", "WG").orElseThrow();
    awaitTrue(
        "secured writer group operational after key fetch",
        () -> service.state(group) == PubSubState.Operational);

    byte[] frame = transport.sent.poll(10, TimeUnit.SECONDS);
    assertNotNull(frame);

    SecurityKeyMaterial material = material();
    ByteBuf buffer = Unpooled.wrappedBuffer(frame);
    try {
      DecodedNetworkMessage decoded =
          new UadpMessageMapping()
              .decode(
                  DecodeContext.of(
                      new DefaultEncodingContext(),
                      (publisherId, writerGroupId, dataSetWriterIds, receivedMode, tokenId) ->
                          java.util.Optional.of(material)),
                  buffer);

      assertNull(decoded.failure());
      assertNotNull(decoded.security());
      assertEquals(MessageSecurityMode.Sign, decoded.security().mode());
      // StaticSecurityKeyProvider serves FirstTokenId 1; the static form never rotates
      assertEquals(uint(1), decoded.security().securityTokenId());
      assertEquals(1, decoded.messages().size());
    } finally {
      buffer.release();
    }
  }
}
