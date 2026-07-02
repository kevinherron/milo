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
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;
import org.eclipse.milo.opcua.sdk.pubsub.DataSetReaderRef;
import org.eclipse.milo.opcua.sdk.pubsub.DataSetReceivedEvent;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubBindings;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubHandle;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubService;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubServiceConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.DataSetReaderConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.DataSetWriterConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.MessageSecurityConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.PubSubConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.PubSubConnectionConfig;
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
import org.eclipse.milo.opcua.sdk.pubsub.security.SecurityKeyProvider;
import org.eclipse.milo.opcua.sdk.pubsub.security.StaticSecurityKeyProvider;
import org.eclipse.milo.opcua.sdk.pubsub.transport.PublisherChannel;
import org.eclipse.milo.opcua.sdk.pubsub.transport.PublisherTransportContext;
import org.eclipse.milo.opcua.sdk.pubsub.transport.SubscriberChannel;
import org.eclipse.milo.opcua.sdk.pubsub.transport.SubscriberTransportContext;
import org.eclipse.milo.opcua.sdk.pubsub.transport.TransportProvider;
import org.eclipse.milo.opcua.sdk.pubsub.uadp.DataSetMessageDraft;
import org.eclipse.milo.opcua.sdk.pubsub.uadp.EncodeContext;
import org.eclipse.milo.opcua.sdk.pubsub.uadp.EncodedNetworkMessage;
import org.eclipse.milo.opcua.sdk.pubsub.uadp.UadpMessageMapping;
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
 * A DataSetReader that is disabled at startup and enabled at runtime, whose security override
 * selects a SecurityGroup its (unsecured) group never registered: enabling the reader must register
 * that SecurityGroupRef with the key manager (fetch-at-startup, applied from the reader's activate
 * hook) so its keys are fetched and matching secured traffic decodes — without the registration the
 * ref would never fetch and every message would silently drop as unknown-token forever.
 */
class SecuredReaderLateEnableTest {

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

  @Test
  void enablingAReaderWithASecurityOverrideRegistersItsSecurityGroup() throws Exception {
    var transport = new StubTransport();
    transportExecutor = Executors.newSingleThreadExecutor();

    // the reader is DISABLED at startup, with an override selecting SecurityGroup "SGX" that its
    // unsecured group does not reference: nothing registers SGX at group activation
    UdpConnectionConfig connection =
        UdpConnectionConfig.builder("conn")
            .address(UdpDatagramAddress.unicast("127.0.0.1", freeUdpPort()))
            .readerGroup(
                ReaderGroupConfig.builder("RG")
                    .dataSetReader(
                        DataSetReaderConfig.builder("R1")
                            .enabled(false)
                            .messageSecurity(
                                MessageSecurityConfig.builder()
                                    .mode(MessageSecurityMode.Sign)
                                    .securityGroup(new SecurityGroupRef("SGX"))
                                    .build())
                            .build())
                    .build())
            .build();

    PubSubConfig config =
        PubSubConfig.builder()
            .securityGroup(SecurityGroupConfig.builder("SGX").build())
            .connection(connection)
            .build();

    var fetchCount = new AtomicInteger();
    SecurityKeyProvider staticProvider = StaticSecurityKeyProvider.of(POLICY, KEY_DATA);
    SecurityKeyProvider countingProvider =
        (securityGroupId, startingTokenId, requestedKeyCount) -> {
          fetchCount.incrementAndGet();
          return staticProvider.getKeys(securityGroupId, startingTokenId, requestedKeyCount);
        };

    PubSubBindings bindings =
        PubSubBindings.builder()
            .securityKeys(new SecurityGroupRef("SGX"), countingProvider)
            .build();

    PubSubServiceConfig serviceConfig =
        PubSubServiceConfig.builder()
            .transportProvider(transport)
            .transportExecutor(transportExecutor)
            .build();

    service = PubSubService.create(config, bindings, serviceConfig);
    service.startup().get(10, TimeUnit.SECONDS);

    var events = new LinkedBlockingQueue<DataSetReceivedEvent>();
    service.addDataSetListener(new DataSetReaderRef("conn", "RG", "R1"), events::add);

    PubSubHandle group = service.components().readerGroup("conn", "RG").orElseThrow();
    PubSubHandle reader = service.components().dataSetReader("conn", "RG", "R1").orElseThrow();
    awaitTrue("unsecured group operational", () -> service.state(group) == PubSubState.Operational);
    assertEquals(PubSubState.Disabled, service.state(reader));

    // nothing consumes SGX yet: no fetch, and a matching secured frame delivers nothing
    assertEquals(0, fetchCount.get());
    transport.inject(encodeFrame(1, 1, 41, MessageSecurityMode.Sign, 1));
    assertNull(events.poll(100, TimeUnit.MILLISECONDS));

    // enabling the reader registers its override's SecurityGroupRef and fetches keys
    service.enable(reader);
    awaitTrue("late-enabled reader activates", () -> service.state(reader) != PubSubState.Disabled);
    awaitTrue("override SecurityGroup fetched on reader enable", () -> fetchCount.get() >= 1);

    // secured traffic for the override's SecurityGroup now resolves, verifies, and delivers
    DataSetReceivedEvent event = null;
    int sequence = 2;
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
    while (event == null && System.nanoTime() < deadline) {
      transport.inject(encodeFrame(sequence, sequence, 42, MessageSecurityMode.Sign, 1));
      sequence++;
      event = events.poll(200, TimeUnit.MILLISECONDS);
    }
    assertNotNull(event, "the late-enabled reader must receive secured traffic");
    assertEquals(Variant.ofInt32(42), event.fields().get(0).value().getValue());
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

  private static int freeUdpPort() throws Exception {
    try (DatagramSocket socket = new DatagramSocket(0)) {
      return socket.getLocalPort();
    }
  }

  /**
   * Encode one NetworkMessage with GroupHeader + NM SequenceNumber, one key-frame DataSetMessage
   * from DataSetWriterId 1 carrying an Int32 value, secured per {@code mode}.
   */
  private static byte[] encodeFrame(
      int networkMessageSequence,
      int dataSetMessageSequence,
      int value,
      MessageSecurityMode mode,
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
        MessageSecurityContext.of(
            mode,
            POLICY,
            uint(securityTokenId),
            SecurityKeyMaterial.of(POLICY, KEY_DATA),
            () -> FIXED_NONCE.clone());

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

  // endregion
}
