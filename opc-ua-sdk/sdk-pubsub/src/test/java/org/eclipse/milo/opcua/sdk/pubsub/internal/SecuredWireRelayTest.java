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
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import java.net.DatagramSocket;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.stream.Stream;
import org.eclipse.milo.opcua.sdk.pubsub.DataSetReaderRef;
import org.eclipse.milo.opcua.sdk.pubsub.DataSetReceivedEvent;
import org.eclipse.milo.opcua.sdk.pubsub.DataSetSnapshot;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubBindings;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubDiagnostics;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubService;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubServiceConfig;
import org.eclipse.milo.opcua.sdk.pubsub.PublishedDataSetSource;
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
import org.eclipse.milo.opcua.sdk.pubsub.config.UadpDataSetWriterSettings;
import org.eclipse.milo.opcua.sdk.pubsub.config.UadpWriterGroupSettings;
import org.eclipse.milo.opcua.sdk.pubsub.config.UdpConnectionConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.UdpDatagramAddress;
import org.eclipse.milo.opcua.sdk.pubsub.config.WriterGroupConfig;
import org.eclipse.milo.opcua.sdk.pubsub.security.PubSubSecurityPolicy;
import org.eclipse.milo.opcua.sdk.pubsub.security.SecurityKeyProvider;
import org.eclipse.milo.opcua.sdk.pubsub.security.SecurityKeySet;
import org.eclipse.milo.opcua.sdk.pubsub.security.StaticSecurityKeyProvider;
import org.eclipse.milo.opcua.sdk.pubsub.transport.PublisherChannel;
import org.eclipse.milo.opcua.sdk.pubsub.transport.PublisherTransportContext;
import org.eclipse.milo.opcua.sdk.pubsub.transport.SubscriberChannel;
import org.eclipse.milo.opcua.sdk.pubsub.transport.SubscriberTransportContext;
import org.eclipse.milo.opcua.sdk.pubsub.transport.TransportProvider;
import org.eclipse.milo.opcua.stack.core.NodeIds;
import org.eclipse.milo.opcua.stack.core.types.builtin.ByteString;
import org.eclipse.milo.opcua.stack.core.types.builtin.DataValue;
import org.eclipse.milo.opcua.stack.core.types.builtin.Variant;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UInteger;
import org.eclipse.milo.opcua.stack.core.types.enumerated.MessageSecurityMode;
import org.eclipse.milo.opcua.stack.core.types.enumerated.PubSubState;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Milo-to-Milo secured engine tests with the wire in the test's hand: a REAL publisher service
 * emits secured NetworkMessages into a capturing stub transport, and the test relays each captured
 * datagram into a REAL subscriber service's transport consumer — the seam where a network attacker
 * (or lossy network) sits. This pins wire-observable behavior no unit test can:
 *
 * <ul>
 *   <li>Tamper detection through the engine: a datagram tampered between encode and delivery
 *       (payload byte or signature byte) ticks {@code invalidSignatureMessages}, is never
 *       delivered, and does not advance the reader's §7.2.3 sequence window — the authentic
 *       datagram with the same sequence number still delivers.
 *   <li>Token rollover on the wire under a fast-rotating {@link SecurityKeyProvider}: the publisher
 *       switches SecurityTokenId at TimeToNextKey, the MessageNonce sequence-number part resets to
 *       1 per token (Part 14 §7.2.4.4.3.2 Table 156), the subscriber follows via its token window
 *       with zero message loss and zero unknown-token/stale-key drops.
 *   <li>Nonce uniqueness: two writer groups sharing one SecurityGroup never reuse a (tokenId,
 *       MessageNonce) pair — the per-token nonce counter is shared, not per-group.
 * </ul>
 *
 * <p>Publisher frames use NetworkMessage content mask 0x41 (PublisherId | PayloadHeader), so the
 * Table 154 header layout ahead of the SecurityHeader is fixed and the test can parse
 * SecurityFlags, SecurityTokenId, and the MessageNonce straight off the captured bytes.
 */
class SecuredWireRelayTest {

  private static final Duration TIMEOUT = Duration.ofSeconds(10);

  private static final PubSubSecurityPolicy POLICY = PubSubSecurityPolicy.Aes256Ctr;
  private static final SecurityGroupRef SG_REF = new SecurityGroupRef("SG");
  private static final PublisherId PUBLISHER_ID = PublisherId.uint16(ushort(7));

  /** NM content mask 0x41: PublisherId | PayloadHeader. */
  private static final UadpWriterGroupSettings GROUP_SETTINGS =
      UadpWriterGroupSettings.builder()
          .networkMessageContentMask(
              new org.eclipse.milo.opcua.stack.core.types.structured.UadpNetworkMessageContentMask(
                  uint(0x41)))
          .build();

  /** DSM content mask 0x20: SequenceNumber, so delivered events carry the §7.2.3 stream. */
  private static final UadpDataSetWriterSettings WRITER_SETTINGS =
      UadpDataSetWriterSettings.builder()
          .dataSetMessageContentMask(
              new org.eclipse.milo.opcua.stack.core.types.structured.UadpDataSetMessageContentMask(
                  uint(0x20)))
          .build();

  private @Nullable PubSubService publisherService;
  private @Nullable PubSubService subscriberService;
  private @Nullable ExecutorService transportExecutor;

  private StubTransport publisherTransport;
  private StubTransport subscriberTransport;
  private final BlockingQueue<DataSetReceivedEvent> events = new LinkedBlockingQueue<>();

  @AfterEach
  void shutdownServices() throws Exception {
    if (publisherService != null) {
      publisherService.close();
      publisherService = null;
    }
    if (subscriberService != null) {
      subscriberService.close();
      subscriberService = null;
    }
    if (transportExecutor != null) {
      transportExecutor.shutdown();
      assertTrue(transportExecutor.awaitTermination(10, TimeUnit.SECONDS));
      transportExecutor = null;
    }
    events.clear();
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

  /**
   * A time-based rotating provider: like an SKS, it computes the current token from elapsed wall
   * time so publisher and subscriber fetches always agree on the token timeline. Serves {@code
   * HORIZON} consecutive keys from the current token; key material is derived deterministically
   * from the token id.
   */
  private static final class RotatingKeyProvider implements SecurityKeyProvider {

    static final Duration LIFETIME = Duration.ofMillis(750);
    static final int HORIZON = 16;

    private final long startNanos = System.nanoTime();

    @Override
    public CompletableFuture<SecurityKeySet> getKeys(
        String securityGroupId, UInteger startingTokenId, UInteger requestedKeyCount) {

      long elapsed = System.nanoTime() - startNanos;
      long index = elapsed / LIFETIME.toNanos();
      long firstTokenId = 1 + index;
      Duration timeToNextKey =
          Duration.ofNanos(LIFETIME.toNanos() - (elapsed % LIFETIME.toNanos()));

      List<ByteString> keys = new ArrayList<>(HORIZON);
      for (int i = 0; i < HORIZON; i++) {
        keys.add(keyDataForToken(firstTokenId + i));
      }

      return CompletableFuture.completedFuture(
          new SecurityKeySet(POLICY.getUri(), uint(firstTokenId), keys, timeToNextKey, LIFETIME));
    }

    static ByteString keyDataForToken(long tokenId) {
      byte[] keyData = new byte[POLICY.getKeyDataLength()];
      for (int i = 0; i < keyData.length; i++) {
        keyData[i] = (byte) (tokenId * 31 + i);
      }
      return ByteString.of(keyData);
    }
  }

  private static SecurityKeyProvider staticProvider() {
    byte[] keyData = new byte[POLICY.getKeyDataLength()];
    for (int i = 0; i < keyData.length; i++) {
      keyData[i] = (byte) i;
    }
    return StaticSecurityKeyProvider.of(POLICY, ByteString.of(keyData));
  }

  /** Field 0 changes on every read, so every publish cycle emits a data frame. */
  private static PublishedDataSetSource countingSource(AtomicInteger counter) {
    return context ->
        DataSetSnapshot.builder(context)
            .field("counter", new DataValue(Variant.ofInt32(counter.incrementAndGet())))
            .build();
  }

  /**
   * Start a publisher service with one writer group per id in {@code writerGroupIds} (writer id ==
   * group id), all secured with {@code mode} under the shared SecurityGroup "SG".
   */
  private void startPublisher(
      SecurityKeyProvider provider,
      MessageSecurityMode mode,
      PublishedDataSetSource source,
      int... writerGroupIds)
      throws Exception {

    publisherTransport = new StubTransport();

    PublishedDataSetConfig dataSet =
        PublishedDataSetConfig.builder("PDS")
            .field(FieldDefinition.builder("counter").dataType(NodeIds.Int32).build())
            .build();

    UdpConnectionConfig.Builder connection =
        UdpConnectionConfig.builder("pub-conn")
            .publisherId(PUBLISHER_ID)
            .address(UdpDatagramAddress.unicast("127.0.0.1", freeUdpPort()))
            // a connection with writer groups opens real UDP discovery sockets: keep them on
            // loopback, never the 224.0.2.14:4840 default
            .discoveryAddress(UdpDatagramAddress.unicast("127.0.0.1", freeUdpPort()));

    for (int id : writerGroupIds) {
      connection.writerGroup(
          WriterGroupConfig.builder("WG" + id)
              .writerGroupId(ushort(id))
              .publishingInterval(Duration.ofMillis(25))
              .messageSettings(GROUP_SETTINGS)
              .messageSecurity(
                  MessageSecurityConfig.builder().mode(mode).securityGroup(SG_REF).build())
              .dataSetWriter(
                  DataSetWriterConfig.builder("W" + id)
                      .dataSet(new PublishedDataSetRef("PDS"))
                      .dataSetWriterId(ushort(id))
                      .settings(WRITER_SETTINGS)
                      .build())
              .build());
    }

    PubSubConfig config =
        PubSubConfig.builder()
            .publishedDataSet(dataSet)
            .securityGroup(SecurityGroupConfig.builder("SG").build())
            .connection(connection.build())
            .build();

    PubSubBindings bindings =
        PubSubBindings.builder()
            .source(new PublishedDataSetRef("PDS"), source)
            .securityKeys(SG_REF, provider)
            .build();

    PubSubServiceConfig serviceConfig =
        PubSubServiceConfig.builder().transportProvider(publisherTransport).build();

    publisherService = PubSubService.create(config, bindings, serviceConfig);
    publisherService.startup().get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);
  }

  /**
   * Start a subscriber service with one secured reader group "RG" and one reader "R1" filtering on
   * {@code dataSetWriterId}, plus a single-thread transport executor so {@link #relay} is a
   * deterministic dispatch barrier.
   */
  private void startSubscriber(
      SecurityKeyProvider provider, MessageSecurityMode mode, int dataSetWriterId)
      throws Exception {

    subscriberTransport = new StubTransport();
    transportExecutor = Executors.newSingleThreadExecutor();

    UdpConnectionConfig connection =
        UdpConnectionConfig.builder("conn")
            .address(UdpDatagramAddress.unicast("127.0.0.1", freeUdpPort()))
            .readerGroup(
                ReaderGroupConfig.builder("RG")
                    .messageSecurity(
                        MessageSecurityConfig.builder().mode(mode).securityGroup(SG_REF).build())
                    .dataSetReader(
                        DataSetReaderConfig.builder("R1")
                            .publisherId(PUBLISHER_ID)
                            .dataSetWriterId(ushort(dataSetWriterId))
                            .build())
                    .build())
            .build();

    PubSubConfig config =
        PubSubConfig.builder()
            .securityGroup(SecurityGroupConfig.builder("SG").build())
            .connection(connection)
            .build();

    PubSubBindings bindings = PubSubBindings.builder().securityKeys(SG_REF, provider).build();

    PubSubServiceConfig serviceConfig =
        PubSubServiceConfig.builder()
            .transportProvider(subscriberTransport)
            .transportExecutor(transportExecutor)
            .build();

    subscriberService = PubSubService.create(config, bindings, serviceConfig);
    subscriberService.addDataSetListener(new DataSetReaderRef("conn", "RG", "R1"), events::add);
    subscriberService.startup().get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);

    // the secured reader group stays PreOperational until its first key fetch lands; wait for
    // the reader to activate so no relayed frame races the fetch into an unknown-token drop
    var reader = subscriberService.components().dataSetReader("conn", "RG", "R1").orElseThrow();
    long deadline = System.nanoTime() + TIMEOUT.toNanos();
    while (subscriberService.state(reader) != PubSubState.PreOperational) {
      if (System.nanoTime() >= deadline) {
        fail("timed out waiting for the secured reader to activate after the key fetch");
      }
      Thread.sleep(5);
    }
  }

  /** Take the next datagram the publisher handed to its transport channel. */
  private byte[] nextPublished() throws InterruptedException {
    byte[] frame = publisherTransport.sent.poll(TIMEOUT.toSeconds(), TimeUnit.SECONDS);
    assertNotNull(frame, "the publisher did not emit a NetworkMessage within the deadline");
    return frame;
  }

  /** Inject a datagram into the subscriber and barrier-flush its dispatch executor. */
  private void relay(byte[] frame) throws Exception {
    subscriberTransport.inject(frame);
    transportExecutor.submit(() -> {}).get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);
  }

  private long counter(
      String path, java.util.function.ToLongFunction<PubSubDiagnostics.ComponentDiagnostics> get) {
    PubSubDiagnostics.ComponentDiagnostics diagnostics =
        subscriberService.diagnostics().snapshot().get(path);
    return diagnostics != null ? get.applyAsLong(diagnostics) : 0L;
  }

  // endregion

  // region wire parsing (Part 14 §7.2.4.4.2 Table 154, mask 0x41 + SecurityHeader layout)

  /** The SecurityHeader fields of a captured frame plus the Table 156 nonce split. */
  private record WireSecurity(int securityFlags, long tokenId, byte[] nonce, long nonceCounter) {

    String noncePair() {
      return tokenId + ":" + ByteBufUtil.hexDump(nonce);
    }
  }

  /**
   * Parse the SecurityHeader off a captured frame. With content mask 0x41 and a UInt16 PublisherId
   * the layout ahead of it is fixed (Table 154): UADPFlags 0xD1 (version 1, PublisherId,
   * PayloadHeader, ExtendedFlags1), ExtendedFlags1 0x11 (PublisherId type UInt16, SecurityHeader),
   * PublisherId (2), PayloadHeader Count (1) + DataSetWriterIds (2 x count), then SecurityFlags
   * (1), SecurityTokenId (UInt32 LE), NonceLength (1) = 8, MessageNonce (8) = Random (4) ||
   * SequenceNumber (UInt32 LE, reset to 1 per token — Table 156).
   */
  private static WireSecurity parseSecurityHeader(byte[] frame) {
    assertEquals(
        (byte) 0xD1, frame[0], "UADPFlags: version 1 | PublisherId | PayloadHeader | Ext1");
    assertEquals((byte) 0x11, frame[1], "ExtendedFlags1: PublisherId UInt16 | SecurityHeader");

    int count = frame[4] & 0xFF;
    int offset = 5 + 2 * count;

    int securityFlags = frame[offset] & 0xFF;
    long tokenId = readUInt32Le(frame, offset + 1);
    assertEquals(8, frame[offset + 5] & 0xFF, "NonceLength: 8 for AES-CTR (Table 157)");

    byte[] nonce = new byte[8];
    System.arraycopy(frame, offset + 6, nonce, 0, 8);
    long nonceCounter = readUInt32Le(nonce, 4);

    return new WireSecurity(securityFlags, tokenId, nonce, nonceCounter);
  }

  private static long readUInt32Le(byte[] bytes, int offset) {
    return (bytes[offset] & 0xFFL)
        | (bytes[offset + 1] & 0xFFL) << 8
        | (bytes[offset + 2] & 0xFFL) << 16
        | (bytes[offset + 3] & 0xFFL) << 24;
  }

  private static int freeUdpPort() throws Exception {
    try (DatagramSocket socket = new DatagramSocket(0)) {
      return socket.getLocalPort();
    }
  }

  // endregion

  private static Stream<Arguments> tamperTargets() {
    return Stream.of(
        // the last byte of the (encrypted) payload region, just ahead of the signature
        Arguments.of("payload byte", (java.util.function.IntUnaryOperator) length -> length - 33),
        // the last byte of the trailing HMAC-SHA256 signature itself
        Arguments.of("signature byte", (java.util.function.IntUnaryOperator) length -> length - 1));
  }

  /**
   * With a real publisher on the wire: a datagram tampered between encode and delivery is dropped
   * whole with {@code invalidSignatureMessages}, delivers nothing, and does not advance the
   * reader's §7.2.3 sequence window — the AUTHENTIC datagram carrying the same DataSetMessage
   * sequence number is then still new and delivers.
   */
  @ParameterizedTest(name = "{0}")
  @MethodSource("tamperTargets")
  void tamperedDatagramIsRejectedWithoutAdvancingTheWindow(
      String label, java.util.function.IntUnaryOperator tamperOffset) throws Exception {

    SecurityKeyProvider provider = staticProvider();
    startSubscriber(provider, MessageSecurityMode.SignAndEncrypt, 1);
    startPublisher(
        provider, MessageSecurityMode.SignAndEncrypt, countingSource(new AtomicInteger()), 1);

    // one authentic frame delivers and completes reader startup
    relay(nextPublished());
    DataSetReceivedEvent first = events.poll(TIMEOUT.toSeconds(), TimeUnit.SECONDS);
    assertNotNull(first, "the first relayed secured frame must deliver");
    UInteger firstSequence = first.dataSetMessageSequenceNumber();
    assertNotNull(firstSequence);

    // the next frame is tampered in flight: one bit flipped at the target offset
    byte[] authentic = nextPublished();
    byte[] tampered = authentic.clone();
    tampered[tamperOffset.applyAsInt(tampered.length)] ^= 0x01;

    relay(tampered);
    assertEquals(
        1,
        counter("conn/RG", PubSubDiagnostics.ComponentDiagnostics::invalidSignatureMessages),
        "tampered frame must tick invalidSignatureMessages at the reader group");
    assertTrue(events.isEmpty(), "tampered frame must not be delivered");

    // The rejected frame did not advance the window — the authentic frame with the SAME
    // sequence number is new, not stale
    relay(authentic);
    DataSetReceivedEvent redelivered = events.poll(TIMEOUT.toSeconds(), TimeUnit.SECONDS);
    assertNotNull(redelivered, "the authentic same-sequence frame must deliver");
    assertEquals(
        (firstSequence.intValue() + 1) & 0xFFFF,
        redelivered.dataSetMessageSequenceNumber().intValue());

    assertEquals(
        0, counter("conn/RG/R1", PubSubDiagnostics.ComponentDiagnostics::staleSequenceMessages));
    assertEquals(
        0, counter("conn/RG/R1", PubSubDiagnostics.ComponentDiagnostics::invalidSequenceMessages));
    assertEquals(0, counter("conn/RG", PubSubDiagnostics.ComponentDiagnostics::decryptionErrors));
  }

  /**
   * Token rollover on the wire: under a fast-rotating provider the publisher switches
   * SecurityTokenId at TimeToNextKey, resetting the MessageNonce sequence-number part to 1 for the
   * new token (Table 156); every relayed frame is delivered in order across the switch (the
   * subscriber's token window follows), with zero unknown-token, stale-key, or signature drops and
   * no (tokenId, nonce) pair ever repeated.
   */
  @Test
  void tokenRolloverSwitchesTokenAndResetsNonceWithZeroLoss() throws Exception {
    SecurityKeyProvider provider = new RotatingKeyProvider();
    startSubscriber(provider, MessageSecurityMode.SignAndEncrypt, 1);
    startPublisher(
        provider, MessageSecurityMode.SignAndEncrypt, countingSource(new AtomicInteger()), 1);

    // relay frames until the wire shows a token switch plus a few frames under the new token;
    // classification of captured frames, never wall-clock timing
    var observed = new ArrayList<WireSecurity>();
    long firstToken = -1;
    while (true) {
      byte[] frame = nextPublished();
      WireSecurity security = parseSecurityHeader(frame);
      observed.add(security);
      relay(frame);

      if (firstToken < 0) {
        firstToken = security.tokenId();
      }
      if (security.tokenId() > firstToken
          && observed.stream().filter(s -> s.tokenId() > observed.get(0).tokenId()).count() >= 3) {
        break;
      }
      assertTrue(observed.size() < 4_000, "no token switch observed on the wire");
    }

    // the wire changed tokens, monotonically
    Set<Long> tokens = new HashSet<>();
    long previousToken = observed.get(0).tokenId();
    for (WireSecurity security : observed) {
      assertTrue(security.tokenId() >= previousToken, "token ids never move backwards");
      previousToken = security.tokenId();
      tokens.add(security.tokenId());
    }
    assertTrue(tokens.size() >= 2, "at least one token switch observed");

    // nonce discipline (Table 156): (tokenId, nonce) pairs never repeat; within a token the
    // sequence-number part starts at 1 and increases
    Set<String> noncePairs = new HashSet<>();
    Map<Long, Long> lastCounterByToken = new HashMap<>();
    for (WireSecurity security : observed) {
      assertTrue(noncePairs.add(security.noncePair()), "a (tokenId, nonce) pair repeated");

      Long lastCounter = lastCounterByToken.get(security.tokenId());
      if (lastCounter == null) {
        assertEquals(
            1,
            security.nonceCounter(),
            "the nonce sequence number resets to 1 when the token switches");
      } else {
        assertTrue(security.nonceCounter() > lastCounter, "nonce counter increases within a token");
      }
      lastCounterByToken.put(security.tokenId(), security.nonceCounter());
    }

    // zero loss: every relayed frame was delivered, in order, with consecutive §7.2.3 sequence
    // numbers straddling the token switch
    var delivered = new ArrayList<DataSetReceivedEvent>();
    events.drainTo(delivered);
    assertEquals(observed.size(), delivered.size(), "every relayed frame must be delivered");
    for (int i = 1; i < delivered.size(); i++) {
      assertEquals(
          (delivered.get(i - 1).dataSetMessageSequenceNumber().intValue() + 1) & 0xFFFF,
          delivered.get(i).dataSetMessageSequenceNumber().intValue(),
          "delivered sequence numbers are consecutive across the token switch");
    }

    // and none of the pinned drop counters moved
    assertEquals(
        0, counter("conn/RG", PubSubDiagnostics.ComponentDiagnostics::unknownTokenMessages));
    assertEquals(0, counter("conn/RG", PubSubDiagnostics.ComponentDiagnostics::staleKeyMessages));
    assertEquals(
        0, counter("conn/RG", PubSubDiagnostics.ComponentDiagnostics::invalidSignatureMessages));
    assertEquals(0, counter("conn/RG", PubSubDiagnostics.ComponentDiagnostics::decryptionErrors));
    assertEquals(0, counter("conn", PubSubDiagnostics.ComponentDiagnostics::decodeErrors));
    assertEquals(0, counter("conn/RG", PubSubDiagnostics.ComponentDiagnostics::decodeErrors));
    assertEquals(
        0, counter("conn/RG/R1", PubSubDiagnostics.ComponentDiagnostics::staleSequenceMessages));
    assertEquals(
        0,
        counter(
            "conn/RG/R1", PubSubDiagnostics.ComponentDiagnostics::securityModeRejectedMessages));
  }

  /**
   * Nonce uniqueness across writer groups: two writer groups sharing one SecurityGroup draw
   * MessageNonces from ONE per-token counter — across N captured NetworkMessages from both groups,
   * every (tokenId, nonce) pair and every nonce sequence-number value is distinct (nonce uniqueness
   * is per key, not per group; a per-group counter would collide at 1).
   */
  @Test
  void noncesAreUniqueAcrossWriterGroupsSharingOneSecurityGroup() throws Exception {
    startPublisher(
        staticProvider(),
        MessageSecurityMode.SignAndEncrypt,
        countingSource(new AtomicInteger()),
        1,
        2);

    var observed = new ArrayList<WireSecurity>();
    while (observed.size() < 40) {
      observed.add(parseSecurityHeader(nextPublished()));
    }

    Set<String> noncePairs = new HashSet<>();
    Set<Long> counters = new HashSet<>();
    for (WireSecurity security : observed) {
      assertEquals(1, security.tokenId(), "the static provider serves FirstTokenId 1, no rotation");
      assertTrue(noncePairs.add(security.noncePair()), "a (tokenId, nonce) pair repeated");
      assertTrue(
          counters.add(security.nonceCounter()),
          "a nonce sequence number repeated under one key: the per-token counter must be shared"
              + " across writer groups");
    }
  }
}
