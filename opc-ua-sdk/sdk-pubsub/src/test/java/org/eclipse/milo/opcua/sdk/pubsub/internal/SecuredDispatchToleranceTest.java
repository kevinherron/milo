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

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import java.net.DatagramSocket;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.stream.Stream;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.eclipse.milo.opcua.sdk.pubsub.DataSetReaderRef;
import org.eclipse.milo.opcua.sdk.pubsub.DataSetReceivedEvent;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubBindings;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubDiagnostics;
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
import org.eclipse.milo.opcua.stack.core.types.structured.ConfigurationVersionDataType;
import org.eclipse.milo.opcua.stack.core.types.structured.UadpNetworkMessageContentMask;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Secured receive-path tolerance through the full engine dispatch chain ({@code PubSubService} +
 * stub transport): truncated secured NetworkMessages at EVERY cut point are cleanly classified
 * drops (the drop tally always advances — nothing silently swallowed, nothing thrown out of the
 * dispatcher — landing only in the decode/mode-gate taxonomy, never a spurious decrypt/token/stale
 * error), never delivered, and unsecured traffic on a sibling reader group keeps flowing throughout
 * — and a hand-built two-chunk SECURED NetworkMessage (Part 14 §7.2.4.4.4 Tables 158/159, each
 * chunk signed and encrypted individually per K19) reassembles through the connection's {@code
 * ChunkReassembler} into a delivered event.
 *
 * <p>Byte-level truncation tolerance of the codec alone is pinned in UadpDecodeToleranceTest; this
 * class asserts the ENGINE consequences: counter classification (WP-Q Failure.Reason mapping),
 * reader health, and delivery isolation.
 */
class SecuredDispatchToleranceTest {

  private static final PubSubSecurityPolicy POLICY = PubSubSecurityPolicy.Aes256Ctr;

  /**
   * The pre-shared key data both sides use (SigningKey(32) || EncryptingKey(32) || KeyNonce(4)).
   */
  private static final ByteString KEY_DATA = sequentialKeyData();

  private static final byte[] FIXED_NONCE = {9, 8, 7, 6, 5, 0, 0, 0};

  /** NM mask 0x67: PublisherId | GroupHeader | WriterGroupId | SequenceNumber | PayloadHeader. */
  private static final UadpNetworkMessageContentMask NM_MASK =
      new UadpNetworkMessageContentMask(uint(0x67));

  private @Nullable PubSubService service;
  private @Nullable ExecutorService transportExecutor;

  private StubTransport transport;
  private final BlockingQueue<DataSetReceivedEvent> securedEvents = new LinkedBlockingQueue<>();
  private final BlockingQueue<DataSetReceivedEvent> plainEvents = new LinkedBlockingQueue<>();

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
    securedEvents.clear();
    plainEvents.clear();
  }

  // region fixture

  /** A transport that never touches the network: exposes datagram injection. */
  private static final class StubTransport implements TransportProvider {

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
          message.release();
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
   * Start a subscriber-only service: reader group "RG" secured with {@code readerMode} under
   * SecurityGroup "SG", reader "R1" on DataSetWriterId 1, plus an unsecured sibling group "RGN"
   * with reader "RN" on DataSetWriterId 2. The secured reader shares the publisher's mode so its
   * intact frames deliver; the None sibling exercises delivery isolation (and legitimately
   * mode-drops the secured frames it matches at header level, K7).
   */
  private void startService(MessageSecurityMode readerMode) throws Exception {
    transport = new StubTransport();
    transportExecutor = Executors.newSingleThreadExecutor();

    UdpConnectionConfig connection =
        UdpConnectionConfig.builder("conn")
            .address(UdpDatagramAddress.unicast("127.0.0.1", freeUdpPort()))
            .readerGroup(
                ReaderGroupConfig.builder("RG")
                    .messageSecurity(
                        MessageSecurityConfig.builder()
                            .mode(readerMode)
                            .securityGroup(new SecurityGroupRef("SG"))
                            .build())
                    .dataSetReader(
                        DataSetReaderConfig.builder("R1").dataSetWriterId(ushort(1)).build())
                    .build())
            .readerGroup(
                ReaderGroupConfig.builder("RGN")
                    .dataSetReader(
                        DataSetReaderConfig.builder("RN").dataSetWriterId(ushort(2)).build())
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
    service.addDataSetListener(new DataSetReaderRef("conn", "RG", "R1"), securedEvents::add);
    service.addDataSetListener(new DataSetReaderRef("conn", "RGN", "RN"), plainEvents::add);
    service.startup().get(10, TimeUnit.SECONDS);

    // wait for the secured reader group's (static, immediate) key fetch so injected frames
    // never race it into unknown-token drops
    var reader = service.components().dataSetReader("conn", "RG", "R1").orElseThrow();
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
    while (service.state(reader)
        != org.eclipse.milo.opcua.stack.core.types.enumerated.PubSubState.PreOperational) {
      if (System.nanoTime() >= deadline) {
        throw new AssertionError("timed out waiting for the secured reader to activate");
      }
      Thread.sleep(5);
    }
  }

  private void injectAndFlush(byte[] frame) throws Exception {
    transport.inject(frame);
    transportExecutor.submit(() -> {}).get(10, TimeUnit.SECONDS);
  }

  private long counter(
      String path, java.util.function.ToLongFunction<PubSubDiagnostics.ComponentDiagnostics> get) {
    PubSubDiagnostics.ComponentDiagnostics diagnostics = service.diagnostics().snapshot().get(path);
    return diagnostics != null ? get.applyAsLong(diagnostics) : 0L;
  }

  /**
   * The sum of every NetworkMessage-level drop-classification counter a rejected datagram can land
   * in: the WP-Q Failure.Reason taxonomy (decodeErrors / invalidSignature / decrypt / token /
   * stale) fanned out over the paths it may be attributed to. Deliberately excludes the per-reader
   * K7 mode-gate counter ({@code securityModeRejectedMessages}), which {@link #totalDrops} adds.
   */
  private long nmLevelDrops() {
    long sum = 0;
    for (String path : List.of("conn", "conn/RG", "conn/RGN", "conn/RG/R1", "conn/RGN/RN")) {
      sum += counter(path, PubSubDiagnostics.ComponentDiagnostics::decodeErrors);
    }
    for (String path : List.of("conn/RG", "conn/RGN")) {
      sum += counter(path, PubSubDiagnostics.ComponentDiagnostics::invalidSignatureMessages);
      sum += counter(path, PubSubDiagnostics.ComponentDiagnostics::decryptionErrors);
      sum += counter(path, PubSubDiagnostics.ComponentDiagnostics::unknownTokenMessages);
      sum += counter(path, PubSubDiagnostics.ComponentDiagnostics::staleKeyMessages);
    }
    return sum;
  }

  /**
   * Every classified-drop counter across all component paths, INCLUDING the per-reader K7 mode
   * gate. A garbage datagram is legitimately attributed on more than one path: a secured frame no
   * reader can decode is a per-reader mode drop at every matched reader (the SHALL applies to each
   * reader independently), and a tampered-with-signature frame is an invalid-signature drop at
   * every matched reader group — so the meaningful invariant is that this total strictly increases
   * (nothing silently swallowed), not that any single counter moves by exactly one.
   */
  private long totalDrops() {
    long sum = nmLevelDrops();
    for (String path : List.of("conn/RG/R1", "conn/RGN/RN")) {
      sum += counter(path, PubSubDiagnostics.ComponentDiagnostics::securityModeRejectedMessages);
    }
    return sum;
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

  // endregion

  // region frame encoding (publisher side of the wire, built directly against the codec)

  /**
   * Encode one NetworkMessage with GroupHeader + NM SequenceNumber, one key-frame DataSetMessage
   * from {@code dataSetWriterId} carrying an Int32 value, secured per {@code mode} ({@code null} =
   * the plain unsecured layout), token 1 (the StaticSecurityKeyProvider FirstTokenId).
   */
  private static byte[] encodeFrame(
      int dataSetWriterId,
      int networkMessageSequence,
      int dataSetMessageSequence,
      int value,
      @Nullable MessageSecurityMode mode)
      throws UaException {

    DataSetWriterConfig writer =
        DataSetWriterConfig.builder("EncodeW")
            .dataSet(new PublishedDataSetRef("EncodePDS"))
            .dataSetWriterId(ushort(dataSetWriterId))
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
                mode,
                POLICY,
                uint(1),
                SecurityKeyMaterial.of(POLICY, KEY_DATA),
                () -> FIXED_NONCE.clone())
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

  // endregion

  private static Stream<Arguments> truncationModes() {
    return Stream.of(
        Arguments.of("Sign", MessageSecurityMode.Sign),
        Arguments.of("SignAndEncrypt", MessageSecurityMode.SignAndEncrypt));
  }

  /**
   * Truncate a secured NetworkMessage at EVERY byte position: each truncated datagram is a cleanly
   * classified drop (the total classified-drop tally strictly advances — nothing is silently
   * swallowed, nothing throws out of the dispatcher, which would freeze the counters), delivers
   * nothing, and lands only in the decode/mode-gate taxonomy — never a spurious decrypt, token, or
   * stale-key error. Unsecured traffic to the sibling reader group keeps delivering throughout, and
   * the intact secured frame still delivers at the end (the drops did not poison reader state or
   * the §7.2.3 window — K18).
   */
  @ParameterizedTest(name = "{0}")
  @MethodSource("truncationModes")
  void truncatedSecuredFramesAreClassifiedDropsAndTheReaderStaysHealthy(
      String label, MessageSecurityMode mode) throws Exception {

    startService(mode);

    byte[] secured = encodeFrame(1, 10, 0, 42, mode);

    // the plain stream's sequence numbers stay above the truncated copies' parsed NM sequence
    // (10): garbage that decodes a valid header prefix before failing is legitimately observed
    // by the unsecured reader's §7.2.3 window (it shares the stream identity), and the healthy
    // stream must keep moving forward through it
    int plainSequence = 100;
    for (int cut = 1; cut < secured.length; cut++) {
      long dropsBefore = totalDrops();

      injectAndFlush(Arrays.copyOf(secured, cut));

      // a truncated datagram is always classified as a drop somewhere (never silently dropped,
      // never an exception escaping the dispatcher — either would leave the tally frozen); the
      // exact attribution (NM-level taxonomy vs per-reader mode gate, one path or several)
      // depends on how far the truncation parsed and how many readers matched
      assertTrue(
          totalDrops() > dropsBefore,
          "truncation at " + cut + "/" + secured.length + " must be a classified drop");
      assertTrue(securedEvents.isEmpty(), "truncation at " + cut + " must not deliver");

      // no truncation is ever mistaken for a crypto/token failure on resolved material
      assertEquals(0, counter("conn/RG", PubSubDiagnostics.ComponentDiagnostics::decryptionErrors));
      assertEquals(
          0, counter("conn/RG", PubSubDiagnostics.ComponentDiagnostics::unknownTokenMessages));
      assertEquals(0, counter("conn/RG", PubSubDiagnostics.ComponentDiagnostics::staleKeyMessages));

      // unsecured traffic on the sibling reader is unaffected by the garbage stream
      if (cut % 16 == 0) {
        plainSequence++;
        injectAndFlush(encodeFrame(2, plainSequence, plainSequence, plainSequence, null));
        DataSetReceivedEvent plainEvent = plainEvents.poll();
        assertNotNull(plainEvent, "unsecured delivery must keep working at cut " + cut);
        assertEquals(Variant.ofInt32(plainSequence), plainEvent.fields().get(0).value().getValue());
      }
    }

    // some cut long enough to parse the SecurityHeader but too short for the signature was
    // classified Bad_DecodingError (the decode taxonomy the charter names)
    assertTrue(
        counter("conn", PubSubDiagnostics.ComponentDiagnostics::decodeErrors) > 0,
        "early truncations classify as decode errors");

    // the reader is still healthy: an intact frame verifies, decrypts, and delivers. It carries
    // a fresh, higher sequence number (200) so this assertion is independent of window state
    // (unverifiedSecuredFrameMustNotAdvanceTheSequenceWindow pins that even the truncated
    // copies' own sequence number would still deliver — unverified frames never advance the
    // §7.2.3 window, K18)
    long nmDropsBefore = nmLevelDrops();
    injectAndFlush(encodeFrame(1, 200, 50, 42, mode));

    DataSetReceivedEvent event = securedEvents.poll();
    assertNotNull(event, "the intact secured frame must deliver after the truncation storm");
    assertEquals(Variant.ofInt32(42), event.fields().get(0).value().getValue());
    assertEquals(uint(50), event.dataSetMessageSequenceNumber());
    // the intact frame is no NM-level failure (it may still mode-drop at the None sibling RN,
    // which is a per-reader gate tick, not an NM-level classification)
    assertEquals(nmDropsBefore, nmLevelDrops(), "the intact frame is not an NM-level drop");
    assertNull(securedEvents.poll());
  }

  /**
   * K18: an unverified secured NetworkMessage must not advance the reader's Part 14 §7.2.3 sequence
   * window — the window runs only after signature verification, so an unauthenticated datagram
   * cannot poison it.
   *
   * <p>Regression guard: a secured NetworkMessage that is too short to even hold its signature is
   * classified {@code DECODING_ERROR} by the decoder <em>before</em> {@code verify()} runs (after
   * key resolution but ahead of verification). If the dispatcher ran the window on it anyway, an
   * off-path attacker who observes a live tokenId (it rides the plaintext SecurityHeader of every
   * legitimate frame) could craft a truncated datagram with a spoofed high plaintext GroupHeader
   * sequence number and cause every subsequent authentic frame to be dropped as stale — a denial of
   * service on the secured stream without any key knowledge.
   *
   * <p>The truncated (unverified) frame is dropped without touching the window, so the authentic
   * frame carrying the same sequence number still delivers: the decoder marks {@code
   * Security.verified()} only after {@code verify()} passes, and {@code
   * ReaderDispatcher.isSecurityDrop} treats any failure on an unverified secured message as a
   * security drop.
   */
  @Test
  void unverifiedSecuredFrameMustNotAdvanceTheSequenceWindow() throws Exception {
    startService(MessageSecurityMode.SignAndEncrypt);

    // baseline: a clean SignAndEncrypt frame at NM seq 5 completes reader startup
    injectAndFlush(encodeFrame(1, 5, 0, 100, MessageSecurityMode.SignAndEncrypt));
    DataSetReceivedEvent baseline = securedEvents.poll();
    assertNotNull(baseline, "the baseline secured frame must deliver");

    // an unauthenticated frame: a real SignAndEncrypt frame claiming NM seq 10, truncated before
    // its signature so verification never runs (DECODING_ERROR)
    byte[] spoof = encodeFrame(1, 10, 1, 999, MessageSecurityMode.SignAndEncrypt);
    injectAndFlush(Arrays.copyOf(spoof, 50));
    assertTrue(securedEvents.isEmpty(), "the unverified frame delivers nothing");

    // the authentic frame at NM seq 10 must still be new: the unverified frame must not have
    // advanced the window (K18)
    injectAndFlush(encodeFrame(1, 10, 1, 42, MessageSecurityMode.SignAndEncrypt));
    DataSetReceivedEvent authentic = securedEvents.poll();
    assertNotNull(
        authentic,
        "the authentic frame must deliver; the unverified frame must not poison the window");
    assertEquals(Variant.ofInt32(42), authentic.fields().get(0).value().getValue());
    assertEquals(
        0,
        counter("conn/RG/R1", PubSubDiagnostics.ComponentDiagnostics::staleSequenceMessages),
        "the authentic frame must not be classified stale");
  }

  /**
   * K19 end-to-end: a DataSetMessage split into two chunk NetworkMessages (Part 14 §7.2.4.4.4,
   * Tables 158/159), each signed AND encrypted individually with its own MessageNonce, reassembles
   * through the connection's ChunkReassembler and delivers one event through the normal dispatch
   * path — verify/decrypt per chunk first, reassembly after (the K19 ordering).
   */
  @Test
  void securedChunkedNetworkMessageReassemblesThroughTheDispatcher() throws Exception {
    startService(MessageSecurityMode.SignAndEncrypt);

    // the original DataSetMessage being chunked: a key frame with Variant fields Int32 42 and
    // Boolean true (10 bytes), split at offset 6
    byte[] dsmBytes =
        bytes(
            0x01, // DataSetFlags1: valid 0x01 | field encoding 00 (Variant)
            0x02, 0x00, // FieldCount = 2 (UInt16 LE)
            0x06, 0x2A, 0x00, 0x00, 0x00, // field 0: Variant, type Int32 (6), value 42
            0x01, 0x01); // field 1: Variant, type Boolean (1), value true

    // each chunk NetworkMessage carries a UNIQUE MessageNonce: (key, nonce) never repeats
    byte[] nonce1 = bytes(0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x00, 0x00, 0x00);
    byte[] nonce2 = bytes(0xDE, 0xAD, 0xBE, 0xEF, 0x02, 0x00, 0x00, 0x00);

    byte[] chunk1 =
        securedChunkMessage(7, 0, dsmBytes.length, Arrays.copyOfRange(dsmBytes, 0, 6), nonce1);
    byte[] chunk2 =
        securedChunkMessage(
            7, 6, dsmBytes.length, Arrays.copyOfRange(dsmBytes, 6, dsmBytes.length), nonce2);

    // the first chunk yields no messages and no errors: reassembly is in progress. (The
    // None-configured sibling reader RN matches the chunk NetworkMessage at header level and
    // counts its K7 mode drop of the secured frame — the SHALL applies to chunk NMs too.)
    injectAndFlush(chunk1);
    assertTrue(securedEvents.isEmpty());
    assertEquals(0, nmLevelDrops(), "an in-progress chunk is not a drop");
    assertEquals(
        1,
        counter(
            "conn/RGN/RN", PubSubDiagnostics.ComponentDiagnostics::securityModeRejectedMessages),
        "the None-configured reader counts the secured chunk NetworkMessage it matched (K7)");

    // the second chunk completes the message: the reassembled DataSetMessage is dispatched to
    // the secured reader (chunk PayloadHeader DataSetWriterId = 1)
    injectAndFlush(chunk2);

    DataSetReceivedEvent event = securedEvents.poll();
    assertNotNull(event, "the reassembled secured DataSetMessage must be delivered");
    assertEquals(ushort(1), event.dataSetWriterId());
    assertEquals(2, event.fields().size());
    assertEquals(Variant.ofInt32(42), event.fields().get(0).value().getValue());
    assertEquals(Variant.ofBoolean(true), event.fields().get(1).value().getValue());

    assertEquals(0, nmLevelDrops());
    assertEquals(
        0,
        counter("conn/RG/R1", PubSubDiagnostics.ComponentDiagnostics::securityModeRejectedMessages),
        "the SignAndEncrypt reader accepts the mode-matched secured chunks");
    assertNull(securedEvents.poll());
  }

  // region chunk building (Part 14 §7.2.4.4.4 Tables 158/159; K19 per-chunk security)

  private static byte[] bytes(int... values) {
    byte[] bs = new byte[values.length];
    for (int i = 0; i < values.length; i++) {
      bs[i] = (byte) values[i];
    }
    return bs;
  }

  private static byte[] concat(byte[]... arrays) {
    int length = 0;
    for (byte[] array : arrays) {
      length += array.length;
    }
    byte[] result = new byte[length];
    int offset = 0;
    for (byte[] array : arrays) {
      System.arraycopy(array, 0, result, offset, array.length);
      offset += array.length;
    }
    return result;
  }

  /** The Table 159 chunk payload fields. */
  private static byte[] chunkFields(
      int sequenceNumber, int chunkOffset, int totalSize, byte[] data) {
    return concat(
        bytes(
            sequenceNumber & 0xFF,
            (sequenceNumber >>> 8) & 0xFF, // MessageSequenceNumber (UInt16 LE)
            chunkOffset & 0xFF,
            (chunkOffset >>> 8) & 0xFF,
            (chunkOffset >>> 16) & 0xFF,
            (chunkOffset >>> 24) & 0xFF, // ChunkOffset (UInt32 LE)
            totalSize & 0xFF,
            (totalSize >>> 8) & 0xFF,
            (totalSize >>> 16) & 0xFF,
            (totalSize >>> 24) & 0xFF, // TotalSize (UInt32 LE)
            data.length & 0xFF,
            (data.length >>> 8) & 0xFF,
            (data.length >>> 16) & 0xFF,
            (data.length >>> 24) & 0xFF), // ChunkData length (ByteString, Int32 LE)
        data);
  }

  /**
   * One complete SignAndEncrypt chunk NetworkMessage under the test key set (PubSub-Aes256-CTR,
   * SecurityTokenId 1 — the StaticSecurityKeyProvider FirstTokenId): the Table 159 fields are the
   * encrypted payload region; the HMAC-SHA256 signature covers the whole NetworkMessage. The
   * ciphertext and signature are computed with raw javax.crypto, independent of the module's
   * UadpMessageSecurity.
   */
  private static byte[] securedChunkMessage(
      int sequenceNumber, int chunkOffset, int totalSize, byte[] data, byte[] messageNonce)
      throws Exception {

    byte[] keyData = KEY_DATA.bytesOrEmpty();
    // Table 155 key data layout for Aes256Ctr: SigningKey(32) || EncryptingKey(32) || KeyNonce(4)
    byte[] signingKey = Arrays.copyOfRange(keyData, 0, 32);
    byte[] encryptingKey = Arrays.copyOfRange(keyData, 32, 64);
    byte[] keyNonce = Arrays.copyOfRange(keyData, 64, 68);

    byte[] header =
        concat(
            bytes(
                0xD1, // byte 0: version 1 | PublisherId 0x10 | PayloadHeader 0x40 | ExtFlags1 0x80
                0x90, // ExtendedFlags1: SecurityHeader 0x10 | ExtendedFlags2 present 0x80
                0x01, // ExtendedFlags2: chunk 0x01, NM type data (000)
                0x2A, // PublisherId: Byte = 42
                0x01, 0x00, // PayloadHeader (chunk form): DataSetWriterId = 1 (UInt16 LE)
                0x03, // SecurityFlags: signed | encrypted
                0x01, 0x00, 0x00, 0x00, // SecurityTokenId = 1 (UInt32 LE)
                0x08), // NonceLength = 8
            messageNonce);

    byte[] plaintext = chunkFields(sequenceNumber, chunkOffset, totalSize, data);
    byte[] ciphertext = aesCtr(encryptingKey, keyNonce, messageNonce, plaintext);

    byte[] signedRegion = concat(header, ciphertext);

    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(signingKey, "HmacSHA256"));
    byte[] signature = mac.doFinal(signedRegion);

    return concat(signedRegion, signature);
  }

  /**
   * AES-CTR computed directly with javax.crypto: counter block = KeyNonce(4) || MessageNonce(8) ||
   * 00000001 (Part 14 Table 157), block counter big-endian starting at 1.
   */
  private static byte[] aesCtr(byte[] key, byte[] keyNonce, byte[] messageNonce, byte[] data)
      throws Exception {

    byte[] counterBlock = new byte[16];
    System.arraycopy(keyNonce, 0, counterBlock, 0, 4);
    System.arraycopy(messageNonce, 0, counterBlock, 4, 8);
    counterBlock[15] = 0x01;

    Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
    cipher.init(
        Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(counterBlock));
    return cipher.doFinal(data);
  }

  // endregion
}
