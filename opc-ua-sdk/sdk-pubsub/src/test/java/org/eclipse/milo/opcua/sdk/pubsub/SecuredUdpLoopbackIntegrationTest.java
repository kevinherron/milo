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

import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.uint;
import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.ushort;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.net.DatagramSocket;
import java.net.SocketException;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;
import java.util.function.Predicate;
import java.util.function.ToLongFunction;
import java.util.stream.Stream;
import org.eclipse.milo.opcua.sdk.pubsub.config.DataSetMetaDataConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.DataSetReaderConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.DataSetWriterConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.FieldDefinition;
import org.eclipse.milo.opcua.sdk.pubsub.config.KeyFieldAddress;
import org.eclipse.milo.opcua.sdk.pubsub.config.MessageSecurityConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.MetadataPolicy;
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
import org.eclipse.milo.opcua.sdk.pubsub.config.UdpDatagramAddress;
import org.eclipse.milo.opcua.sdk.pubsub.config.WriterGroupConfig;
import org.eclipse.milo.opcua.sdk.pubsub.security.PubSubSecurityPolicy;
import org.eclipse.milo.opcua.sdk.pubsub.security.SecurityKeyProvider;
import org.eclipse.milo.opcua.sdk.pubsub.security.StaticSecurityKeyProvider;
import org.eclipse.milo.opcua.stack.core.NodeIds;
import org.eclipse.milo.opcua.stack.core.types.builtin.ByteString;
import org.eclipse.milo.opcua.stack.core.types.builtin.DataValue;
import org.eclipse.milo.opcua.stack.core.types.builtin.Variant;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UShort;
import org.eclipse.milo.opcua.stack.core.types.enumerated.MessageSecurityMode;
import org.eclipse.milo.opcua.stack.core.types.enumerated.PubSubState;
import org.eclipse.milo.opcua.stack.core.types.structured.UadpDataSetMessageContentMask;
import org.eclipse.milo.opcua.stack.core.types.structured.UadpNetworkMessageContentMask;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Milo-to-Milo secured end-to-end integration over unicast loopback UDP with ephemeral ports: a
 * publisher service and a subscriber service, each with a {@link StaticSecurityKeyProvider} bound
 * for the shared SecurityGroup, exchanging signed/encrypted UADP NetworkMessages in-process.
 *
 * <p>Covers the full K2 subset matrix ({@code Aes128Ctr}, {@code Aes256Ctr}) x ({@code Sign},
 * {@code SignAndEncrypt}) with metadata-validated (REQUIRE_CONFIGURED) decode, a multi-writer
 * group, and clean security diagnostics on both sides; secured delta-frame and keep-alive traffic
 * (Part 14 §6.2.4.3 / §6.2.6.3 riding the §7.2.4.4.3.2 secured NetworkMessage form); and the K7
 * receive-mode matrix (Part 14 §7.2.4.3) end-to-end: lower-than-configured is dropped and counted
 * (SHALL), a None-configured reader drops secured messages counted, and higher-than-configured is
 * processed when the reader's group can supply keys (MAY).
 *
 * <p>Network safety: every UDP connection pins an explicit loopback {@code discoveryAddress}, so
 * the engine's discovery channels never bind the well-known port 4840 or join the default {@code
 * 224.0.2.14} multicast group.
 */
class SecuredUdpLoopbackIntegrationTest {

  private static final Duration TIMEOUT = Duration.ofSeconds(10);

  private static final PublisherId PUBLISHER_ID = PublisherId.uint16(ushort(4713));
  private static final UShort GROUP_ID = ushort(1);
  private static final SecurityGroupRef SG_REF = new SecurityGroupRef("SG");

  private static final UUID TEMPERATURE_FIELD_ID = new UUID(0L, 0xA1L);
  private static final UUID STATUS_FIELD_ID = new UUID(0L, 0xA2L);
  private static final UUID COUNTER_FIELD_ID = new UUID(0L, 0xB1L);
  private static final UUID CONSTANT_FIELD_ID = new UUID(0L, 0xB2L);
  private static final UUID VALUE_FIELD_ID = new UUID(0L, 0xC1L);

  private static final DataSetReaderRef READER_A_REF =
      new DataSetReaderRef("sub-conn", "rgrp", "reader-a");
  private static final DataSetReaderRef READER_B_REF =
      new DataSetReaderRef("sub-conn", "rgrp", "reader-b");

  /**
   * Group settings that put the GroupHeader with WriterGroupId and SequenceNumber on the wire so
   * readers can apply their WriterGroupId filter and the §7.2.3 window runs.
   */
  private static final UadpWriterGroupSettings GROUP_SETTINGS =
      UadpWriterGroupSettings.builder()
          .networkMessageContentMask(
              UadpNetworkMessageContentMask.of(
                  UadpNetworkMessageContentMask.Field.PublisherId,
                  UadpNetworkMessageContentMask.Field.GroupHeader,
                  UadpNetworkMessageContentMask.Field.WriterGroupId,
                  UadpNetworkMessageContentMask.Field.SequenceNumber,
                  UadpNetworkMessageContentMask.Field.PayloadHeader))
          .build();

  /**
   * Writer settings that put the full ConfigurationVersion on the wire so the REQUIRE_CONFIGURED
   * version check is genuinely exercised on secured payloads.
   */
  private static final UadpDataSetWriterSettings WRITER_SETTINGS =
      UadpDataSetWriterSettings.builder()
          .dataSetMessageContentMask(
              UadpDataSetMessageContentMask.of(
                  UadpDataSetMessageContentMask.Field.Timestamp,
                  UadpDataSetMessageContentMask.Field.Status,
                  UadpDataSetMessageContentMask.Field.MajorVersion,
                  UadpDataSetMessageContentMask.Field.MinorVersion,
                  UadpDataSetMessageContentMask.Field.SequenceNumber))
          .build();

  private final List<PubSubService> services = new CopyOnWriteArrayList<>();

  @AfterEach
  void tearDown() throws InterruptedException {
    for (PubSubService service : services) {
      try {
        service.shutdown().get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);
      } catch (ExecutionException | TimeoutException e) {
        // best effort cleanup; failures are reported by the tests themselves
      }
    }
    services.clear();
  }

  private static Stream<Arguments> securedMatrix() {
    return Stream.of(
        Arguments.of("Aes128Ctr Sign", PubSubSecurityPolicy.Aes128Ctr, MessageSecurityMode.Sign),
        Arguments.of(
            "Aes128Ctr SignAndEncrypt",
            PubSubSecurityPolicy.Aes128Ctr,
            MessageSecurityMode.SignAndEncrypt),
        Arguments.of("Aes256Ctr Sign", PubSubSecurityPolicy.Aes256Ctr, MessageSecurityMode.Sign),
        Arguments.of(
            "Aes256Ctr SignAndEncrypt",
            PubSubSecurityPolicy.Aes256Ctr,
            MessageSecurityMode.SignAndEncrypt));
  }

  /**
   * The full K2 subset matrix over loopback UDP: both writers of a secured multi-writer group
   * deliver metadata-validated events to their REQUIRE_CONFIGURED readers, a source update travels
   * end-to-end, and every security counter on both sides stays at zero — no decrypt, signature,
   * token, staleness, mode, decode, or sequence-window errors under organic secured traffic.
   */
  @ParameterizedTest(name = "{0}")
  @MethodSource("securedMatrix")
  void securedEndToEndPublishSubscribe(
      String label, PubSubSecurityPolicy policy, MessageSecurityMode mode) throws Exception {

    int port = freeUdpPort();

    var valuesA =
        new AtomicReference<>(
            Map.of(
                "temperature", new DataValue(Variant.ofDouble(21.5)),
                "status", new DataValue(Variant.ofString("running"))));
    var valuesB = new AtomicReference<>(Map.of("counter", new DataValue(Variant.ofInt32(42))));

    PubSubBindings publisherBindings =
        PubSubBindings.builder()
            .source(new PublishedDataSetRef("ds-a"), mapSource(valuesA))
            .source(new PublishedDataSetRef("ds-b"), mapSource(valuesB))
            .securityKeys(SG_REF, staticProvider(policy))
            .build();

    PubSubService publisher =
        track(PubSubService.create(publisherConfig(port, mode), publisherBindings));

    var eventsA = new LinkedBlockingQueue<DataSetReceivedEvent>();
    var eventsB = new LinkedBlockingQueue<DataSetReceivedEvent>();

    PubSubBindings subscriberBindings =
        PubSubBindings.builder()
            .listener(READER_A_REF, eventsA::add)
            .listener(READER_B_REF, eventsB::add)
            .securityKeys(SG_REF, staticProvider(policy))
            .build();

    PubSubService subscriber =
        track(PubSubService.create(subscriberConfig(port, mode), subscriberBindings));

    subscriber.startup().get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);
    // the secured reader group stays PreOperational until its key fetch lands; wait for the
    // readers to activate so no early frame races the fetch into an unknown-token drop
    awaitReaderActivated(subscriber, "sub-conn", "rgrp", "reader-a");
    awaitReaderActivated(subscriber, "sub-conn", "rgrp", "reader-b");
    publisher.startup().get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);

    // both writers' secured DataSetMessages decode with metadata validation
    DataSetReceivedEvent eventA = awaitEvent(eventsA, event -> true);
    assertEquals(PUBLISHER_ID, eventA.publisherId());
    assertEquals(GROUP_ID, eventA.writerGroupId());
    assertEquals(ushort(1), eventA.dataSetWriterId());
    assertNotNull(eventA.metaData());
    assertEquals(uint(7), eventA.metaData().getConfigurationVersionMajor());
    assertEquals(uint(3), eventA.metaData().getConfigurationVersionMinor());
    assertEquals(21.5, eventA.fieldsByName().get("temperature").value().value());
    assertEquals("running", eventA.fieldsByName().get("status").value().value());

    DataSetReceivedEvent eventB = awaitEvent(eventsB, event -> true);
    assertEquals(ushort(2), eventB.dataSetWriterId());
    assertEquals(42, eventB.fieldsByName().get("counter").value().value());

    // a live value change travels through the secured pipeline
    valuesB.set(Map.of("counter", new DataValue(Variant.ofInt32(43))));
    awaitEvent(
        eventsB,
        event -> Integer.valueOf(43).equals(event.fieldsByName().get("counter").value().value()));

    // both readers completed startup on secured frames
    PubSubHandle readerA =
        subscriber.components().dataSetReader("sub-conn", "rgrp", "reader-a").orElseThrow();
    PubSubHandle readerB =
        subscriber.components().dataSetReader("sub-conn", "rgrp", "reader-b").orElseThrow();
    assertEquals(PubSubState.Operational, subscriber.state(readerA));
    assertEquals(PubSubState.Operational, subscriber.state(readerB));

    // publisher-side counters: traffic flowed, zero encryption errors
    awaitTrue(
        () ->
            counter(
                    publisher,
                    "pub-conn/grp",
                    PubSubDiagnostics.ComponentDiagnostics::networkMessagesSent)
                > 0,
        "publisher writer group networkMessagesSent > 0");
    assertEquals(
        0,
        counter(
            publisher, "pub-conn/grp", PubSubDiagnostics.ComponentDiagnostics::encryptionErrors));

    // subscriber-side counters: everything verified/decrypted cleanly
    assertTrue(
        counter(
                subscriber,
                "sub-conn",
                PubSubDiagnostics.ComponentDiagnostics::networkMessagesReceived)
            > 0);
    for (String path : List.of("sub-conn", "sub-conn/rgrp")) {
      assertEquals(
          0, counter(subscriber, path, PubSubDiagnostics.ComponentDiagnostics::decodeErrors), path);
      assertEquals(
          0,
          counter(subscriber, path, PubSubDiagnostics.ComponentDiagnostics::decryptionErrors),
          path);
      assertEquals(
          0,
          counter(
              subscriber, path, PubSubDiagnostics.ComponentDiagnostics::invalidSignatureMessages),
          path);
      assertEquals(
          0,
          counter(subscriber, path, PubSubDiagnostics.ComponentDiagnostics::unknownTokenMessages),
          path);
      assertEquals(
          0,
          counter(subscriber, path, PubSubDiagnostics.ComponentDiagnostics::staleKeyMessages),
          path);
    }
    for (String readerPath : List.of("sub-conn/rgrp/reader-a", "sub-conn/rgrp/reader-b")) {
      assertEquals(
          0,
          counter(
              subscriber,
              readerPath,
              PubSubDiagnostics.ComponentDiagnostics::securityModeRejectedMessages),
          readerPath);
      assertEquals(
          0,
          counter(
              subscriber,
              readerPath,
              PubSubDiagnostics.ComponentDiagnostics::staleSequenceMessages),
          readerPath);
      assertEquals(
          0,
          counter(
              subscriber,
              readerPath,
              PubSubDiagnostics.ComponentDiagnostics::invalidSequenceMessages),
          readerPath);
    }
  }

  /**
   * Build the secured delta/keep-alive publisher config: one SignAndEncrypt writer group at 75 ms
   * carrying a two-field (counter, constant) dataset with the given {@code keyFrameCount} and an
   * optional {@code keepAliveTime}.
   */
  private PubSubConfig deltaPublisherConfig(
      int port, PublishedDataSetConfig dataSet, int keyFrameCount, @Nullable Duration keepAliveTime)
      throws SocketException {

    WriterGroupConfig.Builder group =
        WriterGroupConfig.builder("grp")
            .writerGroupId(GROUP_ID)
            .publishingInterval(Duration.ofMillis(75))
            .messageSettings(GROUP_SETTINGS)
            .messageSecurity(
                MessageSecurityConfig.builder()
                    .mode(MessageSecurityMode.SignAndEncrypt)
                    .securityGroup(SG_REF)
                    .build())
            .dataSetWriter(
                DataSetWriterConfig.builder("writer")
                    .dataSet(dataSet.ref())
                    .dataSetWriterId(ushort(1))
                    .keyFrameCount(uint(keyFrameCount))
                    .settings(WRITER_SETTINGS)
                    .build());
    if (keepAliveTime != null) {
      group.keepAliveTime(keepAliveTime);
    }

    return PubSubConfig.builder()
        .publishedDataSet(dataSet)
        .securityGroup(SecurityGroupConfig.builder("SG").build())
        .connection(
            PubSubConnectionConfig.udp("pub-conn")
                .publisherId(PUBLISHER_ID)
                .address(UdpDatagramAddress.unicast("127.0.0.1", port))
                .discoveryAddress(UdpDatagramAddress.unicast("127.0.0.1", freeUdpPort()))
                .writerGroup(group.build())
                .build())
        .build();
  }

  /** The matching SignAndEncrypt subscriber config for {@link #deltaPublisherConfig}. */
  private PubSubConfig deltaSubscriberConfig(int port, DataSetMetaDataConfig metaData)
      throws SocketException {

    return PubSubConfig.builder()
        .securityGroup(SecurityGroupConfig.builder("SG").build())
        .connection(
            PubSubConnectionConfig.udp("sub-conn")
                .address(UdpDatagramAddress.unicast("127.0.0.1", port))
                .discoveryAddress(UdpDatagramAddress.unicast("127.0.0.1", freeUdpPort()))
                .readerGroup(
                    ReaderGroupConfig.builder("rgrp")
                        .messageSecurity(
                            MessageSecurityConfig.builder()
                                .mode(MessageSecurityMode.SignAndEncrypt)
                                .securityGroup(SG_REF)
                                .build())
                        .dataSetReader(
                            DataSetReaderConfig.builder("reader")
                                .publisherId(PUBLISHER_ID)
                                .writerGroupId(GROUP_ID)
                                .dataSetWriterId(ushort(1))
                                .dataSetMetaData(metaData)
                                .metadataPolicy(MetadataPolicy.REQUIRE_CONFIGURED)
                                .build())
                        .build())
                .build())
        .build();
  }

  private static PublishedDataSetConfig deltaDataSet() {
    return PublishedDataSetConfig.builder("ds-delta")
        .field(
            FieldDefinition.builder("counter")
                .dataType(NodeIds.Int32)
                .dataSetFieldId(COUNTER_FIELD_ID)
                .build())
        .field(
            FieldDefinition.builder("constant")
                .dataType(NodeIds.Int32)
                .dataSetFieldId(CONSTANT_FIELD_ID)
                .build())
        .configurationVersion(uint(1), uint(1))
        .build();
  }

  private static DataSetMetaDataConfig deltaMetaData() {
    return DataSetMetaDataConfig.builder("ds-delta")
        .field("counter", NodeIds.Int32, COUNTER_FIELD_ID)
        .field("constant", NodeIds.Int32, CONSTANT_FIELD_ID)
        .configurationVersion(uint(1), uint(1))
        .build();
  }

  /**
   * Secured delta frames end-to-end (Part 14 §6.2.4.3 delta cadence riding the §7.2.4.4.3.2 secured
   * NetworkMessage form): with {@code keyFrameCount} 3, driving a single-field change produces a
   * delta event carrying only the changed field; two more changes complete the K, D, D, K cadence
   * through the secured pipeline, all with clean security counters.
   */
  @Test
  void securedDeltaFramesFlowEndToEnd() throws Exception {
    PubSubSecurityPolicy policy = PubSubSecurityPolicy.Aes256Ctr;
    int port = freeUdpPort();
    PublishedDataSetConfig dataSet = deltaDataSet();

    var values =
        new AtomicReference<>(
            Map.of(
                "counter", new DataValue(Variant.ofInt32(1)),
                "constant", new DataValue(Variant.ofInt32(100))));

    PubSubService publisher =
        track(
            PubSubService.create(
                deltaPublisherConfig(port, dataSet, 3, null),
                PubSubBindings.builder()
                    .source(dataSet.ref(), mapSource(values))
                    .securityKeys(SG_REF, staticProvider(policy))
                    .build()));

    var events = new LinkedBlockingQueue<DataSetReceivedEvent>();

    PubSubService subscriber =
        track(
            PubSubService.create(
                deltaSubscriberConfig(port, deltaMetaData()),
                PubSubBindings.builder()
                    .listener(new DataSetReaderRef("sub-conn", "rgrp", "reader"), events::add)
                    .securityKeys(SG_REF, staticProvider(policy))
                    .build()));

    subscriber.startup().get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);
    awaitReaderActivated(subscriber, "sub-conn", "rgrp", "reader");
    publisher.startup().get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);

    // the initial key frame carries all fields
    DataSetReceivedEvent keyEvent = awaitEvent(events, event -> true);
    assertEquals(2, keyEvent.fields().size(), "key frame carries all fields");

    // one changed field => the next data frame is a secured delta carrying ONLY that field
    values.set(
        Map.of(
            "counter", new DataValue(Variant.ofInt32(2)),
            "constant", new DataValue(Variant.ofInt32(100))));
    DataSetReceivedEvent deltaEvent =
        awaitEvent(
            events,
            event ->
                Integer.valueOf(2).equals(event.fieldsByName().get("counter").value().value()));
    assertEquals(1, deltaEvent.fields().size(), "delta frame carries only the changed field");
    assertEquals("counter", deltaEvent.fields().get(0).name());

    // second change: still inside the keyFrameCount=3 cadence => another delta
    values.set(
        Map.of(
            "counter", new DataValue(Variant.ofInt32(3)),
            "constant", new DataValue(Variant.ofInt32(100))));
    DataSetReceivedEvent secondDelta =
        awaitEvent(
            events,
            event ->
                Integer.valueOf(3).equals(event.fieldsByName().get("counter").value().value()));
    assertEquals(1, secondDelta.fields().size());

    // the secured delta pipeline produced no crypto/decode errors
    assertEquals(
        0,
        counter(
            subscriber, "sub-conn/rgrp", PubSubDiagnostics.ComponentDiagnostics::decryptionErrors));
    assertEquals(
        0,
        counter(
            subscriber,
            "sub-conn/rgrp",
            PubSubDiagnostics.ComponentDiagnostics::invalidSignatureMessages));
    assertEquals(
        0, counter(subscriber, "sub-conn", PubSubDiagnostics.ComponentDiagnostics::decodeErrors));

    PubSubHandle reader =
        subscriber.components().dataSetReader("sub-conn", "rgrp", "reader").orElseThrow();
    assertEquals(PubSubState.Operational, subscriber.state(reader));
  }

  /**
   * Secured keep-alives end-to-end (Part 14 §6.2.6.3 keep-alive riding the §7.2.4.4.3.2 secured
   * NetworkMessage form): a large {@code keyFrameCount} (no periodic key frame is due within the
   * window) plus a constant source means that after the initial key frame the ONLY traffic on the
   * wire is secured keep-alives — the subscriber keeps receiving and verifying NetworkMessages
   * (received counter climbs) while delivering no further data events, and every security counter
   * stays clean (a keep-alive that failed verification would tick the group; an unsecured one would
   * tick the reader mode gate).
   */
  @Test
  void securedKeepAliveFramesFlowEndToEnd() throws Exception {
    PubSubSecurityPolicy policy = PubSubSecurityPolicy.Aes256Ctr;
    int port = freeUdpPort();
    PublishedDataSetConfig dataSet = deltaDataSet();

    // constant source: nothing ever changes, so after the first key frame the writer emits only
    // keep-alives (keyFrameCount 1000 => no periodic key frame is due within the test window)
    var values =
        new AtomicReference<>(
            Map.of(
                "counter", new DataValue(Variant.ofInt32(7)),
                "constant", new DataValue(Variant.ofInt32(100))));

    PubSubService publisher =
        track(
            PubSubService.create(
                deltaPublisherConfig(port, dataSet, 1000, Duration.ofMillis(150)),
                PubSubBindings.builder()
                    .source(dataSet.ref(), mapSource(values))
                    .securityKeys(SG_REF, staticProvider(policy))
                    .build()));

    var events = new LinkedBlockingQueue<DataSetReceivedEvent>();

    PubSubService subscriber =
        track(
            PubSubService.create(
                deltaSubscriberConfig(port, deltaMetaData()),
                PubSubBindings.builder()
                    .listener(new DataSetReaderRef("sub-conn", "rgrp", "reader"), events::add)
                    .securityKeys(SG_REF, staticProvider(policy))
                    .build()));

    subscriber.startup().get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);
    awaitReaderActivated(subscriber, "sub-conn", "rgrp", "reader");
    publisher.startup().get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);

    // exactly one data event: the initial key frame; drain it and any in-flight duplicate
    DataSetReceivedEvent keyEvent = awaitEvent(events, event -> true);
    assertEquals(2, keyEvent.fields().size(), "the initial secured key frame carries all fields");
    while (events.poll() != null) {
      // drain any straggler in-flight delivery before the quiet window
    }

    // secured keep-alives now carry the wire: the received-NM counter keeps climbing...
    long received =
        counter(
            subscriber,
            "sub-conn",
            PubSubDiagnostics.ComponentDiagnostics::networkMessagesReceived);
    awaitTrue(
        () ->
            counter(
                    subscriber,
                    "sub-conn",
                    PubSubDiagnostics.ComponentDiagnostics::networkMessagesReceived)
                >= received + 3,
        "secured keep-alive NetworkMessages keep arriving and verifying");

    // ...while no further data events are delivered (keep-alives carry no data)
    assertNull(
        events.poll(200, TimeUnit.MILLISECONDS), "secured keep-alives deliver no data events");

    // every keep-alive verified and decrypted: a bad signature/decrypt would tick the group, an
    // unsecured NetworkMessage would tick the reader mode gate
    assertEquals(
        0,
        counter(
            subscriber,
            "sub-conn/rgrp",
            PubSubDiagnostics.ComponentDiagnostics::invalidSignatureMessages));
    assertEquals(
        0,
        counter(
            subscriber, "sub-conn/rgrp", PubSubDiagnostics.ComponentDiagnostics::decryptionErrors));
    assertEquals(
        0,
        counter(
            subscriber,
            "sub-conn/rgrp/reader",
            PubSubDiagnostics.ComponentDiagnostics::securityModeRejectedMessages));
    assertEquals(
        0, counter(subscriber, "sub-conn", PubSubDiagnostics.ComponentDiagnostics::decodeErrors));
    assertEquals(
        0,
        counter(subscriber, "sub-conn/rgrp", PubSubDiagnostics.ComponentDiagnostics::decodeErrors));

    PubSubHandle reader =
        subscriber.components().dataSetReader("sub-conn", "rgrp", "reader").orElseThrow();
    assertEquals(PubSubState.Operational, subscriber.state(reader));
  }

  /**
   * The K7 receive-mode matrix (Part 14 §7.2.4.3) end-to-end against a REAL secured publisher: a
   * Sign writer group and a SignAndEncrypt writer group publish to one subscriber hosting three
   * differently configured readers. The None-configured reader drops the secured messages it
   * matches, counted, and stays healthy (SHALL); the SignAndEncrypt-configured reader matching the
   * Sign group drops lower-than-configured, counted (SHALL); the Sign-configured reader matching
   * the SignAndEncrypt group processes higher-than-configured because its SecurityGroup supplies
   * the keys (MAY) and receives the data.
   */
  @Test
  void receiveModeMismatchMatrixEndToEnd() throws Exception {
    PubSubSecurityPolicy policy = PubSubSecurityPolicy.Aes256Ctr;
    int port = freeUdpPort();

    PublishedDataSetConfig dataSet =
        PublishedDataSetConfig.builder("ds-mm")
            .field(
                FieldDefinition.builder("value")
                    .dataType(NodeIds.Int32)
                    .dataSetFieldId(VALUE_FIELD_ID)
                    .build())
            .configurationVersion(uint(1), uint(1))
            .build();

    PubSubConfig publisherConfig =
        PubSubConfig.builder()
            .publishedDataSet(dataSet)
            .securityGroup(SecurityGroupConfig.builder("SG").build())
            .connection(
                PubSubConnectionConfig.udp("pub-conn")
                    .publisherId(PUBLISHER_ID)
                    .address(UdpDatagramAddress.unicast("127.0.0.1", port))
                    .discoveryAddress(UdpDatagramAddress.unicast("127.0.0.1", freeUdpPort()))
                    .writerGroup(
                        secureWriterGroup(
                            "grp-sign", ushort(1), ushort(1), MessageSecurityMode.Sign, dataSet))
                    .writerGroup(
                        secureWriterGroup(
                            "grp-encrypt",
                            ushort(2),
                            ushort(2),
                            MessageSecurityMode.SignAndEncrypt,
                            dataSet))
                    .build())
            .build();

    DataSetMetaDataConfig metaData =
        DataSetMetaDataConfig.builder("ds-mm")
            .field("value", NodeIds.Int32, VALUE_FIELD_ID)
            .configurationVersion(uint(1), uint(1))
            .build();

    // reader-none: no security, matches the Sign group => drop + count, stays healthy
    // reader-encrypt: SignAndEncrypt configured, matches the Sign group => drop lower + count
    // reader-sign: Sign configured, matches the SignAndEncrypt group => process higher (MAY)
    PubSubConfig subscriberConfig =
        PubSubConfig.builder()
            .securityGroup(SecurityGroupConfig.builder("SG").build())
            .connection(
                PubSubConnectionConfig.udp("sub-conn")
                    .address(UdpDatagramAddress.unicast("127.0.0.1", port))
                    .discoveryAddress(UdpDatagramAddress.unicast("127.0.0.1", freeUdpPort()))
                    .readerGroup(
                        ReaderGroupConfig.builder("rg-none")
                            .dataSetReader(reader("reader-none", ushort(1), ushort(1), metaData))
                            .build())
                    .readerGroup(
                        ReaderGroupConfig.builder("rg-encrypt")
                            .messageSecurity(
                                MessageSecurityConfig.builder()
                                    .mode(MessageSecurityMode.SignAndEncrypt)
                                    .securityGroup(SG_REF)
                                    .build())
                            .dataSetReader(reader("reader-encrypt", ushort(1), ushort(1), metaData))
                            .build())
                    .readerGroup(
                        ReaderGroupConfig.builder("rg-sign")
                            .messageSecurity(
                                MessageSecurityConfig.builder()
                                    .mode(MessageSecurityMode.Sign)
                                    .securityGroup(SG_REF)
                                    .build())
                            .dataSetReader(reader("reader-sign", ushort(2), ushort(2), metaData))
                            .build())
                    .build())
            .build();

    var values = new AtomicReference<>(Map.of("value", new DataValue(Variant.ofInt32(7))));

    PubSubService publisher =
        track(
            PubSubService.create(
                publisherConfig,
                PubSubBindings.builder()
                    .source(dataSet.ref(), mapSource(values))
                    .securityKeys(SG_REF, staticProvider(policy))
                    .build()));

    var noneEvents = new LinkedBlockingQueue<DataSetReceivedEvent>();
    var encryptEvents = new LinkedBlockingQueue<DataSetReceivedEvent>();
    var signEvents = new LinkedBlockingQueue<DataSetReceivedEvent>();

    PubSubService subscriber =
        track(
            PubSubService.create(
                subscriberConfig,
                PubSubBindings.builder()
                    .listener(
                        new DataSetReaderRef("sub-conn", "rg-none", "reader-none"), noneEvents::add)
                    .listener(
                        new DataSetReaderRef("sub-conn", "rg-encrypt", "reader-encrypt"),
                        encryptEvents::add)
                    .listener(
                        new DataSetReaderRef("sub-conn", "rg-sign", "reader-sign"), signEvents::add)
                    .securityKeys(SG_REF, staticProvider(policy))
                    .build()));

    subscriber.startup().get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);
    awaitReaderActivated(subscriber, "sub-conn", "rg-none", "reader-none");
    awaitReaderActivated(subscriber, "sub-conn", "rg-encrypt", "reader-encrypt");
    awaitReaderActivated(subscriber, "sub-conn", "rg-sign", "reader-sign");
    publisher.startup().get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);

    // MAY row: the Sign-configured reader processes the SignAndEncrypt group's messages
    DataSetReceivedEvent signEvent = awaitEvent(signEvents, event -> true);
    assertEquals(ushort(2), signEvent.writerGroupId());
    assertEquals(7, signEvent.fieldsByName().get("value").value().value());

    // SHALL rows: both mismatched readers count their drops...
    awaitTrue(
        () ->
            counter(
                    subscriber,
                    "sub-conn/rg-none/reader-none",
                    PubSubDiagnostics.ComponentDiagnostics::securityModeRejectedMessages)
                > 0,
        "None-configured reader counts secured drops");
    awaitTrue(
        () ->
            counter(
                    subscriber,
                    "sub-conn/rg-encrypt/reader-encrypt",
                    PubSubDiagnostics.ComponentDiagnostics::securityModeRejectedMessages)
                > 0,
        "SignAndEncrypt-configured reader counts lower-than-configured drops");

    // ...deliver nothing, and stay healthy (PreOperational, never Error, not log-storming)
    assertTrue(noneEvents.isEmpty(), "None-configured reader must not receive secured messages");
    assertTrue(encryptEvents.isEmpty(), "lower-than-configured must not be delivered");

    PubSubHandle readerNone =
        subscriber.components().dataSetReader("sub-conn", "rg-none", "reader-none").orElseThrow();
    PubSubHandle readerEncrypt =
        subscriber
            .components()
            .dataSetReader("sub-conn", "rg-encrypt", "reader-encrypt")
            .orElseThrow();
    assertNotEquals(PubSubState.Error, subscriber.state(readerNone));
    assertNotEquals(PubSubState.Error, subscriber.state(readerEncrypt));
    assertEquals(PubSubState.PreOperational, subscriber.state(readerNone));
    assertEquals(PubSubState.PreOperational, subscriber.state(readerEncrypt));

    // the drops were mode drops, not crypto failures
    for (String path : List.of("sub-conn/rg-none", "sub-conn/rg-encrypt", "sub-conn/rg-sign")) {
      assertEquals(
          0,
          counter(
              subscriber, path, PubSubDiagnostics.ComponentDiagnostics::invalidSignatureMessages),
          path);
      assertEquals(
          0,
          counter(subscriber, path, PubSubDiagnostics.ComponentDiagnostics::decryptionErrors),
          path);
      assertEquals(
          0,
          counter(subscriber, path, PubSubDiagnostics.ComponentDiagnostics::unknownTokenMessages),
          path);
    }
  }

  // region fixtures

  /** A static provider serving sequential key data for {@code policy} under SecurityGroup "SG". */
  private static SecurityKeyProvider staticProvider(PubSubSecurityPolicy policy) {
    byte[] keyData = new byte[policy.getKeyDataLength()];
    for (int i = 0; i < keyData.length; i++) {
      keyData[i] = (byte) i;
    }
    return StaticSecurityKeyProvider.of(policy, ByteString.of(keyData));
  }

  private static WriterGroupConfig secureWriterGroup(
      String name,
      UShort writerGroupId,
      UShort dataSetWriterId,
      MessageSecurityMode mode,
      PublishedDataSetConfig dataSet) {

    return WriterGroupConfig.builder(name)
        .writerGroupId(writerGroupId)
        .publishingInterval(Duration.ofMillis(75))
        .messageSettings(GROUP_SETTINGS)
        .messageSecurity(MessageSecurityConfig.builder().mode(mode).securityGroup(SG_REF).build())
        .dataSetWriter(
            DataSetWriterConfig.builder(name + "-writer")
                .dataSet(dataSet.ref())
                .dataSetWriterId(dataSetWriterId)
                .settings(WRITER_SETTINGS)
                .build())
        .build();
  }

  private static DataSetReaderConfig reader(
      String name, UShort writerGroupId, UShort dataSetWriterId, DataSetMetaDataConfig metaData) {

    return DataSetReaderConfig.builder(name)
        .publisherId(PUBLISHER_ID)
        .writerGroupId(writerGroupId)
        .dataSetWriterId(dataSetWriterId)
        .dataSetMetaData(metaData)
        .metadataPolicy(MetadataPolicy.REQUIRE_CONFIGURED)
        .build();
  }

  /**
   * Publisher config: one secured writer group at 75 ms with two writers on two published datasets,
   * sending to 127.0.0.1:{@code port} — the multi-writer shape of UdpLoopbackIntegrationTest with
   * message security added.
   */
  private static PubSubConfig publisherConfig(int port, MessageSecurityMode mode)
      throws SocketException {

    PublishedDataSetConfig dataSetA =
        PublishedDataSetConfig.builder("ds-a")
            .field(
                FieldDefinition.builder("temperature")
                    .dataType(NodeIds.Double)
                    .dataSetFieldId(TEMPERATURE_FIELD_ID)
                    .build())
            .field(
                FieldDefinition.builder("status")
                    .dataType(NodeIds.String)
                    .dataSetFieldId(STATUS_FIELD_ID)
                    .build())
            .configurationVersion(uint(7), uint(3))
            .build();

    PublishedDataSetConfig dataSetB =
        PublishedDataSetConfig.builder("ds-b")
            .field(
                FieldDefinition.builder("counter")
                    .dataType(NodeIds.Int32)
                    .dataSetFieldId(COUNTER_FIELD_ID)
                    .build())
            .configurationVersion(uint(1), uint(1))
            .build();

    WriterGroupConfig writerGroup =
        WriterGroupConfig.builder("grp")
            .writerGroupId(GROUP_ID)
            .publishingInterval(Duration.ofMillis(75))
            .messageSettings(GROUP_SETTINGS)
            .messageSecurity(
                MessageSecurityConfig.builder().mode(mode).securityGroup(SG_REF).build())
            .dataSetWriter(
                DataSetWriterConfig.builder("writer-a")
                    .dataSet(dataSetA.ref())
                    .dataSetWriterId(ushort(1))
                    .settings(WRITER_SETTINGS)
                    .build())
            .dataSetWriter(
                DataSetWriterConfig.builder("writer-b")
                    .dataSet(dataSetB.ref())
                    .dataSetWriterId(ushort(2))
                    .settings(WRITER_SETTINGS)
                    .build())
            .build();

    return PubSubConfig.builder()
        .publishedDataSet(dataSetA)
        .publishedDataSet(dataSetB)
        .securityGroup(SecurityGroupConfig.builder("SG").build())
        .connection(
            PubSubConnectionConfig.udp("pub-conn")
                .publisherId(PUBLISHER_ID)
                .address(UdpDatagramAddress.unicast("127.0.0.1", port))
                .discoveryAddress(UdpDatagramAddress.unicast("127.0.0.1", freeUdpPort()))
                .writerGroup(writerGroup)
                .build())
        .build();
  }

  /**
   * Subscriber config matching {@link #publisherConfig}: one secured reader group with two
   * REQUIRE_CONFIGURED readers, bound to 127.0.0.1:{@code port}.
   */
  private static PubSubConfig subscriberConfig(int port, MessageSecurityMode mode)
      throws SocketException {

    DataSetMetaDataConfig metaDataA =
        DataSetMetaDataConfig.builder("ds-a")
            .field("temperature", NodeIds.Double, TEMPERATURE_FIELD_ID)
            .field("status", NodeIds.String, STATUS_FIELD_ID)
            .configurationVersion(uint(7), uint(3))
            .build();

    DataSetMetaDataConfig metaDataB =
        DataSetMetaDataConfig.builder("ds-b")
            .field("counter", NodeIds.Int32, COUNTER_FIELD_ID)
            .configurationVersion(uint(1), uint(1))
            .build();

    ReaderGroupConfig readerGroup =
        ReaderGroupConfig.builder("rgrp")
            .messageSecurity(
                MessageSecurityConfig.builder().mode(mode).securityGroup(SG_REF).build())
            .dataSetReader(reader("reader-a", GROUP_ID, ushort(1), metaDataA))
            .dataSetReader(reader("reader-b", GROUP_ID, ushort(2), metaDataB))
            .build();

    return PubSubConfig.builder()
        .securityGroup(SecurityGroupConfig.builder("SG").build())
        .connection(
            PubSubConnectionConfig.udp("sub-conn")
                .address(UdpDatagramAddress.unicast("127.0.0.1", port))
                .discoveryAddress(UdpDatagramAddress.unicast("127.0.0.1", freeUdpPort()))
                .readerGroup(readerGroup)
                .build())
        .build();
  }

  // endregion

  // region helpers

  private PubSubService track(PubSubService service) {
    services.add(service);
    return service;
  }

  /**
   * Pick a currently free UDP port by binding and closing an ephemeral socket. The small race
   * between closing and re-binding is accepted.
   */
  private static int freeUdpPort() throws SocketException {
    try (DatagramSocket socket = new DatagramSocket(0)) {
      return socket.getLocalPort();
    }
  }

  /** A source that reads the current values of an AtomicReference-backed map by field key. */
  private static PublishedDataSetSource mapSource(AtomicReference<Map<String, DataValue>> values) {
    return context -> {
      DataSetSnapshot.Builder builder = DataSetSnapshot.builder(context);
      Map<String, DataValue> currentValues = values.get();
      for (FieldDefinition field : context.fields()) {
        String key =
            field.getSource() instanceof KeyFieldAddress keyAddress
                ? keyAddress.key()
                : field.getName();
        DataValue value = currentValues.get(key);
        if (value != null) {
          builder.field(field.getName(), value);
        }
      }
      return builder.build();
    };
  }

  /** Wait for an event matching {@code predicate}, discarding non-matching events. */
  private static DataSetReceivedEvent awaitEvent(
      BlockingQueue<DataSetReceivedEvent> events, Predicate<DataSetReceivedEvent> predicate)
      throws InterruptedException {

    long deadline = System.nanoTime() + TIMEOUT.toNanos();
    while (true) {
      long remaining = deadline - System.nanoTime();
      if (remaining <= 0) {
        fail("timed out waiting for a matching DataSetReceivedEvent");
      }
      DataSetReceivedEvent event =
          events.poll(Math.min(remaining, 100_000_000L), TimeUnit.NANOSECONDS);
      if (event != null && predicate.test(event)) {
        return event;
      }
    }
  }

  /** Poll {@code condition} until it holds or the deadline expires. */
  private static void awaitTrue(BooleanSupplier condition, String description)
      throws InterruptedException {

    long deadline = System.nanoTime() + TIMEOUT.toNanos();
    while (!condition.getAsBoolean()) {
      if (System.nanoTime() >= deadline) {
        fail("timed out waiting for: " + description);
      }
      Thread.sleep(25);
    }
  }

  /**
   * Wait for a secured reader to leave its pending state: reader groups stay PreOperational until
   * their first key fetch lands, and readers only activate afterwards. Racing the publisher against
   * this window would drop early frames as unknown-token, muddying the clean-counter assertions.
   */
  private static void awaitReaderActivated(
      PubSubService service, String connection, String group, String reader)
      throws InterruptedException {

    PubSubHandle handle =
        service.components().dataSetReader(connection, group, reader).orElseThrow();
    awaitTrue(
        () -> service.state(handle) == PubSubState.PreOperational,
        "reader " + connection + "/" + group + "/" + reader + " activated after the key fetch");
  }

  private static long counter(
      PubSubService service,
      String path,
      ToLongFunction<PubSubDiagnostics.ComponentDiagnostics> counter) {

    PubSubDiagnostics.ComponentDiagnostics diagnostics =
        service.diagnostics().component(path).orElse(null);

    return diagnostics == null ? 0L : counter.applyAsLong(diagnostics);
  }

  // endregion
}
