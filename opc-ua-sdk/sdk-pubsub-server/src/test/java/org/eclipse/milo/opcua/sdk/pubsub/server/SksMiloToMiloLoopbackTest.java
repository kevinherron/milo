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

import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.ubyte;
import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.uint;
import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.ushort;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.net.DatagramSocket;
import java.security.cert.X509Certificate;
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
import java.util.function.Predicate;
import org.eclipse.milo.opcua.sdk.pubsub.DataSetReaderRef;
import org.eclipse.milo.opcua.sdk.pubsub.DataSetReceivedEvent;
import org.eclipse.milo.opcua.sdk.pubsub.DataSetSnapshot;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubBindings;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubDiagnostics;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubService;
import org.eclipse.milo.opcua.sdk.pubsub.PublishedDataSetSource;
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
import org.eclipse.milo.opcua.sdk.pubsub.sks.SksSecurityKeyProvider;
import org.eclipse.milo.opcua.stack.core.NodeIds;
import org.eclipse.milo.opcua.stack.core.security.DefaultClientCertificateValidator;
import org.eclipse.milo.opcua.stack.core.security.MemoryCertificateQuarantine;
import org.eclipse.milo.opcua.stack.core.security.MemoryTrustListManager;
import org.eclipse.milo.opcua.stack.core.types.builtin.ByteString;
import org.eclipse.milo.opcua.stack.core.types.builtin.DataValue;
import org.eclipse.milo.opcua.stack.core.types.builtin.LocalizedText;
import org.eclipse.milo.opcua.stack.core.types.builtin.Variant;
import org.eclipse.milo.opcua.stack.core.types.enumerated.ApplicationType;
import org.eclipse.milo.opcua.stack.core.types.enumerated.MessageSecurityMode;
import org.eclipse.milo.opcua.stack.core.types.structured.ApplicationDescription;
import org.eclipse.milo.opcua.stack.core.types.structured.EndpointDescription;
import org.eclipse.milo.opcua.stack.core.types.structured.UadpDataSetMessageContentMask;
import org.eclipse.milo.opcua.stack.core.types.structured.UadpNetworkMessageContentMask;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * The K20 "SKS pull + secured pub + secured sub" row, Milo pulling from Milo full circle: one
 * embedded SKS server (the WP-V {@code GetSecurityKeys} face), a publisher-side and a
 * subscriber-side {@link PubSubService} each bound to its own {@link SksSecurityKeyProvider}
 * pulling the SAME SecurityGroup over real SignAndEncrypt sessions, and SignAndEncrypt-secured UADP
 * traffic on unicast loopback UDP decoding end-to-end.
 *
 * <p>Delivery itself proves the security chain: the reader group is configured {@code
 * SignAndEncrypt}, so the K7 mode gate drops (and counts) anything received below that mode — an
 * event can only arrive if the publisher emitted a secured NetworkMessage the subscriber verified
 * and decrypted with SKS-distributed keys. The test additionally pins zero security-error counters
 * ({@code encryptionErrors}, {@code decryptionErrors}, {@code invalidSignatureMessages}, {@code
 * unknownTokenMessages}, {@code staleKeyMessages}, {@code securityModeRejectedMessages}) and zero
 * {@code decodeErrors} on every component of both services, and one cached SKS session per side.
 *
 * <p>Network safety: the UDP connections pin explicit loopback {@code discoveryAddress}es so no
 * discovery channel ever binds 4840 or joins the default {@code 224.0.2.14} multicast group; the
 * SKS endpoints bind {@code 127.0.0.1} on an ephemeral port.
 */
class SksMiloToMiloLoopbackTest {

  private static final Duration TIMEOUT = Duration.ofSeconds(15);
  private static final Duration STARTUP_TIMEOUT = Duration.ofSeconds(30);

  private static final String GROUP_ID = "LoopbackGroup";
  private static final PubSubSecurityPolicy POLICY = PubSubSecurityPolicy.Aes256Ctr;
  private static final Duration KEY_LIFETIME = Duration.ofHours(1);

  private static final PublisherId PUBLISHER_ID = PublisherId.uint16(ushort(0x5A5A));
  private static final UUID COUNTER_FIELD_ID = new UUID(0L, 0xC0DEL);

  /** PublisherId | GroupHeader | WriterGroupId | SequenceNumber | PayloadHeader. */
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

  private static final UadpDataSetWriterSettings WRITER_SETTINGS =
      UadpDataSetWriterSettings.builder()
          .dataSetMessageContentMask(
              UadpDataSetMessageContentMask.of(
                  UadpDataSetMessageContentMask.Field.MajorVersion,
                  UadpDataSetMessageContentMask.Field.MinorVersion,
                  UadpDataSetMessageContentMask.Field.SequenceNumber))
          .build();

  private final List<PubSubService> services = new CopyOnWriteArrayList<>();
  private final List<SksSecurityKeyProvider> providers = new CopyOnWriteArrayList<>();

  private @Nullable ServerPubSub serverPubSub;
  private @Nullable TestSksServer sks;

  @AfterEach
  void tearDown() throws Exception {
    for (PubSubService service : services) {
      try {
        service.shutdown().get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);
      } catch (ExecutionException | TimeoutException e) {
        // best effort cleanup; failures are reported by the test itself
      }
    }
    services.clear();

    providers.forEach(SksSecurityKeyProvider::close);
    providers.clear();

    if (serverPubSub != null) {
      serverPubSub.close();
      serverPubSub = null;
    }
    if (sks != null) {
      sks.close();
      sks = null;
    }
  }

  @Test
  void securedLoopbackTrafficWithSksPulledKeysDecodesEndToEnd() throws Exception {
    // 1. the embedded SKS: one SecurityGroup, empty RolePermissions (no-RoleMapper posture
    //    allows any encrypted caller), 1h KeyLifetime so no rotation happens mid-test
    sks = TestSksServer.create();

    TestSksServer.ClientIdentity clientIdentity = TestSksServer.newClientIdentity();
    sks.trustClientCertificate(clientIdentity.certificate());

    PubSubConfig sksConfig =
        PubSubConfig.builder()
            .securityGroup(
                SecurityGroupConfig.builder(GROUP_ID)
                    .securityPolicyUri(POLICY.getUri())
                    .keyLifeTime(KEY_LIFETIME)
                    .maxFutureKeyCount(uint(3))
                    .build())
            .build();

    serverPubSub =
        ServerPubSub.attach(
            sks.getServer(),
            sksConfig,
            ServerPubSubOptions.builder().sksServerEnabled(true).build());
    serverPubSub.startup().get(STARTUP_TIMEOUT.toSeconds(), TimeUnit.SECONDS);

    // 2. publisher and subscriber services, each with its OWN pull provider on the SAME group
    int dataPort = freeUdpPort();

    var values = new AtomicReference<>(Map.of("counter", new DataValue(Variant.ofInt32(1))));

    SksSecurityKeyProvider publisherProvider = track(newProvider(clientIdentity));
    SksSecurityKeyProvider subscriberProvider = track(newProvider(clientIdentity));

    PubSubService publisher =
        track(
            PubSubService.create(
                publisherConfig(dataPort),
                PubSubBindings.builder()
                    .source(new PublishedDataSetRef("ds-secured"), mapSource(values))
                    .securityKeys(new SecurityGroupRef(GROUP_ID), publisherProvider)
                    .build()));

    var events = new LinkedBlockingQueue<DataSetReceivedEvent>();

    PubSubService subscriber =
        track(
            PubSubService.create(
                subscriberConfig(dataPort),
                PubSubBindings.builder()
                    .listener(new DataSetReaderRef("sub-conn", "rgrp", "reader"), events::add)
                    .securityKeys(new SecurityGroupRef(GROUP_ID), subscriberProvider)
                    .build()));

    // startup() resolving does not by itself prove the key fetches succeeded (secured
    // groups just stay PreOperational while keys are pending); event delivery below is
    // the real proof the SKS pull worked on both sides
    subscriber.startup().get(STARTUP_TIMEOUT.toSeconds(), TimeUnit.SECONDS);
    publisher.startup().get(STARTUP_TIMEOUT.toSeconds(), TimeUnit.SECONDS);

    // 3. secured frames decode end-to-end, repeatedly (multiple frames, same token)
    DataSetReceivedEvent event = awaitEvent(events, e -> counterOf(e) == 1);
    assertEquals(1, counterOf(event));

    values.set(Map.of("counter", new DataValue(Variant.ofInt32(2))));
    awaitEvent(events, e -> counterOf(e) == 2);

    // 4. zero security-error counters anywhere on either side
    assertNoSecurityErrors(publisher, "publisher");
    assertNoSecurityErrors(subscriber, "subscriber");

    // 5. each side pulled with its own provider and holds one cached SKS session
    assertEquals(2, sks.getServer().getSessionManager().getAllSessions().size());
  }

  // region fixtures

  private PubSubConfig publisherConfig(int dataPort) throws Exception {
    PublishedDataSetConfig dataSet =
        PublishedDataSetConfig.builder("ds-secured")
            .field(
                FieldDefinition.builder("counter")
                    .dataType(NodeIds.Int32)
                    .dataSetFieldId(COUNTER_FIELD_ID)
                    .build())
            .configurationVersion(uint(1), uint(1))
            .build();

    WriterGroupConfig writerGroup =
        WriterGroupConfig.builder("grp")
            .writerGroupId(ushort(1))
            .publishingInterval(Duration.ofMillis(75))
            .messageSettings(GROUP_SETTINGS)
            .messageSecurity(
                MessageSecurityConfig.builder()
                    .mode(MessageSecurityMode.SignAndEncrypt)
                    .securityGroup(new SecurityGroupRef(GROUP_ID))
                    .build())
            .dataSetWriter(
                DataSetWriterConfig.builder("writer")
                    .dataSet(dataSet.ref())
                    .dataSetWriterId(ushort(1))
                    .settings(WRITER_SETTINGS)
                    .build())
            .build();

    return PubSubConfig.builder()
        .publishedDataSet(dataSet)
        .securityGroup(securityGroup())
        .connection(
            PubSubConnectionConfig.udp("pub-conn")
                .publisherId(PUBLISHER_ID)
                .address(UdpDatagramAddress.unicast("127.0.0.1", dataPort))
                .discoveryAddress(UdpDatagramAddress.unicast("127.0.0.1", freeUdpPort()))
                .writerGroup(writerGroup)
                .build())
        .build();
  }

  private PubSubConfig subscriberConfig(int dataPort) throws Exception {
    DataSetMetaDataConfig metaData =
        DataSetMetaDataConfig.builder("ds-secured")
            .field("counter", NodeIds.Int32, COUNTER_FIELD_ID)
            .configurationVersion(uint(1), uint(1))
            .build();

    ReaderGroupConfig readerGroup =
        ReaderGroupConfig.builder("rgrp")
            .messageSecurity(
                MessageSecurityConfig.builder()
                    .mode(MessageSecurityMode.SignAndEncrypt)
                    .securityGroup(new SecurityGroupRef(GROUP_ID))
                    .build())
            .dataSetReader(
                DataSetReaderConfig.builder("reader")
                    .publisherId(PUBLISHER_ID)
                    .writerGroupId(ushort(1))
                    .dataSetWriterId(ushort(1))
                    .dataSetMetaData(metaData)
                    .metadataPolicy(MetadataPolicy.REQUIRE_CONFIGURED)
                    .build())
            .build();

    return PubSubConfig.builder()
        .securityGroup(securityGroup())
        .connection(
            PubSubConnectionConfig.udp("sub-conn")
                .address(UdpDatagramAddress.unicast("127.0.0.1", dataPort))
                .discoveryAddress(UdpDatagramAddress.unicast("127.0.0.1", freeUdpPort()))
                .readerGroup(readerGroup)
                .build())
        .build();
  }

  /**
   * The SecurityGroup as configured on the pub/sub sides: same wire id and policy as the SKS
   * server's group (K8: a policy mismatch would fail the fetch).
   */
  private static SecurityGroupConfig securityGroup() {
    return SecurityGroupConfig.builder(GROUP_ID)
        .securityPolicyUri(POLICY.getUri())
        .keyLifeTime(KEY_LIFETIME)
        .maxFutureKeyCount(uint(3))
        .build();
  }

  /** A pull provider resolving the embedded SKS via a Table 40 identity record. */
  private SksSecurityKeyProvider newProvider(TestSksServer.ClientIdentity clientIdentity) {
    var server =
        new ApplicationDescription(
            sks.getApplicationUri(),
            "urn:eclipse:milo:pubsub:sks-test-server",
            LocalizedText.english("embedded sks test server"),
            ApplicationType.Server,
            null,
            null,
            new String[] {sks.getEndpointUrl()});

    var entry =
        new EndpointDescription(
            null,
            server,
            ByteString.NULL_VALUE,
            MessageSecurityMode.SignAndEncrypt,
            null,
            null,
            null,
            ubyte(0));

    var trustListManager = new MemoryTrustListManager();
    trustListManager.addTrustedCertificate(sks.getCertificate());

    var certificateValidator =
        new DefaultClientCertificateValidator(trustListManager, new MemoryCertificateQuarantine());

    return SksSecurityKeyProvider.builder()
        .securityKeyServices(List.of(entry))
        .securityGroupId(GROUP_ID)
        .certificateValidator(certificateValidator)
        .clientCustomizer(
            b ->
                b.setApplicationUri(clientIdentity.applicationUri())
                    .setCertificate(clientIdentity.certificate())
                    .setCertificateChain(new X509Certificate[] {clientIdentity.certificate()})
                    .setKeyPair(clientIdentity.keyPair()))
        .requestTimeout(TIMEOUT)
        .fetchTimeout(STARTUP_TIMEOUT)
        .build();
  }

  // endregion

  // region helpers

  private PubSubService track(PubSubService service) {
    services.add(service);
    return service;
  }

  private SksSecurityKeyProvider track(SksSecurityKeyProvider provider) {
    providers.add(provider);
    return provider;
  }

  private static int freeUdpPort() throws Exception {
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

  private static int counterOf(DataSetReceivedEvent event) {
    DataValue value = event.fieldsByName().get("counter");
    return value != null && value.value().value() instanceof Integer i ? i : Integer.MIN_VALUE;
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
      DataSetReceivedEvent event = events.poll(remaining, TimeUnit.NANOSECONDS);
      if (event != null && predicate.test(event)) {
        return event;
      }
    }
  }

  /** Every component of {@code service} must show zero security errors and zero decode errors. */
  private static void assertNoSecurityErrors(PubSubService service, String label) {
    Map<String, PubSubDiagnostics.ComponentDiagnostics> snapshot = service.diagnostics().snapshot();
    assertTrue(!snapshot.isEmpty(), label + " has no diagnostics components");

    snapshot.forEach(
        (path, diagnostics) -> {
          String at = label + " " + path + " ";
          assertEquals(0, diagnostics.encryptionErrors(), at + "encryptionErrors");
          assertEquals(0, diagnostics.decryptionErrors(), at + "decryptionErrors");
          assertEquals(0, diagnostics.invalidSignatureMessages(), at + "invalidSignatureMessages");
          assertEquals(0, diagnostics.unknownTokenMessages(), at + "unknownTokenMessages");
          assertEquals(0, diagnostics.staleKeyMessages(), at + "staleKeyMessages");
          assertEquals(
              0, diagnostics.securityModeRejectedMessages(), at + "securityModeRejectedMessages");
          assertEquals(0, diagnostics.decodeErrors(), at + "decodeErrors");
        });
  }

  // endregion
}
