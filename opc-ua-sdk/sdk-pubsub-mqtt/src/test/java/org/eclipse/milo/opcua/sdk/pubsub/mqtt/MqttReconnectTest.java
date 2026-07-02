/*
 * Copyright (c) 2026 the Eclipse Milo Authors
 *
 * This program and the accompanying materials are made
 * available under the terms of the Eclipse Public License 2.0
 * which is available at https://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 */

package org.eclipse.milo.opcua.sdk.pubsub.mqtt;

import static org.eclipse.milo.opcua.sdk.pubsub.mqtt.PubSubMqttTestSupport.TIMEOUT;
import static org.eclipse.milo.opcua.sdk.pubsub.mqtt.PubSubMqttTestSupport.awaitEvent;
import static org.eclipse.milo.opcua.sdk.pubsub.mqtt.PubSubMqttTestSupport.awaitTrue;
import static org.eclipse.milo.opcua.sdk.pubsub.mqtt.PubSubMqttTestSupport.mapSource;
import static org.eclipse.milo.opcua.sdk.pubsub.mqtt.PubSubMqttTestSupport.mqttServiceConfig;
import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.ushort;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.hivemq.client.mqtt.datatypes.MqttQos;
import com.hivemq.client.mqtt.mqtt5.message.publish.Mqtt5Publish;
import java.net.URI;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicReference;
import org.eclipse.milo.opcua.sdk.pubsub.DataSetReaderRef;
import org.eclipse.milo.opcua.sdk.pubsub.DataSetReceivedEvent;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubBindings;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubHandle;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubService;
import org.eclipse.milo.opcua.sdk.pubsub.config.BrokerTransportSettings;
import org.eclipse.milo.opcua.sdk.pubsub.config.DataSetMetaDataConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.DataSetReaderConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.DataSetWriterConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.FieldDefinition;
import org.eclipse.milo.opcua.sdk.pubsub.config.MetadataPolicy;
import org.eclipse.milo.opcua.sdk.pubsub.config.PubSubConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.PubSubConnectionConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.PublishedDataSetConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.PublisherId;
import org.eclipse.milo.opcua.sdk.pubsub.config.ReaderGroupConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.WriterGroupConfig;
import org.eclipse.milo.opcua.stack.core.NodeIds;
import org.eclipse.milo.opcua.stack.core.types.builtin.DataValue;
import org.eclipse.milo.opcua.stack.core.types.builtin.Variant;
import org.eclipse.milo.opcua.stack.core.types.enumerated.PubSubState;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Broker-outage recovery: the embedded broker is stopped and a fresh instance is started on the
 * same port (CE supports this; the second instance pins the discovered port explicitly). The HiveMQ
 * clients reconnect automatically, the subscriber session re-issues its subscriptions, and data
 * flow resumes.
 *
 * <p>Timing: HiveMQ reconnect backoff starts at 1 s and doubles (±25% jitter, capped at 120 s), and
 * a broker boot takes roughly 1.5-8 s, so resumption is awaited with a generous timeout.
 */
class MqttReconnectTest {

  private static final PublisherId PUBLISHER_ID = PublisherId.uint16(ushort(777));

  private static final String DATA_TOPIC = "opcua/uadp/data/777/grp";

  private static final String META_TOPIC = "opcua/uadp/metadata/777/grp/writer-a";

  /** Resumption budget: broker boot + reconnect backoff that may have grown during the boot. */
  private static final Duration RESUME_TIMEOUT = Duration.ofSeconds(60);

  @TempDir static Path tempDir;

  private final List<PubSubService> services = new CopyOnWriteArrayList<>();

  @AfterEach
  void tearDown() throws InterruptedException {
    for (PubSubService service : services) {
      try {
        service.shutdown().get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);
      } catch (ExecutionException | TimeoutException e) {
        // best effort cleanup
      }
    }
    services.clear();
  }

  @Test
  void subscriberResubscribesAndDataFlowResumesAfterBrokerRestart() throws Exception {
    EmbeddedTestBroker firstBroker = EmbeddedTestBroker.start(tempDir.resolve("broker1"));
    int port = firstBroker.port();

    var events = new LinkedBlockingQueue<DataSetReceivedEvent>();

    PubSubService publisher;
    PubSubService subscriber;
    try {
      publisher = startPublisher(port);
      subscriber = startSubscriber(port, events);

      // data flows through the first broker instance
      awaitEvent(events, event -> true, Duration.ofSeconds(30));
    } catch (Exception e) {
      firstBroker.stop();
      throw e;
    }

    // stop the broker: the transport reports the disconnect, so the publisher connection
    // fails into Error and its writer group cascades to Paused, stopping publishing
    firstBroker.stop();

    PubSubHandle pubConn = publisher.components().connection("pub-conn").orElseThrow();
    PubSubHandle pubGroup = publisher.components().writerGroup("pub-conn", "grp").orElseThrow();

    awaitTrue(
        () -> publisher.state(pubConn) == PubSubState.Error,
        "publisher connection to enter Error after broker stop",
        Duration.ofSeconds(30));
    awaitTrue(
        () -> publisher.state(pubGroup) == PubSubState.Paused,
        "publisher writer group to Pause after broker stop",
        Duration.ofSeconds(30));

    events.clear();

    // a FRESH broker instance on the SAME port; in-memory persistence means all broker state
    // (sessions, retained messages) is gone, so the resumed flow proves the clients
    // reconnected and the subscriber re-issued its subscriptions
    EmbeddedTestBroker secondBroker = EmbeddedTestBroker.start(tempDir.resolve("broker2"), port);
    try {
      DataSetReceivedEvent event = awaitEvent(events, e -> true, RESUME_TIMEOUT);
      assertEquals(ushort(1), event.dataSetWriterId());
      assertEquals(21.5, event.fieldsByName().get("temperature").value().value());

      // the publisher connection recovers to Operational on reconnect, re-activating its
      // writer group (which resumes publishing and re-publishes retained metadata)
      awaitTrue(
          () -> publisher.state(pubConn) == PubSubState.Operational,
          "publisher connection Operational after broker restart",
          Duration.ofSeconds(30));

      // the reader settles (back) into Operational
      PubSubHandle reader =
          subscriber.components().dataSetReader("sub-conn", "rgrp", "reader-a").orElseThrow();
      awaitTrue(
          () -> subscriber.state(reader) == PubSubState.Operational,
          "reader Operational after broker restart",
          Duration.ofSeconds(30));

      // shut down the services before the broker so teardown is clean and quiet
      subscriber.shutdown().get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);
      publisher.shutdown().get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);
    } finally {
      secondBroker.stop();
    }
  }

  /**
   * Retained-metadata republish: metadata is published only at writer activation (no periodic
   * republish is configured), so after the broker is replaced by a fresh instance — whose in-memory
   * retained store starts empty — the only way a subscriber can still discover the writer's
   * metadata is if the publisher RE-PUBLISHED it when its connection recovered to Operational. A
   * raw MQTT probe connecting to the fresh broker after the restart receives that republished
   * metadata.
   */
  @Test
  void retainedMetadataRepublishesToFreshBrokerAfterRestart() throws Exception {
    EmbeddedTestBroker firstBroker = EmbeddedTestBroker.start(tempDir.resolve("broker-meta-1"));
    int port = firstBroker.port();

    PubSubService publisher;
    try {
      publisher = startPublisher(port);
      // once data is flowing the publisher is demonstrably established and the retained metadata is
      // stored, so a LATE subscriber to the metadata topic receives it with the retain flag set
      assertRetainedMetadataIsReplayed(port, Duration.ofSeconds(30));
    } catch (Exception e) {
      firstBroker.stop();
      throw e;
    }

    PubSubHandle pubConn = publisher.components().connection("pub-conn").orElseThrow();

    // stop the broker: the publisher connection fails into Error
    firstBroker.stop();
    awaitTrue(
        () -> publisher.state(pubConn) == PubSubState.Error,
        "publisher connection Error after broker stop",
        Duration.ofSeconds(30));

    // a FRESH broker on the same port has NO retained messages; anything a late subscriber can
    // still replay was necessarily republished by the reconnecting publisher
    EmbeddedTestBroker secondBroker =
        EmbeddedTestBroker.start(tempDir.resolve("broker-meta-2"), port);
    try {
      // the connection recovers to Operational, which re-activates the writer group and triggers
      // the retained-metadata republish
      awaitTrue(
          () -> publisher.state(pubConn) == PubSubState.Operational,
          "publisher connection Operational after broker restart",
          Duration.ofSeconds(30));

      // the republished retained metadata replays to a late subscriber on the fresh broker
      assertRetainedMetadataIsReplayed(port, RESUME_TIMEOUT);

      publisher.shutdown().get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);
    } finally {
      secondBroker.stop();
    }
  }

  /**
   * Confirm data is flowing on {@code port} (so the publisher is established and its retained
   * metadata is stored), then assert a late subscriber to the metadata topic replays the retained
   * metadata announcement.
   */
  private static void assertRetainedMetadataIsReplayed(int port, Duration timeout)
      throws Exception {
    try (RawMqtt5Probe dataProbe = RawMqtt5Probe.connect(port)) {
      dataProbe.subscribe(DATA_TOPIC, MqttQos.AT_MOST_ONCE);
      dataProbe.awaitMessage(timeout);
    }
    try (RawMqtt5Probe metaProbe = RawMqtt5Probe.connect(port)) {
      metaProbe.subscribe(META_TOPIC, MqttQos.AT_LEAST_ONCE);
      Mqtt5Publish meta = metaProbe.awaitMessage(timeout);
      assertTrue(meta.isRetain(), "metadata must replay to a late subscriber as retained");
      assertEquals(META_TOPIC, meta.getTopic().toString());
      assertTrue(meta.getPayloadAsBytes().length > 0, "republished metadata must have a payload");
    }
  }

  // region fixtures

  private PubSubService startPublisher(int port) throws Exception {
    PublishedDataSetConfig dataSet =
        PublishedDataSetConfig.builder("ds-a")
            .field(FieldDefinition.builder("temperature").dataType(NodeIds.Double).build())
            .build();

    PubSubConfig config =
        PubSubConfig.builder()
            .publishedDataSet(dataSet)
            .connection(
                PubSubConnectionConfig.mqtt("pub-conn")
                    .brokerUri(URI.create("mqtt://127.0.0.1:" + port))
                    .publisherId(PUBLISHER_ID)
                    .writerGroup(
                        WriterGroupConfig.builder("grp")
                            .writerGroupId(ushort(1))
                            .publishingInterval(Duration.ofMillis(100))
                            .dataSetWriter(
                                DataSetWriterConfig.builder("writer-a")
                                    .dataSet(dataSet.ref())
                                    .dataSetWriterId(ushort(1))
                                    .build())
                            .build())
                    .build())
            .build();

    var values =
        new AtomicReference<>(Map.of("temperature", new DataValue(Variant.ofDouble(21.5))));

    PubSubService publisher =
        track(
            PubSubService.create(
                config,
                PubSubBindings.builder().source(dataSet.ref(), mapSource(values)).build(),
                mqttServiceConfig()));

    publisher.startup().get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);
    return publisher;
  }

  private PubSubService startSubscriber(int port, LinkedBlockingQueue<DataSetReceivedEvent> events)
      throws Exception {

    DataSetMetaDataConfig metaData =
        DataSetMetaDataConfig.builder("ds-a").field("temperature", NodeIds.Double).build();

    PubSubConfig config =
        PubSubConfig.builder()
            .connection(
                PubSubConnectionConfig.mqtt("sub-conn")
                    .brokerUri(URI.create("mqtt://127.0.0.1:" + port))
                    .readerGroup(
                        ReaderGroupConfig.builder("rgrp")
                            .dataSetReader(
                                DataSetReaderConfig.builder("reader-a")
                                    .publisherId(PUBLISHER_ID)
                                    .dataSetWriterId(ushort(1))
                                    .dataSetMetaData(metaData)
                                    .metadataPolicy(MetadataPolicy.REQUIRE_CONFIGURED)
                                    .brokerTransport(
                                        BrokerTransportSettings.builder()
                                            .queueName(DATA_TOPIC)
                                            .build())
                                    .build())
                            .build())
                    .build())
            .build();

    PubSubService subscriber =
        track(
            PubSubService.create(
                config,
                PubSubBindings.builder()
                    .listener(new DataSetReaderRef("sub-conn", "rgrp", "reader-a"), events::add)
                    .build(),
                mqttServiceConfig()));

    subscriber.startup().get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);
    return subscriber;
  }

  private PubSubService track(PubSubService service) {
    services.add(service);
    return service;
  }

  // endregion
}
