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

import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.ushort;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import io.netty.buffer.ByteBuf;
import java.net.DatagramSocket;
import java.net.SocketException;
import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;
import org.eclipse.milo.opcua.sdk.pubsub.DataSetSnapshot;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubBindings;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubService;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubServiceConfig;
import org.eclipse.milo.opcua.sdk.pubsub.PublishedDataSetReadContext;
import org.eclipse.milo.opcua.sdk.pubsub.config.DataSetReaderConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.DataSetWriterConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.FieldDefinition;
import org.eclipse.milo.opcua.sdk.pubsub.config.PubSubConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.PubSubConnectionConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.PublishedDataSetConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.PublishedDataSetRef;
import org.eclipse.milo.opcua.sdk.pubsub.config.PublisherId;
import org.eclipse.milo.opcua.sdk.pubsub.config.ReaderGroupConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.UdpConnectionConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.UdpDatagramAddress;
import org.eclipse.milo.opcua.sdk.pubsub.config.WriterGroupConfig;
import org.eclipse.milo.opcua.sdk.pubsub.transport.PublisherChannel;
import org.eclipse.milo.opcua.sdk.pubsub.transport.PublisherTransportContext;
import org.eclipse.milo.opcua.sdk.pubsub.transport.SubscriberChannel;
import org.eclipse.milo.opcua.sdk.pubsub.transport.SubscriberTransportContext;
import org.eclipse.milo.opcua.sdk.pubsub.transport.TransportProvider;
import org.eclipse.milo.opcua.stack.core.NodeIds;
import org.eclipse.milo.opcua.stack.core.types.builtin.DataValue;
import org.eclipse.milo.opcua.stack.core.types.builtin.Variant;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * Discovery channels are opened lazily when a connection first needs them (a writer group's
 * responder leg here) and are closed again when a reconfiguration removes the last component that
 * required them. Data channels use an in-memory stub transport; the discovery channels use the
 * built-in UDP transport on a free loopback port.
 */
class DiscoveryChannelCloseTest {

  private static final UUID FIELD_ID = new UUID(0L, 1L);

  private @Nullable PubSubService service;
  private @Nullable ExecutorService transportExecutor;

  @AfterEach
  void shutdown() throws Exception {
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

  /** In-memory data transport; discovery still uses the built-in UDP provider. */
  private static final class StubDataTransport implements TransportProvider {

    @Override
    public String transportProfileUri() {
      return "urn:eclipse:milo:test:discovery-close-stub";
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
      return () -> CompletableFuture.completedFuture(null);
    }
  }

  private static int freeUdpPort() throws SocketException {
    try (DatagramSocket socket = new DatagramSocket(0)) {
      return socket.getLocalPort();
    }
  }

  private static PublishedDataSetConfig publishedDataSet() {
    return PublishedDataSetConfig.builder("PDS")
        .field(
            FieldDefinition.builder("F1").dataType(NodeIds.Int32).dataSetFieldId(FIELD_ID).build())
        .build();
  }

  private static DataSetSnapshot snapshotOf(PublishedDataSetReadContext context) {
    return DataSetSnapshot.builder(context).field("F1", new DataValue(Variant.ofInt32(42))).build();
  }

  private static void awaitTrue(String description, BooleanSupplier condition)
      throws InterruptedException {

    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
    while (System.nanoTime() < deadline) {
      if (condition.getAsBoolean()) {
        return;
      }
      Thread.sleep(10);
    }
    fail("timed out waiting for: " + description);
  }

  @Test
  void discoveryChannelsCloseWhenReconfigureRemovesLastWriterGroup() throws Exception {
    int dataPort = freeUdpPort();
    int discoveryPort = freeUdpPort();

    transportExecutor = Executors.newSingleThreadExecutor();

    WriterGroupConfig writerGroup =
        WriterGroupConfig.builder("WG")
            .writerGroupId(ushort(1))
            .publishingInterval(Duration.ofMillis(50))
            .dataSetWriter(
                DataSetWriterConfig.builder("W1")
                    .dataSet(new PublishedDataSetRef("PDS"))
                    .dataSetWriterId(ushort(1))
                    .build())
            .build();

    // a REQUIRE_CONFIGURED reader group that outlives the writer group but never needs discovery
    ReaderGroupConfig readerGroup =
        ReaderGroupConfig.builder("RG")
            .dataSetReader(DataSetReaderConfig.builder("R1").build())
            .build();

    UdpConnectionConfig withWriterGroup =
        UdpConnectionConfig.builder("conn")
            .publisherId(PublisherId.uint16(ushort(9)))
            .address(UdpDatagramAddress.unicast("127.0.0.1", dataPort))
            .discoveryAddress(UdpDatagramAddress.unicast("127.0.0.1", discoveryPort))
            .writerGroup(writerGroup)
            .readerGroup(readerGroup)
            .build();

    PubSubServiceConfig serviceConfig =
        PubSubServiceConfig.builder()
            .transportProvider(new StubDataTransport())
            .transportExecutor(transportExecutor)
            .build();

    service =
        PubSubService.create(
            PubSubConfig.builder()
                .publishedDataSet(publishedDataSet())
                .connection(withWriterGroup)
                .build(),
            PubSubBindings.builder()
                .source(new PublishedDataSetRef("PDS"), DiscoveryChannelCloseTest::snapshotOf)
                .build(),
            serviceConfig);
    service.startup().get(10, TimeUnit.SECONDS);

    var impl = (PubSubServiceImpl) service;
    DiscoveryRuntime discovery = impl.connectionRuntime("conn").discoveryRuntime();
    assertNotNull(discovery, "UDP connection should have a discovery runtime");

    // the writer group's responder leg opened the discovery channels
    awaitTrue("discovery channels to open for the responder leg", discovery::channelsOpen);

    // reconfigure the connection to drop its only writer group, keeping the reader group
    UdpConnectionConfig withoutWriterGroup =
        UdpConnectionConfig.builder("conn")
            .publisherId(PublisherId.uint16(ushort(9)))
            .address(UdpDatagramAddress.unicast("127.0.0.1", dataPort))
            .discoveryAddress(UdpDatagramAddress.unicast("127.0.0.1", discoveryPort))
            .readerGroup(readerGroup)
            .build();

    service.reconfigure(
        PubSubConfig.builder()
            .publishedDataSet(publishedDataSet())
            .connection(withoutWriterGroup)
            .build(),
        PubSubService.ReconfigureMode.DISABLE_AFFECTED);

    // the connection survives (the reader group remains), but discovery is no longer required, so
    // its channels are closed rather than left open one-way
    DiscoveryRuntime afterReconfigure = impl.connectionRuntime("conn").discoveryRuntime();
    assertNotNull(afterReconfigure);
    assertFalse(
        afterReconfigure.channelsOpen(),
        "discovery channels must close once the last writer group is removed");
  }
}
