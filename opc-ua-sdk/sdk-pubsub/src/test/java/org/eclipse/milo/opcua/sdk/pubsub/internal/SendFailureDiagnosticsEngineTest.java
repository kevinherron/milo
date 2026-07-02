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
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import io.netty.buffer.ByteBuf;
import java.net.URI;
import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;
import org.eclipse.milo.opcua.sdk.pubsub.DataSetSnapshot;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubBindings;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubDiagnostics.ComponentDiagnostics;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubService;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubServiceConfig;
import org.eclipse.milo.opcua.sdk.pubsub.PublishedDataSetReadContext;
import org.eclipse.milo.opcua.sdk.pubsub.config.DataSetWriterConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.FieldDefinition;
import org.eclipse.milo.opcua.sdk.pubsub.config.MqttConnectionConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.PubSubConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.PubSubConnectionConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.PublishedDataSetConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.PublishedDataSetRef;
import org.eclipse.milo.opcua.sdk.pubsub.config.PublisherId;
import org.eclipse.milo.opcua.sdk.pubsub.config.WriterGroupConfig;
import org.eclipse.milo.opcua.sdk.pubsub.transport.MessageAddress;
import org.eclipse.milo.opcua.sdk.pubsub.transport.PublisherChannel;
import org.eclipse.milo.opcua.sdk.pubsub.transport.PublisherTransportContext;
import org.eclipse.milo.opcua.sdk.pubsub.transport.SubscriberChannel;
import org.eclipse.milo.opcua.sdk.pubsub.transport.SubscriberTransportContext;
import org.eclipse.milo.opcua.sdk.pubsub.transport.TransportProvider;
import org.eclipse.milo.opcua.stack.core.NodeIds;
import org.eclipse.milo.opcua.stack.core.StatusCodes;
import org.eclipse.milo.opcua.stack.core.UaException;
import org.eclipse.milo.opcua.stack.core.types.builtin.DataValue;
import org.eclipse.milo.opcua.stack.core.types.builtin.StatusCode;
import org.eclipse.milo.opcua.stack.core.types.builtin.Variant;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * End-to-end send-failure diagnostics through the real engine (the un-flatten and shutdown-silence
 * contract that {@code DiagnosticsCollectorTest} pins only at the collector level):
 *
 * <ul>
 *   <li>a transport send failure surfaces the channel's REAL {@link StatusCode} (not the former
 *       blanket {@code Bad_CommunicationError}) as the writer group's {@code FailedTransmissions}
 *       {@code lastError}, with a {@code FailedDataSetMessage} counter-only attribution (no {@code
 *       lastError}) on each contributing writer; and
 *   <li>a send that fails after the connection's channel was torn down on a clean shutdown ticks
 *       NOTHING — no counter, {@code lastError}, or event — because the failure is teardown noise.
 * </ul>
 *
 * <p>The transport is an in-memory stub, so nothing touches the network.
 */
class SendFailureDiagnosticsEngineTest {

  private static final UUID FIELD_ID = new UUID(0L, 1L);

  /** The real transport status the failing channel reports; must survive un-flattened. */
  private static final StatusCode SEND_FAILURE_STATUS =
      new StatusCode(StatusCodes.Bad_ServerNotConnected);

  private @Nullable PubSubService service;

  @AfterEach
  void shutdown() throws Exception {
    if (service != null) {
      service.close();
      service = null;
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

  private void startService(TransportProvider transport) throws Exception {
    MqttConnectionConfig connection =
        MqttConnectionConfig.builder("conn")
            .brokerUri(URI.create("mqtt://localhost:1883"))
            .publisherId(PublisherId.uint16(ushort(1)))
            .writerGroup(
                WriterGroupConfig.builder("WG")
                    .writerGroupId(ushort(1))
                    .publishingInterval(Duration.ofMillis(25))
                    .dataSetWriter(
                        DataSetWriterConfig.builder("W1")
                            .dataSet(new PublishedDataSetRef("PDS"))
                            .dataSetWriterId(ushort(1))
                            .build())
                    .build())
            .build();

    PubSubServiceConfig serviceConfig =
        PubSubServiceConfig.builder().transportProvider(transport).build();

    service =
        PubSubService.create(
            PubSubConfig.builder()
                .publishedDataSet(publishedDataSet())
                .connection(connection)
                .build(),
            PubSubBindings.builder()
                .source(
                    new PublishedDataSetRef("PDS"), SendFailureDiagnosticsEngineTest::snapshotOf)
                .build(),
            serviceConfig);
    service.startup().get(10, TimeUnit.SECONDS);
  }

  private ComponentDiagnostics diag(String path) {
    ComponentDiagnostics cd = service.diagnostics().snapshot().get(path);
    org.junit.jupiter.api.Assertions.assertNotNull(cd, path);
    return cd;
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
  void sendFailureSurfacesTheUnflattenedTransportStatus() throws Exception {
    // every send completes exceptionally with the real transport status
    startService(new AlwaysFailingTransport());

    awaitTrue(
        "a failed transmission is recorded",
        () ->
            service.diagnostics().snapshot().get("conn/WG") != null
                && diag("conn/WG").failedTransmissions() >= 1);

    // the writer group carries FailedTransmissions with the REAL status un-flattened (not the
    // former blanket Bad_CommunicationError)
    assertTrue(diag("conn/WG").failedTransmissions() >= 1);
    assertEquals(SEND_FAILURE_STATUS, diag("conn/WG").lastError());

    // the contributing writer carries FailedDataSetMessages, counter-only (no lastError)
    awaitTrue(
        "the writer's failed DataSetMessages are attributed",
        () -> diag("conn/WG/W1").failedDataSetMessages() >= 1);
    assertNull(diag("conn/WG/W1").lastError());
  }

  @Test
  void sendFailingAfterCleanShutdownTicksNothing() throws Exception {
    // sends never complete until the test completes them, so at shutdown a batch is in flight
    var transport = new DeferredFailureTransport();
    startService(transport);

    awaitTrue("at least one send is in flight", () -> !transport.pending.isEmpty());

    // clean shutdown tears the connection's publisher channel down (closeChannels nulls it), so the
    // in-flight sends' failures are teardown noise; the diagnostics tree stays registered after
    // shutdown, so the snapshot is still readable
    service.shutdown().get(10, TimeUnit.SECONDS);

    // now the in-flight sends fail against the torn-down channel
    CompletableFuture<Void> next;
    int completed = 0;
    while ((next = transport.pending.poll()) != null) {
      next.completeExceptionally(new UaException(SEND_FAILURE_STATUS, "channel closed"));
      completed++;
    }
    assertTrue(completed >= 1, "expected at least one in-flight send to fail after shutdown");

    // shutdown silence: no counter, no lastError, no event for a failure on a torn-down channel
    assertEquals(0, diag("conn/WG").failedTransmissions());
    assertEquals(0, diag("conn/WG/W1").failedDataSetMessages());
    assertNull(diag("conn/WG").lastError());
  }

  /**
   * A transport whose DATA sends fail immediately with {@link #SEND_FAILURE_STATUS} while metadata
   * sends succeed — so only the writer-group DATA send-failure path (FailedTransmissions /
   * FailedDataSetMessages) is exercised, and the metadata publisher never sets the writer path's
   * {@code lastError}.
   */
  private static final class AlwaysFailingTransport implements TransportProvider {

    @Override
    public String transportProfileUri() {
      return "urn:eclipse:milo:test:always-failing";
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
        public CompletableFuture<Void> send(ByteBuf message, MessageAddress address) {
          message.release();
          if (address != null && address.kind() == MessageAddress.Kind.DATA) {
            return CompletableFuture.failedFuture(
                new UaException(SEND_FAILURE_STATUS, "stub: broker not connected"));
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
      return () -> CompletableFuture.completedFuture(null);
    }
  }

  /**
   * A transport whose sends return futures the test completes later, so a batch of in-flight sends
   * can be failed after a clean shutdown has torn the channel down.
   */
  private static final class DeferredFailureTransport implements TransportProvider {

    final BlockingQueue<CompletableFuture<Void>> pending = new LinkedBlockingQueue<>();

    @Override
    public String transportProfileUri() {
      return "urn:eclipse:milo:test:deferred-failure";
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
          var future = new CompletableFuture<Void>();
          pending.add(future);
          return future;
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
}
