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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import io.netty.buffer.ByteBuf;
import java.net.URI;
import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;
import org.eclipse.milo.opcua.sdk.pubsub.DataSetSnapshot;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubBindings;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubDiagnostics.ComponentDiagnostics;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubDiagnostics.Counter;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubHandle;
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
import org.eclipse.milo.opcua.sdk.pubsub.transport.PublisherChannel;
import org.eclipse.milo.opcua.sdk.pubsub.transport.PublisherTransportContext;
import org.eclipse.milo.opcua.sdk.pubsub.transport.SubscriberChannel;
import org.eclipse.milo.opcua.sdk.pubsub.transport.SubscriberTransportContext;
import org.eclipse.milo.opcua.sdk.pubsub.transport.TransportProvider;
import org.eclipse.milo.opcua.stack.core.NodeIds;
import org.eclipse.milo.opcua.stack.core.types.builtin.DataValue;
import org.eclipse.milo.opcua.stack.core.types.builtin.Variant;
import org.eclipse.milo.opcua.stack.core.types.enumerated.PubSubState;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * End-to-end (Part 14 §9.1.11.3 / Table 311) state-counter attribution driven through the real
 * engine: {@link DiagnosticsCollectorTest} pins the collector arithmetic with synthetic {@code
 * recordStateChange} calls, while this test drives genuine transitions — startup, a Method
 * Disable/Enable of a group with its writer child cascading by parent, and subtree disposal on
 * shutdown — through {@link PubSubService} and asserts the six {@code State*} counters land with
 * the correct cause attribution (the {@code ByMethod}/{@code ByParent} split on the final
 * Operational hop, and dispose never counting as {@code StateDisabledByMethod}).
 *
 * <p>An MQTT connection with an in-memory stub transport is used so nothing touches the network (no
 * UDP discovery sockets); an unsecured writer group with a bound source reaches Operational as soon
 * as it is activated.
 */
class StateCounterAttributionEngineTest {

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

  /** In-memory transport that swallows every send; never touches the network. */
  private static final class StubTransport implements TransportProvider {

    @Override
    public String transportProfileUri() {
      return "urn:eclipse:milo:test:state-counter-stub";
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

  private static PublishedDataSetConfig publishedDataSet() {
    return PublishedDataSetConfig.builder("PDS")
        .field(
            FieldDefinition.builder("F1").dataType(NodeIds.Int32).dataSetFieldId(FIELD_ID).build())
        .build();
  }

  private static DataSetSnapshot snapshotOf(PublishedDataSetReadContext context) {
    return DataSetSnapshot.builder(context).field("F1", new DataValue(Variant.ofInt32(42))).build();
  }

  private void startService() throws Exception {
    transportExecutor = Executors.newSingleThreadExecutor();

    MqttConnectionConfig connection =
        MqttConnectionConfig.builder("conn")
            .brokerUri(URI.create("mqtt://localhost:1883"))
            .publisherId(PublisherId.uint16(ushort(1)))
            .writerGroup(
                WriterGroupConfig.builder("WG")
                    .writerGroupId(ushort(1))
                    .publishingInterval(Duration.ofMillis(50))
                    .dataSetWriter(
                        DataSetWriterConfig.builder("W1")
                            .dataSet(new PublishedDataSetRef("PDS"))
                            .dataSetWriterId(ushort(1))
                            .build())
                    .build())
            .build();

    PubSubServiceConfig serviceConfig =
        PubSubServiceConfig.builder()
            .transportProvider(new StubTransport())
            .transportExecutor(transportExecutor)
            .build();

    service =
        PubSubService.create(
            PubSubConfig.builder()
                .publishedDataSet(publishedDataSet())
                .connection(connection)
                .build(),
            PubSubBindings.builder()
                .source(
                    new PublishedDataSetRef("PDS"), StateCounterAttributionEngineTest::snapshotOf)
                .build(),
            serviceConfig);
    service.startup().get(10, TimeUnit.SECONDS);
  }

  private void flushTransport() throws Exception {
    assertNotNull(transportExecutor);
    transportExecutor.submit(() -> {}).get(10, TimeUnit.SECONDS);
  }

  private ComponentDiagnostics diag(String path) {
    ComponentDiagnostics cd = service.diagnostics().snapshot().get(path);
    assertNotNull(cd, path);
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
  void startupAttributesTheOperationalHopToParentForEveryComponent() throws Exception {
    startService();

    // startup drives the whole tree PreOperational (PARENT) then Operational (STARTUP), and the
    // collector attributes the final hop by the remembered PARENT trigger
    for (String path : new String[] {"conn", "conn/WG", "conn/WG/W1"}) {
      assertEquals(1, diag(path).stateOperationalByParent(), path);
      assertEquals(0, diag(path).stateOperationalByMethod(), path);
      // TimeFirstChange is set the moment a counter first leaves 0 on a real transition
      assertTrue(diag(path).timeFirstChange(Counter.STATE_OPERATIONAL_BY_PARENT).isPresent(), path);
    }
    assertTrue(
        diag("conn").timeFirstChange(Counter.STATE_OPERATIONAL_BY_METHOD).isEmpty(),
        "a counter that never left 0 has no TimeFirstChange");
  }

  @Test
  void methodDisablePausesChildrenAndReEnableSplitsTheOperationalCause() throws Exception {
    startService();

    PubSubHandle group = service.components().writerGroup("conn", "WG").orElseThrow();
    awaitTrue("group Operational", () -> service.state(group) == PubSubState.Operational);

    // deltas are asserted rather than absolute counts: startup drives components through transient
    // Paused states (parent not yet Operational) that already tick StatePausedByParent, so only the
    // change caused by the Disable/Enable itself is meaningful
    long wgDisabledBefore = diag("conn/WG").stateDisabledByMethod();
    long wgPausedBefore = diag("conn/WG").statePausedByParent();
    long w1PausedBefore = diag("conn/WG/W1").statePausedByParent();
    long w1DisabledBefore = diag("conn/WG/W1").stateDisabledByMethod();

    // a Method Disable of the group: the group goes Disabled BY METHOD; its writer child is not
    // itself disabled — its parent left Operational, so it Pauses BY PARENT
    service.disable(group);
    flushTransport();
    awaitTrue(
        "group Disabled and writer Paused", () -> service.state(group) == PubSubState.Disabled);

    assertEquals(
        wgDisabledBefore + 1, diag("conn/WG").stateDisabledByMethod(), "group disabled by method");
    assertEquals(
        wgPausedBefore,
        diag("conn/WG").statePausedByParent(),
        "the group went straight to Disabled, not Paused");
    assertEquals(
        w1PausedBefore + 1, diag("conn/WG/W1").statePausedByParent(), "writer paused by parent");
    assertEquals(
        w1DisabledBefore,
        diag("conn/WG/W1").stateDisabledByMethod(),
        "a child cascaded to Paused by its parent is never StateDisabledByMethod");

    long wgOpByMethodBefore = diag("conn/WG").stateOperationalByMethod();
    long w1OpByMethodBefore = diag("conn/WG/W1").stateOperationalByMethod();
    long w1OpByParentBefore = diag("conn/WG/W1").stateOperationalByParent();

    // re-enable by Method: the group's final Operational hop is attributed to Method (its
    // remembered
    // trigger), while its writer child comes back by the parent cascade — the ByMethod/ByParent
    // split on the final hop
    service.enable(group);
    flushTransport();
    awaitTrue("group back Operational", () -> service.state(group) == PubSubState.Operational);
    awaitTrue(
        "writer back Operational",
        () -> diag("conn/WG/W1").stateOperationalByParent() == w1OpByParentBefore + 1);

    assertEquals(
        wgOpByMethodBefore + 1,
        diag("conn/WG").stateOperationalByMethod(),
        "the re-enabled group's final hop is attributed to Method");
    assertEquals(
        w1OpByParentBefore + 1,
        diag("conn/WG/W1").stateOperationalByParent(),
        "the writer returned to Operational by the parent cascade");
    assertEquals(
        w1OpByMethodBefore,
        diag("conn/WG/W1").stateOperationalByMethod(),
        "the writer never had an explicit enable");
  }

  @Test
  void subtreeDisposalOnShutdownIsNotCountedAsAMethodDisable() throws Exception {
    startService();

    // sanity: no Method Disable happened, so StateDisabledByMethod is 0 everywhere
    assertEquals(0, diag("conn/WG").stateDisabledByMethod());

    // shutdown disposes the whole subtree (children first) into Disabled with cause DISPOSE; the
    // diagnostics tree is only unregistered on reconfigure-removal/close, so the snapshot is still
    // readable after shutdown (Part 14 §9.1.11 Q2: a dispose is NOT a Disable Method call)
    service.shutdown().get(10, TimeUnit.SECONDS);

    for (String path : new String[] {"conn", "conn/WG", "conn/WG/W1"}) {
      assertEquals(0, diag(path).stateDisabledByMethod(), path);
    }
  }
}
