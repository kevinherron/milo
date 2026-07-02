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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import io.netty.buffer.ByteBuf;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.AbstractExecutorService;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubBindings;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubHandle;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubService;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubServiceConfig;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubStateChangeEvent;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubStateListener;
import org.eclipse.milo.opcua.sdk.pubsub.config.DataSetReaderConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.PubSubConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.PubSubConnectionConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.ReaderGroupConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.UdpConnectionConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.UdpDatagramAddress;
import org.eclipse.milo.opcua.sdk.pubsub.transport.PublisherChannel;
import org.eclipse.milo.opcua.sdk.pubsub.transport.PublisherTransportContext;
import org.eclipse.milo.opcua.sdk.pubsub.transport.SubscriberChannel;
import org.eclipse.milo.opcua.sdk.pubsub.transport.SubscriberTransportContext;
import org.eclipse.milo.opcua.sdk.pubsub.transport.TransportProvider;
import org.eclipse.milo.opcua.sdk.pubsub.transport.TransportStateListener;
import org.eclipse.milo.opcua.stack.core.types.enumerated.PubSubState;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * Tests the R16 transport-state to {@code PubSubState} mapping through a fake transport-state
 * source (a stub transport that captures the {@link TransportStateListener} the engine hands it in
 * the open context) and the R12 listener-removal API. The connection uses an in-memory stub
 * transport for its data channels, so nothing touches the network.
 */
class TransportStateMappingTest {

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

  /**
   * A stub transport that captures the engine's transport-state listener; never touches network.
   */
  private static final class ListenerCapturingTransport implements TransportProvider {

    final AtomicReference<TransportStateListener> listener = new AtomicReference<>();

    @Override
    public String transportProfileUri() {
      return "urn:eclipse:milo:test:transport-state-stub";
    }

    @Override
    public boolean supports(PubSubConnectionConfig connection) {
      return true;
    }

    @Override
    public PublisherChannel openPublisher(PublisherTransportContext context) {
      capture(context.transportStateListener());
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
      capture(context.transportStateListener());
      return () -> CompletableFuture.completedFuture(null);
    }

    private void capture(@Nullable TransportStateListener l) {
      if (l != null) {
        listener.set(l);
      }
    }

    TransportStateListener listener() {
      TransportStateListener l = listener.get();
      assertNotNull(l, "the engine did not supply a transport-state listener");
      return l;
    }
  }

  private ListenerCapturingTransport startReaderService() throws Exception {
    return startReaderService(Executors.newSingleThreadExecutor());
  }

  private ListenerCapturingTransport startReaderService(ExecutorService executor) throws Exception {
    var transport = new ListenerCapturingTransport();
    transportExecutor = executor;

    // UDP connection, no writer groups and a default (REQUIRE_CONFIGURED) reader: no discovery
    // sockets are opened, and the stub transport serves the data subscriber channel
    UdpConnectionConfig connection =
        UdpConnectionConfig.builder("conn")
            .address(UdpDatagramAddress.unicast("127.0.0.1", 14841))
            .readerGroup(
                ReaderGroupConfig.builder("RG")
                    .dataSetReader(DataSetReaderConfig.builder("R1").build())
                    .build())
            .build();

    PubSubServiceConfig serviceConfig =
        PubSubServiceConfig.builder()
            .transportProvider(transport)
            .transportExecutor(transportExecutor)
            .build();

    service =
        PubSubService.create(
            PubSubConfig.builder().connection(connection).build(),
            PubSubBindings.builder().build(),
            serviceConfig);
    service.startup().get(10, TimeUnit.SECONDS);

    return transport;
  }

  private void flushTransport() throws Exception {
    assertNotNull(transportExecutor);
    transportExecutor.submit(() -> {}).get(10, TimeUnit.SECONDS);
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
  void transportDisconnectFailsConnectionAndReconnectRecoversIt() throws Exception {
    ListenerCapturingTransport transport = startReaderService();

    PubSubHandle conn = service.components().connection("conn").orElseThrow();
    PubSubHandle group = service.components().readerGroup("conn", "RG").orElseThrow();
    PubSubHandle reader = service.components().dataSetReader("conn", "RG", "R1").orElseThrow();

    assertEquals(PubSubState.Operational, service.state(conn));
    assertEquals(PubSubState.Operational, service.state(group));
    assertEquals(PubSubState.PreOperational, service.state(reader));

    // broker disconnect: the connection fails into Error, cascading its children to Paused
    transport.listener().onDisconnected();
    flushTransport();

    assertEquals(PubSubState.Error, service.state(conn));
    assertEquals(PubSubState.Paused, service.state(group));
    assertEquals(PubSubState.Paused, service.state(reader));
    assertEquals(1, service.diagnostics().snapshot().get("conn").stateError());

    // a repeat disconnect while already in Error is a no-op
    transport.listener().onDisconnected();
    flushTransport();
    assertEquals(1, service.diagnostics().snapshot().get("conn").stateError());

    // reconnect: the connection recovers to Operational and its children re-activate
    transport.listener().onConnected();
    flushTransport();

    assertEquals(PubSubState.Operational, service.state(conn));
    assertEquals(PubSubState.Operational, service.state(group));
    assertEquals(PubSubState.PreOperational, service.state(reader));
    assertEquals(1, service.diagnostics().snapshot().get("conn").stateOperationalFromError());
  }

  /**
   * Regression guard for the R16 disconnect/reconnect ordering race: when the transport executor
   * reorders two independently-submitted callbacks (as the default multi-threaded {@code
   * Stack.sharedExecutor()} may), the engine must still apply an in-order disconnect+reconnect pair
   * so the connection ends in the state that reflects actual connectivity (Operational), not
   * whichever of {@code fail()}/{@code recover()} happened to win the executor race. The engine
   * guarantees this by serializing both callbacks through the per-connection FIFO dispatch queue;
   * without that serialization a reordered {@code recover()} (no-op while Operational) followed by
   * {@code fail()} would wedge the connection in {@code Error} despite a healthy transport.
   */
  @Test
  void disconnectThenReconnectResolvesToOperationalUnderExecutorReordering() throws Exception {
    var executor = new ReorderingExecutor();
    ListenerCapturingTransport transport = startReaderService(executor);

    PubSubHandle conn = service.components().connection("conn").orElseThrow();
    assertEquals(PubSubState.Operational, service.state(conn));

    // onDisconnected then onConnected fire in order on the transport event loop; the executor is
    // armed to replay whatever it receives in REVERSE order, simulating a shared-pool reordering
    executor.arm();
    transport.listener().onDisconnected();
    transport.listener().onConnected();
    executor.drainReversed();
    flushTransport();

    assertEquals(
        PubSubState.Operational,
        service.state(conn),
        "an in-order disconnect+reconnect must resolve to Operational even when the transport"
            + " executor reorders the two submissions");
  }

  /**
   * An {@link ExecutorService} that, once {@link #arm()}ed, buffers submitted tasks instead of
   * running them and later replays the buffer in REVERSE submission order via {@link
   * #drainReversed()} — a deterministic stand-in for a multi-threaded executor that runs two
   * independently-submitted tasks out of order. While disarmed it runs tasks on a backing
   * single-threaded executor so service startup and {@code flushTransport()} behave normally.
   */
  private static final class ReorderingExecutor extends AbstractExecutorService {

    private final ExecutorService delegate = Executors.newSingleThreadExecutor();
    private final List<Runnable> buffered = new ArrayList<>();
    private volatile boolean armed = false;

    void arm() {
      armed = true;
    }

    /** Disarm, then run the buffered tasks in reverse submission order on the calling thread. */
    void drainReversed() {
      List<Runnable> tasks;
      synchronized (buffered) {
        armed = false;
        tasks = new ArrayList<>(buffered);
        buffered.clear();
      }
      for (int i = tasks.size() - 1; i >= 0; i--) {
        tasks.get(i).run();
      }
    }

    @Override
    public void execute(Runnable command) {
      synchronized (buffered) {
        if (armed) {
          buffered.add(command);
          return;
        }
      }
      delegate.execute(command);
    }

    @Override
    public void shutdown() {
      delegate.shutdown();
    }

    @Override
    public List<Runnable> shutdownNow() {
      return delegate.shutdownNow();
    }

    @Override
    public boolean isShutdown() {
      return delegate.isShutdown();
    }

    @Override
    public boolean isTerminated() {
      return delegate.isTerminated();
    }

    @Override
    public boolean awaitTermination(long timeout, TimeUnit unit) throws InterruptedException {
      return delegate.awaitTermination(timeout, unit);
    }
  }

  @Test
  void removeStateListenerStopsDeliveries() throws Exception {
    startReaderService();

    var removed = new CopyOnWriteArrayList<PubSubStateChangeEvent>();
    var kept = new CopyOnWriteArrayList<PubSubStateChangeEvent>();
    PubSubStateListener removedListener = removed::add;
    PubSubStateListener keptListener = kept::add;

    service.addStateListener(removedListener);
    service.addStateListener(keptListener);
    service.removeStateListener(removedListener);

    PubSubHandle group = service.components().readerGroup("conn", "RG").orElseThrow();
    service.disable(group);

    awaitTrue("kept listener to receive the disable transition", () -> !kept.isEmpty());
    flushTransport();

    assertTrue(removed.isEmpty(), "a removed state listener must not receive events");
    assertTrue(kept.stream().anyMatch(e -> e.newState() == PubSubState.Disabled));
  }
}
