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
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import io.netty.buffer.ByteBuf;
import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;
import org.eclipse.milo.opcua.sdk.pubsub.config.DataSetWriterConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.FieldDefinition;
import org.eclipse.milo.opcua.sdk.pubsub.config.MessageSecurityConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.MqttConnectionConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.PubSubConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.PubSubConnectionConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.PublishedDataSetConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.PublishedDataSetRef;
import org.eclipse.milo.opcua.sdk.pubsub.config.PublisherId;
import org.eclipse.milo.opcua.sdk.pubsub.config.SecurityGroupConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.SecurityGroupRef;
import org.eclipse.milo.opcua.sdk.pubsub.config.WriterGroupConfig;
import org.eclipse.milo.opcua.sdk.pubsub.security.PubSubSecurityPolicy;
import org.eclipse.milo.opcua.sdk.pubsub.security.SecurityKeyProvider;
import org.eclipse.milo.opcua.sdk.pubsub.security.SecurityKeySet;
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

/**
 * End-to-end R7 (Part 14 §6.2.12.2) key invalidation driven through {@link
 * PubSubService#invalidateSecurityKeys(SecurityGroupRef)} — the exact call {@code
 * RemoteConfigurationServer} makes after a {@code CloseAndUpdate} changes a SecurityGroup's {@code
 * SecurityPolicyUri} or {@code KeyLifetime}. The scenario is the one the {@code DISABLE_AFFECTED}
 * reconfigure alone misses (documented in the WP-Z-r7 notes): a SINGLE SecurityGroup shared by TWO
 * concurrently-running secured writer groups. Because the two groups restart one-at-a-time, the
 * shared key state never loses all consumers at once and is never disposed, so its window survives;
 * only the explicit invalidate drops it deterministically for both consumers.
 *
 * <p>{@code SecurityGroupInvalidationTest} (server package) pins which SecurityGroup edits trigger
 * the invalidate, and {@code SecurityKeyManagerTest} pins the manager drop/re-fetch in isolation.
 * This test ties the public service API to two live shared consumers over an in-memory stub
 * transport (no network), observing the re-fetch through a fetch-counting {@link
 * SecurityKeyProvider}.
 */
class SharedSecurityGroupInvalidationEndToEndTest {

  private static final SecurityGroupRef SG_REF = new SecurityGroupRef("SG");
  private static final PubSubSecurityPolicy POLICY = PubSubSecurityPolicy.Aes256Ctr;
  private static final UUID FIELD_ID = new UUID(0L, 1L);

  private @Nullable PubSubService service;

  @AfterEach
  void shutdown() throws Exception {
    if (service != null) {
      service.close();
      service = null;
    }
  }

  @Test
  void invalidateDropsAndReFetchesTheSharedWindowForBothConsumers() throws Exception {
    var provider = new CountingKeyProvider(staticKeySet(1));
    startTwoSharedSecuredGroups(provider);

    awaitTrue("both shared writer groups Operational", this::bothGroupsOperational);
    awaitTrue(
        "both shared writer groups publishing", () -> sent("conn/WG1") > 0 && sent("conn/WG2") > 0);

    // both consumers share one key state, so exactly one initial fetch backed both
    int initialFetches = provider.fetchCount.get();
    assertTrue(initialFetches >= 1, "the shared group must have fetched keys");

    // park the re-fetch so the drop is observable, and stage a fresh key stream (a new token, as a
    // changed policy/lifetime would produce) for the groups to recover onto
    var parked = new CompletableFuture<SecurityKeySet>();
    provider.next.set(parked);

    service.invalidateSecurityKeys(SG_REF);

    // §6.2.12.2: the single shared window is dropped and a fresh fetch is issued once — this is the
    // shared-consumer behavior a per-group DISABLE_AFFECTED restart cannot deliver
    awaitTrue(
        "invalidate re-fetches the shared group",
        () -> provider.fetchCount.get() == initialFetches + 1);

    // baselines captured after the drop; a cycle already holding a pre-drop key copy can tick at
    // most once more per group, so a climb of +2 proves genuine recovery, not a straggler
    long baseA = sent("conn/WG1");
    long baseB = sent("conn/WG2");

    // the fresh keys land: BOTH consumers recover onto the new shared window and resume publishing
    parked.complete(staticKeySet(9));
    awaitTrue(
        "both consumers recover on the re-fetched shared keys",
        () -> sent("conn/WG1") >= baseA + 2 && sent("conn/WG2") >= baseB + 2);

    assertTrue(bothGroupsOperational(), "both groups remain Operational across the invalidate");
  }

  @Test
  void invalidatingAnUnrelatedGroupDoesNotDisturbTheLiveSharedGroup() throws Exception {
    var provider = new CountingKeyProvider(staticKeySet(1));
    startTwoSharedSecuredGroups(provider);

    awaitTrue("both shared writer groups Operational", this::bothGroupsOperational);
    awaitTrue(
        "both shared writer groups publishing", () -> sent("conn/WG1") > 0 && sent("conn/WG2") > 0);

    int fetchesBefore = provider.fetchCount.get();
    long baseA = sent("conn/WG1");
    long baseB = sent("conn/WG2");

    // invalidate a SecurityGroup that has no live key state (no consumer references it): a no-op,
    // mirroring the applier skipping a group whose edit did not touch SecurityPolicyUri/KeyLifetime
    service.invalidateSecurityKeys(new SecurityGroupRef("UNRELATED"));

    // both groups keep publishing undisturbed; the unrelated invalidate triggers no fetch
    awaitTrue(
        "both shared groups keep publishing",
        () -> sent("conn/WG1") >= baseA + 2 && sent("conn/WG2") >= baseB + 2);
    assertEquals(
        fetchesBefore, provider.fetchCount.get(), "an unrelated invalidate must not re-fetch");
    assertTrue(bothGroupsOperational());
  }

  // region fixtures

  private boolean bothGroupsOperational() {
    return service.components().writerGroup("conn", "WG1").map(service::state).orElse(null)
            == PubSubState.Operational
        && service.components().writerGroup("conn", "WG2").map(service::state).orElse(null)
            == PubSubState.Operational;
  }

  private long sent(String path) {
    PubSubDiagnostics.ComponentDiagnostics cd = service.diagnostics().snapshot().get(path);
    return cd == null ? 0L : cd.networkMessagesSent();
  }

  private void startTwoSharedSecuredGroups(SecurityKeyProvider provider) throws Exception {
    PublishedDataSetConfig dataSet =
        PublishedDataSetConfig.builder("PDS")
            .field(
                FieldDefinition.builder("F1")
                    .dataType(NodeIds.Int32)
                    .dataSetFieldId(FIELD_ID)
                    .build())
            .build();

    MqttConnectionConfig connection =
        MqttConnectionConfig.builder("conn")
            .brokerUri(URI.create("mqtt://localhost:1883"))
            .publisherId(PublisherId.uint16(ushort(1)))
            .writerGroup(securedGroup("WG1", 1))
            .writerGroup(securedGroup("WG2", 2))
            .build();

    PubSubConfig config =
        PubSubConfig.builder()
            .publishedDataSet(dataSet)
            .securityGroup(SecurityGroupConfig.builder("SG").build())
            .connection(connection)
            .build();

    PubSubBindings bindings =
        PubSubBindings.builder()
            .source(dataSet.ref(), SharedSecurityGroupInvalidationEndToEndTest::snapshotOf)
            .securityKeys(SG_REF, provider)
            .build();

    PubSubServiceConfig serviceConfig =
        PubSubServiceConfig.builder().transportProvider(new StubTransport()).build();

    service = PubSubService.create(config, bindings, serviceConfig);
    service.startup().get(10, TimeUnit.SECONDS);
  }

  /** A secured writer group referencing the shared SecurityGroup, publishing every 25 ms. */
  private static WriterGroupConfig securedGroup(String name, int writerId) {
    return WriterGroupConfig.builder(name)
        .writerGroupId(ushort(writerId))
        .publishingInterval(Duration.ofMillis(25))
        .messageSecurity(
            MessageSecurityConfig.builder()
                .mode(MessageSecurityMode.Sign)
                .securityGroup(SG_REF)
                .build())
        .dataSetWriter(
            DataSetWriterConfig.builder("W" + writerId)
                .dataSet(new PublishedDataSetRef("PDS"))
                .dataSetWriterId(ushort(writerId))
                .build())
        .build();
  }

  private static DataSetSnapshot snapshotOf(PublishedDataSetReadContext context) {
    return DataSetSnapshot.builder(context).field("F1", new DataValue(Variant.ofInt32(42))).build();
  }

  /**
   * A non-rotating, non-expiring single-key set for {@link #POLICY} at the given first token id.
   */
  private static SecurityKeySet staticKeySet(long firstTokenId) {
    byte[] key = new byte[POLICY.getKeyDataLength()];
    for (int i = 0; i < key.length; i++) {
      key[i] = (byte) (firstTokenId + i);
    }
    return new SecurityKeySet(
        POLICY.getUri(),
        uint(firstTokenId),
        List.of(ByteString.of(key)),
        Duration.ZERO,
        Duration.ZERO);
  }

  private void awaitTrue(String description, BooleanSupplier condition)
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

  /** A provider serving a settable key set and counting every fetch. */
  private static final class CountingKeyProvider implements SecurityKeyProvider {

    final AtomicInteger fetchCount = new AtomicInteger();
    final AtomicReference<CompletableFuture<SecurityKeySet>> next;

    CountingKeyProvider(SecurityKeySet initial) {
      this.next = new AtomicReference<>(CompletableFuture.completedFuture(initial));
    }

    @Override
    public CompletableFuture<SecurityKeySet> getKeys(
        String securityGroupId, UInteger startingTokenId, UInteger requestedKeyCount) {
      fetchCount.incrementAndGet();
      return next.get();
    }
  }

  /** In-memory transport that swallows every send; never touches the network. */
  private static final class StubTransport implements TransportProvider {

    @Override
    public String transportProfileUri() {
      return "urn:eclipse:milo:test:shared-sg-stub";
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

  // endregion
}
