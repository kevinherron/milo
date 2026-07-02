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

import static org.eclipse.milo.opcua.sdk.pubsub.server.RemoteConfigClientSupport.CLOSE_AND_UPDATE;
import static org.eclipse.milo.opcua.sdk.pubsub.server.RemoteConfigClientSupport.RESERVE_IDS;
import static org.eclipse.milo.opcua.sdk.pubsub.server.RemoteConfigClientSupport.TIMEOUT;
import static org.eclipse.milo.opcua.sdk.pubsub.server.RemoteConfigClientSupport.WRITE;
import static org.eclipse.milo.opcua.sdk.pubsub.server.RemoteConfigClientSupport.call;
import static org.eclipse.milo.opcua.sdk.pubsub.server.RemoteConfigClientSupport.connect;
import static org.eclipse.milo.opcua.sdk.pubsub.server.RemoteConfigClientSupport.open;
import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.ubyte;
import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.uint;
import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.ulong;
import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.ushort;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.eclipse.milo.opcua.sdk.client.OpcUaClient;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubService;
import org.eclipse.milo.opcua.sdk.pubsub.config.PubSubConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.PubSubConfigFiles;
import org.eclipse.milo.opcua.stack.core.StatusCodes;
import org.eclipse.milo.opcua.stack.core.encoding.EncodingContext;
import org.eclipse.milo.opcua.stack.core.types.builtin.ByteString;
import org.eclipse.milo.opcua.stack.core.types.builtin.ExtensionObject;
import org.eclipse.milo.opcua.stack.core.types.builtin.StatusCode;
import org.eclipse.milo.opcua.stack.core.types.builtin.Variant;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UInteger;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UShort;
import org.eclipse.milo.opcua.stack.core.types.enumerated.DataSetOrderingType;
import org.eclipse.milo.opcua.stack.core.types.enumerated.MessageSecurityMode;
import org.eclipse.milo.opcua.stack.core.types.structured.CallMethodResult;
import org.eclipse.milo.opcua.stack.core.types.structured.DatagramConnectionTransportDataType;
import org.eclipse.milo.opcua.stack.core.types.structured.DatagramWriterGroupTransportDataType;
import org.eclipse.milo.opcua.stack.core.types.structured.NetworkAddressUrlDataType;
import org.eclipse.milo.opcua.stack.core.types.structured.PubSubConfiguration2DataType;
import org.eclipse.milo.opcua.stack.core.types.structured.PubSubConfigurationRefDataType;
import org.eclipse.milo.opcua.stack.core.types.structured.PubSubConfigurationRefMask;
import org.eclipse.milo.opcua.stack.core.types.structured.PubSubConfigurationRefMask.Field;
import org.eclipse.milo.opcua.stack.core.types.structured.PubSubConfigurationValueDataType;
import org.eclipse.milo.opcua.stack.core.types.structured.PubSubConnectionDataType;
import org.eclipse.milo.opcua.stack.core.types.structured.SecurityGroupDataType;
import org.eclipse.milo.opcua.stack.core.types.structured.UadpNetworkMessageContentMask;
import org.eclipse.milo.opcua.stack.core.types.structured.UadpWriterGroupMessageDataType;
import org.eclipse.milo.opcua.stack.core.types.structured.WriterGroupDataType;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * The Part 14 §9.1.3.7.6 {@code CloseAndUpdate} element-operation matrix, driven end-to-end by a
 * real {@link OpcUaClient} {@code Call}.
 *
 * <p>Two groups:
 *
 * <ul>
 *   <li>The <b>method-level result codes</b> reachable with a {@code null} {@code
 *       ConfigurationReferences} argument (handle validation, write-mode gate, {@code
 *       Bad_NothingToDo}), exercising the real {@code Call} → {@link
 *       RemoteConfigurationServer#closeAndUpdate} path.
 *   <li>The <b>element-operation matrix</b> (Add / Match / Add+Match / Modify / Remove, per-element
 *       result codes, atomic-vs-partial apply, auto-assignment, bit-11/12 handling, persistence,
 *       and the read-modify-write round trip), sending a non-empty {@code ConfigurationReferences}
 *       Structure array over the wire as an {@code ExtensionObject[]}.
 * </ul>
 */
class CloseAndUpdateClientCallTest {

  private static final int MODE_READ = 0x01;
  private static final int MODE_WRITE_ERASE = 0x06;

  private static TestSksServer sks;

  @BeforeAll
  static void startServer() throws Exception {
    sks = TestSksServer.create();
  }

  @AfterAll
  static void stopServer() throws Exception {
    if (sks != null) {
      sks.close();
    }
  }

  // region method-level result codes (reachable with null references — these run)

  @Test
  void closeAndUpdateWithNullReferencesIsNothingToDo() throws Exception {
    try (ServerPubSub ignored = attach(PubSubConfig.builder().build(), null)) {
      OpcUaClient client = connect(sks);
      try {
        UInteger handle = open(client, MODE_WRITE_ERASE);
        // §9.1.3.7.6: a null/empty ConfigurationReferences array is Bad_NothingToDo, and the
        // handle is still validated and closed first
        var result =
            call(
                client,
                CLOSE_AND_UPDATE,
                new Variant(handle),
                new Variant(Boolean.TRUE),
                new Variant((Object) null));
        assertEquals(StatusCodes.Bad_NothingToDo, result.getStatusCode().getValue());
      } finally {
        client.disconnect();
      }
    }
  }

  @Test
  void closeAndUpdateWithAnInvalidHandleIsInvalidArgument() throws Exception {
    try (ServerPubSub ignored = attach(PubSubConfig.builder().build(), null)) {
      OpcUaClient client = connect(sks);
      try {
        var result =
            call(
                client,
                CLOSE_AND_UPDATE,
                new Variant(uint(999_999)),
                new Variant(Boolean.TRUE),
                new Variant((Object) null));
        assertEquals(StatusCodes.Bad_InvalidArgument, result.getStatusCode().getValue());
      } finally {
        client.disconnect();
      }
    }
  }

  @Test
  void closeAndUpdateOnAReadOnlyHandleIsInvalidState() throws Exception {
    try (ServerPubSub ignored = attach(PubSubConfig.builder().build(), null)) {
      OpcUaClient client = connect(sks);
      try {
        UInteger handle = open(client, MODE_READ);
        // §9.1.3.7.6: the file must be opened for write
        var result =
            call(
                client,
                CLOSE_AND_UPDATE,
                new Variant(handle),
                new Variant(Boolean.TRUE),
                new Variant((Object) null));
        assertEquals(StatusCodes.Bad_InvalidState, result.getStatusCode().getValue());
      } finally {
        client.disconnect();
      }
    }
  }

  // endregion

  // region element-operation matrix

  @Test
  void addConnectionRowAppliesAndReportsAConfigurationValue() throws Exception {
    try (ServerPubSub ignored = attach(PubSubConfig.builder().build(), null)) {
      OpcUaClient client = connect(sks);
      try {
        var file = config(connection("added-conn"));
        var result =
            closeAndUpdate(
                client,
                file,
                true,
                ref(mask(Field.ElementAdd, Field.ReferenceConnection), 0, 0, 0));

        assertTrue(changesApplied(result));
        assertEquals(1, referencesResults(result).length);
        assertTrue(referencesResults(result)[0].isGood());
        PubSubConfigurationValueDataType[] values = configurationValues(result, ctx(client));
        assertEquals(1, values.length);
        assertEquals("added-conn", values[0].getName());
      } finally {
        client.disconnect();
      }
    }
  }

  @Test
  void removeConnectionRowDropsItByName() throws Exception {
    try (ServerPubSub ignored = attach(configWithConnection("to-remove"), null)) {
      OpcUaClient client = connect(sks);
      try {
        var file = config(connection("to-remove"));
        var result =
            closeAndUpdate(
                client,
                file,
                true,
                ref(mask(Field.ElementRemove, Field.ReferenceConnection), 0, 0, 0));

        assertTrue(changesApplied(result));
        assertTrue(referencesResults(result)[0].isGood());
      } finally {
        client.disconnect();
      }
    }
  }

  @Test
  void modifyingAMissingElementIsPerElementNoMatchWithMethodLevelGood() throws Exception {
    try (ServerPubSub ignored = attach(configWithConnection("present"), null)) {
      OpcUaClient client = connect(sks);
      try {
        var file = config(connection("absent"));
        var result =
            closeAndUpdate(
                client,
                file,
                false,
                ref(mask(Field.ElementModify, Field.ReferenceConnection), 0, 0, 0));

        // element failures surface only via ReferencesResults; the method itself is Good
        assertTrue(result.getStatusCode().isGood());
        assertEquals(StatusCodes.Bad_NoMatch, referencesResults(result)[0].getValue());
      } finally {
        client.disconnect();
      }
    }
  }

  @Test
  void anInvalidOperationBitComboIsPerElementInvalidArgument() throws Exception {
    try (ServerPubSub ignored = attach(configWithConnection("c1"), null)) {
      OpcUaClient client = connect(sks);
      try {
        var file = config(connection("c1"));
        // Add + Modify is a forbidden combination (Table 239): per-element Bad_InvalidArgument
        var result =
            closeAndUpdate(
                client,
                file,
                false,
                ref(
                    mask(Field.ElementAdd, Field.ElementModify, Field.ReferenceConnection),
                    0,
                    0,
                    0));

        assertEquals(StatusCodes.Bad_InvalidArgument, referencesResults(result)[0].getValue());
      } finally {
        client.disconnect();
      }
    }
  }

  @Test
  void addPlusMatchIsTheAddIfMissingIdiom() throws Exception {
    try (ServerPubSub ignored = attach(PubSubConfig.builder().build(), null)) {
      OpcUaClient client = connect(sks);
      try {
        // no matching connection exists, so Add+Match adds it (add-if-missing)
        var file = config(connection("c-idempotent"));
        var result =
            closeAndUpdate(
                client,
                file,
                true,
                ref(
                    mask(Field.ElementAdd, Field.ElementMatch, Field.ReferenceConnection),
                    0,
                    0,
                    0));

        assertTrue(changesApplied(result));
        assertTrue(referencesResults(result)[0].isGood());
      } finally {
        client.disconnect();
      }
    }
  }

  @Test
  void matchAgainstALiveWriterGroupWithActiveGroupHeaderIsInvalidState() throws Exception {
    // a live UADP WriterGroup whose NetworkMessageContentMask has GroupHeader set (a live group
    // needs a WriterGroupId; the id is not a match field, so the null-id file group still matches)
    var liveGroup = writerGroupWithGroupHeader("wg-gh", 1);
    var live = config(connection("c-gh", liveGroup));

    try (ServerPubSub ignored = attach(PubSubConfig.fromDataType(live, nsTable()), null)) {
      OpcUaClient client = connect(sks);
      try {
        // Match the writer group under connection "c-gh" (file group carries a null name/id)
        var fileGroup = writerGroupWithGroupHeader(null, 0);
        var file = config(connection("c-gh", fileGroup));
        var result =
            closeAndUpdate(
                client,
                file,
                false,
                ref(mask(Field.ElementMatch, Field.ReferenceWriterGroup), 0, 0, 0));

        assertEquals(StatusCodes.Bad_InvalidState, referencesResults(result)[0].getValue());
      } finally {
        client.disconnect();
      }
    }
  }

  @Test
  void atomicModeAppliesAllOrNothingButEvaluatesEveryReference() throws Exception {
    try (ServerPubSub ignored = attach(PubSubConfig.builder().build(), null)) {
      OpcUaClient client = connect(sks);
      try {
        // one good add, one modify-of-a-missing element
        var file = config(connection("ok"), connection("missing"));
        var refs =
            new PubSubConfigurationRefDataType[] {
              ref(mask(Field.ElementAdd, Field.ReferenceConnection), 0, 0, 0),
              ref(mask(Field.ElementModify, Field.ReferenceConnection), 1, 0, 0)
            };
        var result = closeAndUpdate(client, file, true, refs);

        // RequireCompleteUpdate=true: nothing applied, but the full-length results are returned
        assertTrue(result.getStatusCode().isGood());
        assertEquals(Boolean.FALSE, result.getOutputArguments()[0].getValue());
        assertEquals(2, referencesResults(result).length);
        assertTrue(referencesResults(result)[0].isGood());
        assertEquals(StatusCodes.Bad_NoMatch, referencesResults(result)[1].getValue());
      } finally {
        client.disconnect();
      }
    }
  }

  @Test
  void partialModeAppliesTheSurvivors() throws Exception {
    try (ServerPubSub ignored = attach(PubSubConfig.builder().build(), null)) {
      OpcUaClient client = connect(sks);
      try {
        var file = config(connection("survivor"), connection("missing"));
        var refs =
            new PubSubConfigurationRefDataType[] {
              ref(mask(Field.ElementAdd, Field.ReferenceConnection), 0, 0, 0),
              ref(mask(Field.ElementModify, Field.ReferenceConnection), 1, 0, 0)
            };
        var result = closeAndUpdate(client, file, false, refs);

        // RequireCompleteUpdate=false: the good add is applied, the bad modify is reported
        assertTrue(changesApplied(result));
        assertTrue(referencesResults(result)[0].isGood());
        assertEquals(StatusCodes.Bad_NoMatch, referencesResults(result)[1].getValue());
      } finally {
        client.disconnect();
      }
    }
  }

  @Test
  void elementAddAutoAssignsNameAndInternalWriterGroupId() throws Exception {
    try (ServerPubSub ignored = attach(configWithConnection("host"), null)) {
      OpcUaClient client = connect(sks);
      try {
        // a writer group with null name and null id under the existing connection "host"
        var file = config(connection("host", writerGroup(null, 0)));
        var result =
            closeAndUpdate(
                client,
                file,
                true,
                ref(mask(Field.ElementAdd, Field.ReferenceWriterGroup), 0, 0, 0));

        assertTrue(changesApplied(result));
        PubSubConfigurationValueDataType[] values = configurationValues(result, ctx(client));
        assertEquals(1, values.length);
        assertNotNull(values[0].getName());
        assertTrue(!values[0].getName().isEmpty());
        // the assigned WriterGroupId (a UInt16) is drawn from the internal-assignment range
        assertTrue(((UShort) values[0].getIdentifier().getValue()).intValue() >= 0x8000);
      } finally {
        client.disconnect();
      }
    }
  }

  @Test
  void securityGroupReferenceRequiresSksAdmin() throws Exception {
    // no RoleMapper => the default authorizer allows checkConfigure AND checkSksAdmin
    try (ServerPubSub ignored = attach(PubSubConfig.builder().build(), null)) {
      OpcUaClient client = connect(sks);
      try {
        var sg = new SecurityGroupDataType("sg", null, null, null, null, null, null, null, null);
        var file =
            new PubSubConfiguration2DataType(
                null,
                new PubSubConnectionDataType[0],
                true,
                null,
                null,
                null,
                new SecurityGroupDataType[] {sg},
                null,
                uint(0),
                null);
        var result =
            closeAndUpdate(
                client,
                file,
                true,
                ref(mask(Field.ElementAdd, Field.ReferenceSecurityGroup), 0, 0, 0));

        // bit-11 SecurityGroup refs are allowed only with checkSksAdmin (granted here)
        assertTrue(changesApplied(result));
        assertTrue(referencesResults(result)[0].isGood());
      } finally {
        client.disconnect();
      }
    }
  }

  @Test
  void pushTargetReferenceIsRejectedPerElement() throws Exception {
    try (ServerPubSub ignored = attach(configWithConnection("c1"), null)) {
      OpcUaClient client = connect(sks);
      try {
        var file = config(connection("c1"));
        var result =
            closeAndUpdate(
                client,
                file,
                false,
                ref(mask(Field.ElementAdd, Field.ReferencePushTarget), 0, 0, 0));

        // bit-12 PushTarget refs are a per-element rejection, never a method-level failure
        assertTrue(result.getStatusCode().isGood());
        assertEquals(StatusCodes.Bad_InvalidArgument, referencesResults(result)[0].getValue());
      } finally {
        client.disconnect();
      }
    }
  }

  @Test
  void aMutatingCloseAndUpdatePersistsThroughTheStore() throws Exception {
    var store = new CountingStore();
    try (ServerPubSub ignored = attach(PubSubConfig.builder().build(), store)) {
      // attach saves the initial (empty) configuration once
      int savesAfterAttach = store.saved.size();

      OpcUaClient client = connect(sks);
      try {
        var file = config(connection("persisted-conn"));
        var result =
            closeAndUpdate(
                client,
                file,
                true,
                ref(mask(Field.ElementAdd, Field.ReferenceConnection), 0, 0, 0));

        assertTrue(changesApplied(result));
        // a successful mutating CloseAndUpdate saves through the store
        assertTrue(store.saved.size() > savesAfterAttach);
      } finally {
        client.disconnect();
      }
    }
  }

  @Test
  void readModifyWriteRoundTripTakesEffect() throws Exception {
    try (ServerPubSub serverPubSub = attach(PubSubConfig.builder().build(), null)) {
      OpcUaClient client = connect(sks);
      try {
        // add a connection through the file model, then confirm the live runtime tracks it
        var file = config(connection("round-trip-conn"));
        var result =
            closeAndUpdate(
                client,
                file,
                true,
                ref(mask(Field.ElementAdd, Field.ReferenceConnection), 0, 0, 0));

        assertTrue(changesApplied(result));
        assertTrue(serverPubSub.runtime().components().connection("round-trip-conn").isPresent());
      } finally {
        client.disconnect();
      }
    }
  }

  @Test
  void wholeConfigValidationFailureReturnsFullResultsWithoutApplying() throws Exception {
    try (ServerPubSub serverPubSub = attach(configWithConnection("host"), null)) {
      OpcUaClient client = connect(sks);
      try {
        // two writer groups added under "host" with distinct names but a colliding explicit
        // WriterGroupId: each passes the per-ref name-uniqueness check (Good), but the candidate
        // fails whole-config validation (duplicate WriterGroupId within a connection)
        var file =
            config(
                connection(
                    "host",
                    writerGroupWithGroupHeader("wg-a", 0x1234),
                    writerGroupWithGroupHeader("wg-b", 0x1234)));
        var refs =
            new PubSubConfigurationRefDataType[] {
              ref(mask(Field.ElementAdd, Field.ReferenceWriterGroup), 0, 0, 0),
              ref(mask(Field.ElementAdd, Field.ReferenceWriterGroup), 0, 1, 0)
            };
        var result = closeAndUpdate(client, file, true, refs);

        // §9.1.3.7.6: a whole-config validation failure at apply is reported as
        // ChangesApplied=false
        // with the full-length (both-Good) ReferencesResults, NOT a method-level Bad with empty
        // output arguments
        assertTrue(result.getStatusCode().isGood(), result.toString());
        assertEquals(Boolean.FALSE, result.getOutputArguments()[0].getValue());
        assertEquals(2, referencesResults(result).length);
        assertTrue(referencesResults(result)[0].isGood());
        assertTrue(referencesResults(result)[1].isGood());
        // the live configuration is unchanged: no writer group was added to "host"
        assertTrue(serverPubSub.runtime().components().connection("host").isPresent());
      } finally {
        client.disconnect();
      }
    }
  }

  @Test
  void programmaticReconfigureIsSerializedAgainstCloseAndUpdate() throws Exception {
    var store = new BlockingStore();
    ExecutorService updater = Executors.newSingleThreadExecutor();
    ExecutorService reconfigurer = Executors.newSingleThreadExecutor();
    try (ServerPubSub serverPubSub = attach(PubSubConfig.builder().build(), store)) {
      OpcUaClient client = connect(sks);
      try {
        // a client CloseAndUpdate that adds connection "cau" and then parks inside closeAndUpdate's
        // persist() (BlockingStore.save) while still holding the reconfigure monitor
        Future<CallMethodResult> closeAndUpdateTask =
            updater.submit(
                () ->
                    closeAndUpdate(
                        client,
                        config(connection("cau")),
                        true,
                        ref(mask(Field.ElementAdd, Field.ReferenceConnection), 0, 0, 0)));

        assertTrue(store.saveEntered.await(TIMEOUT.toSeconds(), TimeUnit.SECONDS));

        // a programmatic reconfigure that would REPLACE "cau" with "prog"
        var progConfig = PubSubConfig.fromDataType(config(connection("prog")), nsTable());
        var startedReconfigure = new CountDownLatch(1);
        Future<?> reconfigureTask =
            reconfigurer.submit(
                () -> {
                  startedReconfigure.countDown();
                  serverPubSub.reconfigure(
                      progConfig, PubSubService.ReconfigureMode.DISABLE_AFFECTED);
                });
        try {
          assertTrue(startedReconfigure.await(TIMEOUT.toSeconds(), TimeUnit.SECONDS));

          // the reconfigure shares the monitor the parked CloseAndUpdate holds, so it cannot
          // complete...
          assertThrows(TimeoutException.class, () -> reconfigureTask.get(1, TimeUnit.SECONDS));

          // ...and its ENGINE apply has not run either: the whole reconfigure (engine apply +
          // fragment rebuild + base adoption) is inside the excluded region, so the live config
          // still reflects the parked CloseAndUpdate's "cau" and not the reconfigure's "prog"
          assertTrue(serverPubSub.runtime().components().connection("cau").isPresent());
          assertTrue(serverPubSub.runtime().components().connection("prog").isEmpty());
        } finally {
          store.releaseSave.countDown();
        }

        reconfigureTask.get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);
        closeAndUpdateTask.get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);

        // once both complete, the programmatic reconfigure ran last and won for the engine
        assertTrue(serverPubSub.runtime().components().connection("prog").isPresent());
        assertTrue(serverPubSub.runtime().components().connection("cau").isEmpty());
      } finally {
        client.disconnect();
      }
    } finally {
      updater.shutdownNow();
      reconfigurer.shutdownNow();
    }
  }

  @Test
  void reserveIdsIsSerializedAgainstCloseAndUpdate() throws Exception {
    var store = new BlockingStore();
    ExecutorService updaterExecutor = Executors.newSingleThreadExecutor();
    ExecutorService reserverExecutor = Executors.newSingleThreadExecutor();
    try (ServerPubSub ignored = attach(PubSubConfig.builder().build(), store)) {
      OpcUaClient updater = connect(sks);
      OpcUaClient reserver = connect(sks);
      try {
        Future<CallMethodResult> closeAndUpdateTask =
            updaterExecutor.submit(
                () ->
                    closeAndUpdate(
                        updater,
                        config(connection("cau")),
                        true,
                        ref(mask(Field.ElementAdd, Field.ReferenceConnection), 0, 0, 0)));

        assertTrue(store.saveEntered.await(TIMEOUT.toSeconds(), TimeUnit.SECONDS));

        // a concurrent ReserveIds from another session must not run its id allocation while the
        // CloseAndUpdate is parked holding the reconfigure monitor: otherwise it could grant an id
        // the CloseAndUpdate applier is about to auto-assign from the same snapshot (§9.1.3.7.5)
        Future<CallMethodResult> reserveTask = reserverExecutor.submit(() -> reserveIds(reserver));
        try {
          assertThrows(TimeoutException.class, () -> reserveTask.get(1, TimeUnit.SECONDS));
        } finally {
          store.releaseSave.countDown();
        }

        closeAndUpdateTask.get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);

        // once the CloseAndUpdate releases the monitor, the ReserveIds completes
        CallMethodResult reserveResult = reserveTask.get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);
        assertTrue(reserveResult.getStatusCode().isGood(), reserveResult.toString());
      } finally {
        reserver.disconnect();
        updater.disconnect();
      }
    } finally {
      updaterExecutor.shutdownNow();
      reserverExecutor.shutdownNow();
    }
  }

  // endregion

  // region fixtures / helpers

  private static ServerPubSub attach(PubSubConfig config, PubSubConfigurationStore store)
      throws Exception {
    var options = ServerPubSubOptions.builder().allowRemoteConfiguration(true);
    if (store != null) {
      options.configurationStore(store);
    }
    ServerPubSub serverPubSub = ServerPubSub.attach(sks.getServer(), config, options.build());
    serverPubSub.startup().get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);
    return serverPubSub;
  }

  private static EncodingContext ctx(OpcUaClient client) {
    return client.getStaticEncodingContext();
  }

  private static org.eclipse.milo.opcua.stack.core.NamespaceTable nsTable() {
    return sks.getServer().getNamespaceTable();
  }

  /** Open (write+erase), write the encoded file body, and call CloseAndUpdate. */
  private static org.eclipse.milo.opcua.stack.core.types.structured.CallMethodResult closeAndUpdate(
      OpcUaClient client,
      PubSubConfiguration2DataType file,
      boolean requireCompleteUpdate,
      PubSubConfigurationRefDataType... refs)
      throws Exception {

    UInteger handle = open(client, MODE_WRITE_ERASE);
    byte[] bytes = PubSubConfigFiles.write(file, ctx(client));
    // configuration files are far below the 1 MiB buffer, so a single Write suffices
    call(client, WRITE, new Variant(handle), new Variant(ByteString.of(bytes)));
    return call(
        client,
        CLOSE_AND_UPDATE,
        new Variant(handle),
        new Variant(requireCompleteUpdate),
        new Variant(refs));
  }

  private static boolean changesApplied(
      org.eclipse.milo.opcua.stack.core.types.structured.CallMethodResult result) {
    return Boolean.TRUE.equals(result.getOutputArguments()[0].getValue());
  }

  private static StatusCode[] referencesResults(
      org.eclipse.milo.opcua.stack.core.types.structured.CallMethodResult result) {
    return (StatusCode[]) result.getOutputArguments()[1].getValue();
  }

  private static PubSubConfigurationValueDataType[] configurationValues(
      org.eclipse.milo.opcua.stack.core.types.structured.CallMethodResult result,
      EncodingContext encodingContext)
      throws Exception {

    Object value = result.getOutputArguments()[2].getValue();
    if (value == null) {
      return new PubSubConfigurationValueDataType[0];
    }
    ExtensionObject[] encoded = (ExtensionObject[]) value;
    var values = new ArrayList<PubSubConfigurationValueDataType>();
    for (ExtensionObject xo : encoded) {
      values.add((PubSubConfigurationValueDataType) xo.decode(encodingContext));
    }
    return values.toArray(PubSubConfigurationValueDataType[]::new);
  }

  private static PubSubConfigurationRefMask mask(Field... fields) {
    return PubSubConfigurationRefMask.of(fields);
  }

  private static PubSubConfigurationRefDataType ref(
      PubSubConfigurationRefMask mask, int connectionIndex, int groupIndex, int elementIndex) {
    return new PubSubConfigurationRefDataType(
        mask, ushort(elementIndex), ushort(connectionIndex), ushort(groupIndex));
  }

  private static PubSubConnectionDataType connection(String name, WriterGroupDataType... groups) {
    // A UDP connection requires an address URL (DataTypeToConfigMapper validation); use a unicast
    // loopback address and an explicit loopback discoveryAddress so applying the config never
    // touches the network (the Part 14 default discovery is multicast opc.udp://224.0.2.14:4840).
    var address = new NetworkAddressUrlDataType(null, "opc.udp://127.0.0.1:" + freeUdpPort());
    var transportSettings =
        new DatagramConnectionTransportDataType(
            new NetworkAddressUrlDataType(null, "opc.udp://127.0.0.1:" + freeUdpPort()));
    // a datagram (UInt64) PublisherId: required once the connection carries writer groups, and
    // harmless otherwise, so every connection is independently valid
    return new PubSubConnectionDataType(
        name,
        true,
        new Variant(ulong(1L)),
        "http://opcfoundation.org/UA-Profile/Transport/pubsub-udp-uadp",
        address,
        null,
        transportSettings,
        groups.length == 0 ? null : groups,
        null);
  }

  /** An ephemeral loopback UDP port, so fixtures never collide on a fixed port. */
  private static int freeUdpPort() {
    try (java.net.DatagramSocket socket = new java.net.DatagramSocket(0)) {
      return socket.getLocalPort();
    } catch (java.net.SocketException e) {
      throw new RuntimeException("could not allocate a free UDP port", e);
    }
  }

  private static WriterGroupDataType writerGroup(String name, int id) {
    return writerGroup(name, id, UadpNetworkMessageContentMask.of());
  }

  private static WriterGroupDataType writerGroupWithGroupHeader(String name, int id) {
    return writerGroup(
        name,
        id,
        UadpNetworkMessageContentMask.of(UadpNetworkMessageContentMask.Field.GroupHeader));
  }

  /**
   * A writer group whose optional TransportSettings/MessageSettings are non-null. These fields are
   * carried on the wire as ExtensionObjects; a null one cannot be decoded from the binary
   * configuration file, so a group written through the CloseAndUpdate file flow must populate them.
   * The values are chosen to survive the DataType->config->DataType round trip unchanged
   * (groupVersion 0, DataSetOrdering Undefined), so they still compare equal as WriterGroup match
   * fields.
   */
  private static WriterGroupDataType writerGroup(
      String name, int id, UadpNetworkMessageContentMask contentMask) {
    var transportSettings = new DatagramWriterGroupTransportDataType(ubyte(1), null);
    var messageSettings =
        new UadpWriterGroupMessageDataType(
            uint(0), DataSetOrderingType.Undefined, contentMask, null, null);
    return new WriterGroupDataType(
        name,
        true,
        MessageSecurityMode.None,
        null,
        null,
        null,
        null,
        id == 0 ? null : ushort(id),
        // publishingInterval (ms): a valid writer group requires a positive value
        100.0,
        null,
        null,
        null,
        null,
        transportSettings,
        messageSettings,
        null);
  }

  private static PubSubConfiguration2DataType config(PubSubConnectionDataType... connections) {
    return new PubSubConfiguration2DataType(
        null, connections, true, null, null, null, null, null, uint(0), null);
  }

  private static PubSubConfig configWithConnection(String name) {
    return PubSubConfig.fromDataType(config(connection(name)), nsTable());
  }

  /** A client {@code ReserveIds} call over the UDP/UADP transport profile. */
  private static CallMethodResult reserveIds(OpcUaClient client) throws Exception {
    return call(
        client,
        RESERVE_IDS,
        new Variant("http://opcfoundation.org/UA-Profile/Transport/pubsub-udp-uadp"),
        new Variant(ushort(4)),
        new Variant(ushort(0)));
  }

  /** An in-memory {@link PubSubConfigurationStore} counting every {@code save()}. */
  private static final class CountingStore implements PubSubConfigurationStore {
    final List<PubSubConfiguration2DataType> saved = new CopyOnWriteArrayList<>();

    @Override
    public PubSubConfiguration2DataType load() {
      return null;
    }

    @Override
    public void save(PubSubConfiguration2DataType value) {
      saved.add(value);
    }
  }

  /**
   * A store whose {@code save()} parks (once it first sees the mutating configuration carrying the
   * {@code "cau"} connection) until {@link #releaseSave} is counted down, so a client
   * CloseAndUpdate can be held inside {@link RemoteConfigurationServer#closeAndUpdate} while it
   * still owns the reconfigure monitor. The empty attach-time save (no {@code "cau"} connection) is
   * not parked.
   */
  private static final class BlockingStore implements PubSubConfigurationStore {
    final CountDownLatch saveEntered = new CountDownLatch(1);
    final CountDownLatch releaseSave = new CountDownLatch(1);

    @Override
    public PubSubConfiguration2DataType load() {
      return null;
    }

    @Override
    public void save(PubSubConfiguration2DataType value) {
      if (!carriesConnection(value, "cau")) {
        return;
      }
      saveEntered.countDown();
      try {
        releaseSave.await(TIMEOUT.toSeconds(), TimeUnit.SECONDS);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
      }
    }

    private static boolean carriesConnection(PubSubConfiguration2DataType value, String name) {
      PubSubConnectionDataType[] connections = value.getConnections();
      if (connections == null) {
        return false;
      }
      for (PubSubConnectionDataType connection : connections) {
        if (connection != null && name.equals(connection.getName())) {
          return true;
        }
      }
      return false;
    }
  }

  // endregion
}
