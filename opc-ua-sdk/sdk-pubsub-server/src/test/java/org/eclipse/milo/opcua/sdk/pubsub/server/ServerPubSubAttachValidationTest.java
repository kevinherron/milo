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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.eclipse.milo.opcua.sdk.pubsub.config.DataSetMetaDataConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.DataSetReaderConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.FieldDefinition;
import org.eclipse.milo.opcua.sdk.pubsub.config.FieldSelector;
import org.eclipse.milo.opcua.sdk.pubsub.config.NodeFieldAddress;
import org.eclipse.milo.opcua.sdk.pubsub.config.PubSubConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.PubSubConfigValidationException;
import org.eclipse.milo.opcua.sdk.pubsub.config.PubSubConnectionConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.PublishedDataSetConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.ReaderGroupConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.StandaloneSubscribedDataSetConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.TargetVariableConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.TargetVariablesConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.UdpDatagramAddress;
import org.eclipse.milo.opcua.sdk.server.nodes.UaVariableNode;
import org.eclipse.milo.opcua.stack.core.AttributeId;
import org.eclipse.milo.opcua.stack.core.NodeIds;
import org.eclipse.milo.opcua.stack.core.types.builtin.DataValue;
import org.eclipse.milo.opcua.stack.core.types.builtin.NodeId;
import org.eclipse.milo.opcua.stack.core.types.builtin.Variant;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.ULong;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Attach-time validation: every {@link NodeFieldAddress} in the effective configuration — published
 * dataset field sources, direct reader TargetVariables targets, and standalone subscribed dataset
 * TargetVariables targets — must resolve against the server's NamespaceTable, and TargetVariables
 * index ranges must parse. {@code allowRemoteConfiguration(true)} now attaches the
 * remote-configuration FileType model.
 */
class ServerPubSubAttachValidationTest {

  private static final String UNRESOLVABLE_TARGET = "nsu=urn:milo:test:unresolvable;s=Target";

  private static TestPubSubServer testServer;
  private static NodeId writableNodeId;

  @BeforeAll
  static void startServer() {
    testServer = TestPubSubServer.create();
    writableNodeId =
        testServer.addVariable(
            "ValidationTarget", NodeIds.Double, new DataValue(Variant.ofDouble(0.0)));
  }

  @AfterAll
  static void stopServer() {
    testServer.close();
  }

  @Test
  void unresolvableSourceNamespaceFailsAttachNamingDataSetAndField() {
    PublishedDataSetConfig dataSet =
        PublishedDataSetConfig.builder("ds")
            .field(
                FieldDefinition.builder("temperature")
                    .source(
                        NodeFieldAddress.parse(
                            "nsu=urn:milo:test:unresolvable;s=Temp", AttributeId.Value))
                    .dataType(NodeIds.Double)
                    .build())
            .build();

    PubSubConfig config = PubSubConfig.builder().publishedDataSet(dataSet).build();

    PubSubConfigValidationException e =
        assertThrows(
            PubSubConfigValidationException.class,
            () -> ServerPubSub.attach(testServer.getServer(), config));

    assertNotNull(e.getMessage());
    assertTrue(
        e.getMessage().contains("PublishedDataSet 'ds' field 'temperature'"),
        "expected the offending element in: " + e.getMessage());
  }

  @Test
  void unresolvableTargetVariableTargetFailsAttachNamingReader() {
    PubSubConfig config =
        readerConfig(
            TargetVariablesConfig.builder()
                .map(
                    FieldSelector.byName("temperature"),
                    TargetVariableConfig.builder()
                        .target(NodeFieldAddress.parse(UNRESOLVABLE_TARGET, AttributeId.Value))
                        .build())
                .build());

    PubSubConfigValidationException e =
        assertThrows(
            PubSubConfigValidationException.class,
            () -> ServerPubSub.attach(testServer.getServer(), config));

    assertNotNull(e.getMessage());
    assertTrue(
        e.getMessage().contains("DataSetReader 'conn/grp/reader'"),
        "expected the offending element in: " + e.getMessage());
  }

  @Test
  void unresolvableStandaloneSubscribedDataSetTargetFailsAttachNamingDataSet() {
    StandaloneSubscribedDataSetConfig standalone =
        StandaloneSubscribedDataSetConfig.builder("sds")
            .metaData(DataSetMetaDataConfig.builder("sds").field("f", NodeIds.Int32).build())
            .subscribedDataSet(
                TargetVariablesConfig.builder()
                    .map(
                        FieldSelector.byName("f"),
                        TargetVariableConfig.builder()
                            .target(NodeFieldAddress.parse(UNRESOLVABLE_TARGET, AttributeId.Value))
                            .build())
                    .build())
            .build();

    PubSubConfig config = PubSubConfig.builder().standaloneSubscribedDataSet(standalone).build();

    PubSubConfigValidationException e =
        assertThrows(
            PubSubConfigValidationException.class,
            () -> ServerPubSub.attach(testServer.getServer(), config));

    assertNotNull(e.getMessage());
    assertTrue(
        e.getMessage().contains("StandaloneSubscribedDataSet 'sds'"),
        "expected the offending element in: " + e.getMessage());
  }

  @Test
  void malformedReceiverIndexRangeFailsAttach() {
    PubSubConfig config =
        readerConfig(
            TargetVariablesConfig.builder()
                .map(
                    FieldSelector.byName("temperature"),
                    TargetVariableConfig.builder()
                        .target(resolvableTarget())
                        .receiverIndexRange("not-a-range")
                        .build())
                .build());

    PubSubConfigValidationException e =
        assertThrows(
            PubSubConfigValidationException.class,
            () -> ServerPubSub.attach(testServer.getServer(), config));

    assertNotNull(e.getMessage());
    assertTrue(
        e.getMessage().contains("not-a-range"),
        "expected the offending range in: " + e.getMessage());
  }

  @Test
  void malformedWriteIndexRangeFailsAttach() {
    // "3:3" is rejected by NumericRange.parse: a range must have low < high
    PubSubConfig config =
        readerConfig(
            TargetVariablesConfig.builder()
                .map(
                    FieldSelector.byName("temperature"),
                    TargetVariableConfig.builder()
                        .target(resolvableTarget())
                        .writeIndexRange("3:3")
                        .build())
                .build());

    PubSubConfigValidationException e =
        assertThrows(
            PubSubConfigValidationException.class,
            () -> ServerPubSub.attach(testServer.getServer(), config));

    assertNotNull(e.getMessage());
    assertTrue(
        e.getMessage().contains("3:3"), "expected the offending range in: " + e.getMessage());
  }

  @Test
  void malformedStandaloneSubscribedDataSetIndexRangeFailsAttach() {
    StandaloneSubscribedDataSetConfig standalone =
        StandaloneSubscribedDataSetConfig.builder("sds-range")
            .metaData(DataSetMetaDataConfig.builder("sds-range").field("f", NodeIds.Int32).build())
            .subscribedDataSet(
                TargetVariablesConfig.builder()
                    .map(
                        FieldSelector.byName("f"),
                        TargetVariableConfig.builder()
                            .target(resolvableTarget())
                            .receiverIndexRange("not-a-range")
                            .build())
                    .build())
            .build();

    PubSubConfig config = PubSubConfig.builder().standaloneSubscribedDataSet(standalone).build();

    PubSubConfigValidationException e =
        assertThrows(
            PubSubConfigValidationException.class,
            () -> ServerPubSub.attach(testServer.getServer(), config));

    assertNotNull(e.getMessage());
    assertTrue(
        e.getMessage().contains("StandaloneSubscribedDataSet 'sds-range'")
            && e.getMessage().contains("not-a-range"),
        "expected the offending element and range in: " + e.getMessage());
  }

  @Test
  void allowRemoteConfigurationAttaches() {
    PubSubConfig config = PubSubConfig.builder().build();

    ServerPubSubOptions options =
        ServerPubSubOptions.builder().allowRemoteConfiguration(true).build();

    // no longer throws: the FileType remote-configuration model attaches (not started here)
    ServerPubSub serverPubSub = ServerPubSub.attach(testServer.getServer(), config, options);
    assertNotNull(serverPubSub.runtime());
    serverPubSub.close();
  }

  @Test
  void resolvableConfigurationAttaches() {
    PubSubConfig config =
        readerConfig(
            TargetVariablesConfig.builder()
                .map(
                    FieldSelector.byName("temperature"),
                    TargetVariableConfig.builder()
                        .target(resolvableTarget())
                        .receiverIndexRange("0:1")
                        .writeIndexRange("2")
                        .build())
                .build());

    ServerPubSub serverPubSub = ServerPubSub.attach(testServer.getServer(), config);
    assertNotNull(serverPubSub.runtime());
    serverPubSub.close();
  }

  @Test
  void disabledRemoteConfigInitializesFileTypeSizeWithoutSerializingTheConfig() {
    // a reader group carries no TransportSettings/MessageSettings (the codec cannot encode those
    // as null) and the TargetVariable uses a FieldNameSelector with no configured DataSetMetaData
    // (the mapper cannot resolve a DataSetFieldId): both make the configuration unserializable to
    // PubSubConfiguration2DataType, yet it is legal for a locally-configured server. Attach must
    // not serialize at attach; Size is reported as 0.
    PubSubConfig config =
        readerConfig(
            TargetVariablesConfig.builder()
                .map(
                    FieldSelector.byName("temperature"),
                    TargetVariableConfig.builder().target(resolvableTarget()).build())
                .build());

    ServerPubSub serverPubSub = ServerPubSub.attach(testServer.getServer(), config);
    try {
      Object size =
          ((UaVariableNode)
                  testServer
                      .getServer()
                      .getAddressSpaceManager()
                      .getManagedNode(NodeIds.PublishSubscribe_PubSubConfiguration_Size)
                      .orElseThrow())
              .getValue()
              .getValue()
              .getValue();
      assertEquals(ULong.valueOf(0), size);
    } finally {
      serverPubSub.close();
    }
  }

  // region fixtures

  private static NodeFieldAddress resolvableTarget() {
    return NodeFieldAddress.of(
        writableNodeId, AttributeId.Value, testServer.getServer().getNamespaceTable());
  }

  /** One UDP connection "conn" with reader group "grp" and reader "reader" using {@code spec}. */
  private static PubSubConfig readerConfig(TargetVariablesConfig spec) {
    return PubSubConfig.builder()
        .connection(
            PubSubConnectionConfig.udp("conn")
                .address(UdpDatagramAddress.unicast("127.0.0.1", 14840))
                .readerGroup(
                    ReaderGroupConfig.builder("grp")
                        .dataSetReader(
                            DataSetReaderConfig.builder("reader").subscribedDataSet(spec).build())
                        .build())
                .build())
        .build();
  }

  // endregion
}
