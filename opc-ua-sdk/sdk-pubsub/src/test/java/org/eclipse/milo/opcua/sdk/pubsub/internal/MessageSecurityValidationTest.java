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

import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.ubyte;
import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.ushort;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubBindings;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubService;
import org.eclipse.milo.opcua.sdk.pubsub.PubSubServiceConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.BrokerTransportSettings;
import org.eclipse.milo.opcua.sdk.pubsub.config.DataSetReaderConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.DataSetWriterConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.FieldDefinition;
import org.eclipse.milo.opcua.sdk.pubsub.config.JsonDataSetReaderSettings;
import org.eclipse.milo.opcua.sdk.pubsub.config.JsonDataSetWriterSettings;
import org.eclipse.milo.opcua.sdk.pubsub.config.JsonWriterGroupSettings;
import org.eclipse.milo.opcua.sdk.pubsub.config.MessageSecurityConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.MqttConnectionConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.PubSubConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.PubSubConnectionConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.PublishedDataSetConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.PublisherId;
import org.eclipse.milo.opcua.sdk.pubsub.config.ReaderGroupConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.SecurityGroupConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.SecurityGroupRef;
import org.eclipse.milo.opcua.sdk.pubsub.config.UdpConnectionConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.UdpDatagramAddress;
import org.eclipse.milo.opcua.sdk.pubsub.config.WriterGroupConfig;
import org.eclipse.milo.opcua.sdk.pubsub.security.PubSubSecurityPolicy;
import org.eclipse.milo.opcua.sdk.pubsub.security.SecurityKeyProvider;
import org.eclipse.milo.opcua.sdk.pubsub.security.StaticSecurityKeyProvider;
import org.eclipse.milo.opcua.sdk.pubsub.transport.PublisherChannel;
import org.eclipse.milo.opcua.sdk.pubsub.transport.PublisherTransportContext;
import org.eclipse.milo.opcua.sdk.pubsub.transport.SubscriberChannel;
import org.eclipse.milo.opcua.sdk.pubsub.transport.SubscriberTransportContext;
import org.eclipse.milo.opcua.sdk.pubsub.transport.TransportProvider;
import org.eclipse.milo.opcua.stack.core.NodeIds;
import org.eclipse.milo.opcua.stack.core.StatusCodes;
import org.eclipse.milo.opcua.stack.core.UaException;
import org.eclipse.milo.opcua.stack.core.UaRuntimeException;
import org.eclipse.milo.opcua.stack.core.types.builtin.ByteString;
import org.eclipse.milo.opcua.stack.core.types.builtin.LocalizedText;
import org.eclipse.milo.opcua.stack.core.types.enumerated.ApplicationType;
import org.eclipse.milo.opcua.stack.core.types.enumerated.MessageSecurityMode;
import org.eclipse.milo.opcua.stack.core.types.structured.ApplicationDescription;
import org.eclipse.milo.opcua.stack.core.types.structured.EndpointDescription;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * Tests for the startup/reconfigure message security validation that replaced the Bad_NotSupported
 * gates: any secured JSON-mapped group/reader is rejected naming BrokerSecurityConfig (JSON has no
 * message security in OPC UA 1.05, Part 14 §7.3.4.1), and a secured UADP group/reader requires a
 * resolvable SecurityGroupRef, a supported policy, a bound SecurityKeyProvider, and valid
 * SecurityKeyServices entries — all {@code Bad_ConfigurationError}.
 */
class MessageSecurityValidationTest {

  private static final SecurityGroupRef SG_REF = new SecurityGroupRef("SG");

  private @Nullable PubSubService service;
  private @Nullable ExecutorService transportExecutor;

  @AfterEach
  void shutdownService() throws Exception {
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

  /** A transport that supports everything and never touches the network. */
  private static final class StubTransport implements TransportProvider {

    @Override
    public String transportProfileUri() {
      return "urn:eclipse:milo:test:stub-transport";
    }

    @Override
    public boolean supports(PubSubConnectionConfig connection) {
      return true;
    }

    @Override
    public PublisherChannel openPublisher(PublisherTransportContext context) {
      return new PublisherChannel() {
        @Override
        public CompletableFuture<Void> send(io.netty.buffer.ByteBuf message) {
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

  private void createService(PubSubConfig config, PubSubBindings bindings) {
    transportExecutor = Executors.newSingleThreadExecutor();

    PubSubServiceConfig serviceConfig =
        PubSubServiceConfig.builder()
            .transportProvider(new StubTransport())
            .transportExecutor(transportExecutor)
            .build();

    service = PubSubService.create(config, bindings, serviceConfig);
  }

  private UaException assertStartupFailsWithConfigurationError(
      PubSubConfig config, PubSubBindings bindings, String expectedFragment) {

    createService(config, bindings);

    ExecutionException e =
        assertThrows(ExecutionException.class, () -> service.startup().get(10, TimeUnit.SECONDS));
    UaException cause = assertInstanceOf(UaException.class, e.getCause());
    assertEquals(StatusCodes.Bad_ConfigurationError, cause.getStatusCode().value());
    assertTrue(
        cause.getMessage() != null && cause.getMessage().contains(expectedFragment),
        "unexpected message: " + cause.getMessage());
    return cause;
  }

  private static SecurityKeyProvider staticProvider() {
    byte[] keyData = new byte[PubSubSecurityPolicy.Aes256Ctr.getKeyDataLength()];
    for (int i = 0; i < keyData.length; i++) {
      keyData[i] = (byte) i;
    }
    return StaticSecurityKeyProvider.of(PubSubSecurityPolicy.Aes256Ctr, ByteString.of(keyData));
  }

  private static org.eclipse.milo.opcua.sdk.pubsub.DataSetSnapshot emptySnapshot(
      org.eclipse.milo.opcua.sdk.pubsub.PublishedDataSetReadContext context) {
    return org.eclipse.milo.opcua.sdk.pubsub.DataSetSnapshot.builder(context).build();
  }

  private static PublishedDataSetConfig dataSet() {
    return PublishedDataSetConfig.builder("PDS")
        .field(FieldDefinition.builder("F1").dataType(NodeIds.Int32).build())
        .build();
  }

  private static MessageSecurityConfig signSecurity(boolean withRef) {
    MessageSecurityConfig.Builder builder =
        MessageSecurityConfig.builder().mode(MessageSecurityMode.Sign);
    if (withRef) {
      builder.securityGroup(SG_REF);
    }
    return builder.build();
  }

  // region JSON (no message security in 1.05)

  @Test
  void securedJsonWriterGroupFailsStartupNamingBrokerSecurityConfig() {
    PublishedDataSetConfig dataSet = dataSet();

    PubSubConfig config =
        PubSubConfig.builder()
            .publishedDataSet(dataSet)
            .securityGroup(SecurityGroupConfig.builder("SG").build())
            .connection(
                MqttConnectionConfig.builder("conn")
                    .brokerUri(URI.create("mqtt://localhost:1883"))
                    .publisherId(PublisherId.uint16(ushort(1)))
                    .writerGroup(
                        WriterGroupConfig.builder("WG")
                            .writerGroupId(ushort(1))
                            .messageSettings(JsonWriterGroupSettings.builder().build())
                            .messageSecurity(signSecurity(true))
                            .dataSetWriter(
                                DataSetWriterConfig.builder("W1")
                                    .dataSet(dataSet.ref())
                                    .dataSetWriterId(ushort(1))
                                    .settings(JsonDataSetWriterSettings.builder().build())
                                    .build())
                            .build())
                    .build())
            .build();

    assertStartupFailsWithConfigurationError(
        config,
        PubSubBindings.builder()
            .source(dataSet.ref(), MessageSecurityValidationTest::emptySnapshot)
            .securityKeys(SG_REF, staticProvider())
            .build(),
        "BrokerSecurityConfig");
  }

  @Test
  void securedJsonReaderFailsStartupNamingBrokerSecurityConfig() {
    PubSubConfig config =
        PubSubConfig.builder()
            .securityGroup(SecurityGroupConfig.builder("SG").build())
            .connection(
                MqttConnectionConfig.builder("conn")
                    .brokerUri(URI.create("mqtt://localhost:1883"))
                    .readerGroup(
                        ReaderGroupConfig.builder("RG")
                            .messageSecurity(signSecurity(true))
                            .dataSetReader(
                                DataSetReaderConfig.builder("R1")
                                    .settings(JsonDataSetReaderSettings.builder().build())
                                    .brokerTransport(
                                        BrokerTransportSettings.builder().queueName("q").build())
                                    .build())
                            .build())
                    .build())
            .build();

    assertStartupFailsWithConfigurationError(
        config,
        PubSubBindings.builder().securityKeys(SG_REF, staticProvider()).build(),
        "BrokerSecurityConfig");
  }

  // endregion

  // region secured UADP requirements

  private static PubSubConfig uadpWriterConfig(
      @Nullable SecurityGroupConfig securityGroup, MessageSecurityConfig security) {

    PublishedDataSetConfig dataSet = dataSet();

    PubSubConfig.Builder builder = PubSubConfig.builder().publishedDataSet(dataSet);
    if (securityGroup != null) {
      builder.securityGroup(securityGroup);
    }
    return builder
        .connection(
            UdpConnectionConfig.builder("conn")
                .publisherId(PublisherId.uint16(ushort(1)))
                .address(UdpDatagramAddress.unicast("127.0.0.1", 14840))
                .writerGroup(
                    WriterGroupConfig.builder("WG")
                        .writerGroupId(ushort(1))
                        .messageSecurity(security)
                        .dataSetWriter(
                            DataSetWriterConfig.builder("W1")
                                .dataSet(dataSet.ref())
                                .dataSetWriterId(ushort(1))
                                .build())
                        .build())
                .build())
        .build();
  }

  @Test
  void securedGroupWithoutSecurityGroupRefFailsStartup() {
    PubSubConfig config = uadpWriterConfig(null, signSecurity(false));

    assertStartupFailsWithConfigurationError(
        config,
        PubSubBindings.builder()
            .source(dataSet().ref(), MessageSecurityValidationTest::emptySnapshot)
            .build(),
        "requires a resolvable SecurityGroupRef");
  }

  @Test
  void securedGroupWithoutBoundProviderFailsStartup() {
    PubSubConfig config =
        uadpWriterConfig(SecurityGroupConfig.builder("SG").build(), signSecurity(true));

    assertStartupFailsWithConfigurationError(
        config,
        PubSubBindings.builder()
            .source(dataSet().ref(), MessageSecurityValidationTest::emptySnapshot)
            .build(),
        "no SecurityKeyProvider bound");
  }

  @Test
  void securedGroupWithUnsupportedPolicyUriFailsStartup() {
    PubSubConfig config =
        uadpWriterConfig(
            SecurityGroupConfig.builder("SG")
                .securityPolicyUri("http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256")
                .build(),
            signSecurity(true));

    assertStartupFailsWithConfigurationError(
        config,
        PubSubBindings.builder()
            .source(dataSet().ref(), MessageSecurityValidationTest::emptySnapshot)
            .securityKeys(SG_REF, staticProvider())
            .build(),
        "unsupported security policy URI");
  }

  @Test
  void invalidSecurityKeyServiceEntriesFailStartup() {
    // a ClientAndServer-typed entry is a hard SecurityKeyServiceValidator error
    var badEntry =
        new EndpointDescription(
            null,
            new ApplicationDescription(
                "urn:sks",
                null,
                LocalizedText.english("SKS"),
                ApplicationType.ClientAndServer,
                null,
                null,
                new String[] {"opc.tcp://sks:4840"}),
            ByteString.NULL_VALUE,
            MessageSecurityMode.SignAndEncrypt,
            null,
            null,
            null,
            ubyte(0));

    PubSubConfig config =
        uadpWriterConfig(
            SecurityGroupConfig.builder("SG").build(),
            MessageSecurityConfig.builder()
                .mode(MessageSecurityMode.Sign)
                .securityGroup(SG_REF)
                .keyServices(List.of(badEntry))
                .build());

    assertStartupFailsWithConfigurationError(
        config,
        PubSubBindings.builder()
            .source(dataSet().ref(), MessageSecurityValidationTest::emptySnapshot)
            .securityKeys(SG_REF, staticProvider())
            .build(),
        "invalid SecurityKeyServices");
  }

  @Test
  void securedReaderOverrideWithoutSecurityGroupFailsStartup() {
    PubSubConfig config =
        PubSubConfig.builder()
            .connection(
                UdpConnectionConfig.builder("conn")
                    .address(UdpDatagramAddress.unicast("127.0.0.1", 14840))
                    .readerGroup(
                        ReaderGroupConfig.builder("RG")
                            .dataSetReader(
                                DataSetReaderConfig.builder("R1")
                                    .messageSecurity(signSecurity(false))
                                    .build())
                            .build())
                    .build())
            .build();

    UaException e =
        assertStartupFailsWithConfigurationError(
            config, PubSubBindings.builder().build(), "requires a resolvable SecurityGroupRef");
    assertTrue(
        e.getMessage().contains("dataset reader 'conn/RG/R1'"),
        "unexpected message: " + e.getMessage());
  }

  // endregion

  // region reconfigure (enforced at startup AND reconfigure)

  @Test
  void reconfigureRejectsSecuredJsonGroup() throws Exception {
    PublishedDataSetConfig dataSet = dataSet();

    PubSubConfig unsecured =
        PubSubConfig.builder()
            .publishedDataSet(dataSet)
            .connection(
                MqttConnectionConfig.builder("conn")
                    .brokerUri(URI.create("mqtt://localhost:1883"))
                    .publisherId(PublisherId.uint16(ushort(1)))
                    .writerGroup(
                        WriterGroupConfig.builder("WG")
                            .writerGroupId(ushort(1))
                            .messageSettings(JsonWriterGroupSettings.builder().build())
                            .dataSetWriter(
                                DataSetWriterConfig.builder("W1")
                                    .dataSet(dataSet.ref())
                                    .dataSetWriterId(ushort(1))
                                    .settings(JsonDataSetWriterSettings.builder().build())
                                    .build())
                            .build())
                    .build())
            .build();

    createService(
        unsecured,
        PubSubBindings.builder()
            .source(dataSet.ref(), MessageSecurityValidationTest::emptySnapshot)
            .build());
    service.startup().get(10, TimeUnit.SECONDS);

    PubSubConfig secured =
        PubSubConfig.builder()
            .publishedDataSet(dataSet)
            .securityGroup(SecurityGroupConfig.builder("SG").build())
            .connection(
                MqttConnectionConfig.builder("conn")
                    .brokerUri(URI.create("mqtt://localhost:1883"))
                    .publisherId(PublisherId.uint16(ushort(1)))
                    .writerGroup(
                        WriterGroupConfig.builder("WG")
                            .writerGroupId(ushort(1))
                            .messageSettings(JsonWriterGroupSettings.builder().build())
                            .messageSecurity(signSecurity(true))
                            .dataSetWriter(
                                DataSetWriterConfig.builder("W1")
                                    .dataSet(dataSet.ref())
                                    .dataSetWriterId(ushort(1))
                                    .settings(JsonDataSetWriterSettings.builder().build())
                                    .build())
                            .build())
                    .build())
            .build();

    UaRuntimeException e =
        assertThrows(
            UaRuntimeException.class,
            () -> service.reconfigure(secured, PubSubService.ReconfigureMode.DISABLE_AFFECTED));
    assertEquals(StatusCodes.Bad_ConfigurationError, e.getStatusCode().value());
    assertTrue(
        e.getMessage() != null && e.getMessage().contains("BrokerSecurityConfig"),
        "unexpected message: " + e.getMessage());
  }

  // endregion
}
