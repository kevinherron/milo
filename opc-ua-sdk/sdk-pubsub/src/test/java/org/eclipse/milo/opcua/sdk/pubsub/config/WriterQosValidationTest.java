/*
 * Copyright (c) 2026 the Eclipse Milo Authors
 *
 * This program and the accompanying materials are made
 * available under the terms of the Eclipse Public License 2.0
 * which is available at https://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 */

package org.eclipse.milo.opcua.sdk.pubsub.config;

import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.ushort;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.eclipse.milo.opcua.stack.core.types.enumerated.BrokerTransportQualityOfService;
import org.junit.jupiter.api.Test;

/**
 * The deferred §6.4.2.5.4 fold-in: a DataSetWriter-level {@code RequestedDeliveryGuarantee}
 * override is only valid alongside a writer-level {@code QueueName} override.
 */
class WriterQosValidationTest {

  private static PubSubConfig.Builder configWith(BrokerTransportSettings writerBroker) {
    var writer =
        DataSetWriterConfig.builder("w")
            .dataSet(new PublishedDataSetRef("ds"))
            .dataSetWriterId(ushort(1))
            .brokerTransport(writerBroker)
            .build();

    var group =
        WriterGroupConfig.builder("wg").writerGroupId(ushort(1)).dataSetWriter(writer).build();

    var connection =
        UdpConnectionConfig.builder("c")
            .address(UdpDatagramAddress.unicast("127.0.0.1", 4840))
            .publisherId(PublisherId.uint16(ushort(1)))
            .writerGroup(group)
            .build();

    return PubSubConfig.builder()
        .publishedDataSet(
            PublishedDataSetConfig.builder("ds")
                .field(FieldDefinition.builder("f1").build())
                .build())
        .connection(connection);
  }

  @Test
  void deliveryGuaranteeOverrideWithoutQueueNameIsRejected() {
    BrokerTransportSettings broker =
        BrokerTransportSettings.builder()
            .requestedDeliveryGuarantee(BrokerTransportQualityOfService.AtLeastOnce)
            .build();

    PubSubConfigValidationException e =
        assertThrows(PubSubConfigValidationException.class, () -> configWith(broker).build());
    assertTrue(e.getMessage().contains("queueName"));
  }

  @Test
  void deliveryGuaranteeOverrideWithQueueNameIsAccepted() {
    BrokerTransportSettings broker =
        BrokerTransportSettings.builder()
            .queueName("opcua/data/w")
            .requestedDeliveryGuarantee(BrokerTransportQualityOfService.AtLeastOnce)
            .build();

    assertDoesNotThrow(() -> configWith(broker).build());
  }

  @Test
  void notSpecifiedGuaranteeWithoutQueueNameIsAccepted() {
    BrokerTransportSettings broker = BrokerTransportSettings.builder().build();

    assertDoesNotThrow(() -> configWith(broker).build());
  }
}
