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

import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.ubyte;
import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.uint;
import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.ushort;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.eclipse.milo.opcua.stack.core.UaException;
import org.eclipse.milo.opcua.stack.core.encoding.DefaultEncodingContext;
import org.eclipse.milo.opcua.stack.core.encoding.EncodingContext;
import org.eclipse.milo.opcua.stack.core.types.builtin.QualifiedName;
import org.eclipse.milo.opcua.stack.core.types.builtin.Variant;
import org.eclipse.milo.opcua.stack.core.types.enumerated.MessageSecurityMode;
import org.eclipse.milo.opcua.stack.core.types.structured.DataSetFieldContentMask;
import org.eclipse.milo.opcua.stack.core.types.structured.DataSetReaderDataType;
import org.eclipse.milo.opcua.stack.core.types.structured.DataSetWriterDataType;
import org.eclipse.milo.opcua.stack.core.types.structured.KeyValuePair;
import org.eclipse.milo.opcua.stack.core.types.structured.NetworkAddressUrlDataType;
import org.eclipse.milo.opcua.stack.core.types.structured.PubSubConfiguration2DataType;
import org.eclipse.milo.opcua.stack.core.types.structured.PubSubConnectionDataType;
import org.eclipse.milo.opcua.stack.core.types.structured.PublishedDataSetDataType;
import org.eclipse.milo.opcua.stack.core.types.structured.ReaderGroupDataType;
import org.eclipse.milo.opcua.stack.core.types.structured.SecurityGroupDataType;
import org.eclipse.milo.opcua.stack.core.types.structured.StandaloneSubscribedDataSetDataType;
import org.eclipse.milo.opcua.stack.core.types.structured.WriterGroupDataType;
import org.junit.jupiter.api.Test;

/** Round-trip and error-path tests for {@link PubSubConfigFiles} (Phase 5 pin R19). */
class PubSubConfigFilesTest {

  private final EncodingContext context = new DefaultEncodingContext();

  private static PubSubConfiguration2DataType sampleConfig() {
    return new PubSubConfiguration2DataType(
        new PublishedDataSetDataType[0],
        new PubSubConnectionDataType[0],
        Boolean.TRUE,
        new StandaloneSubscribedDataSetDataType[0],
        null,
        null,
        new SecurityGroupDataType[0],
        null,
        uint(12345),
        new KeyValuePair[] {new KeyValuePair(new QualifiedName(1, "k"), new Variant("v"))});
  }

  /**
   * A UDP connection whose writer/reader carry no transport or message settings: Part 14 defines no
   * datagram DataSetWriter/ReaderGroup transport type, so those optional abstract-typed fields are
   * null. They encode as null ExtensionObjects and must decode back to null.
   */
  private static PubSubConfiguration2DataType udpConfig() {
    var address = new NetworkAddressUrlDataType(null, "opc.udp://239.0.0.1:4840");

    var dataSetWriter =
        new DataSetWriterDataType(
            "writer",
            Boolean.TRUE,
            ushort(1),
            DataSetFieldContentMask.of(),
            uint(0),
            "ds",
            null,
            null, // TransportSettings: no datagram DataSetWriter transport type in Part 14
            null); // MessageSettings

    var writerGroup =
        new WriterGroupDataType(
            "wg",
            Boolean.TRUE,
            MessageSecurityMode.None,
            null,
            null,
            uint(0),
            null,
            ushort(1),
            1000.0,
            5000.0,
            ubyte(0),
            null,
            null,
            null, // TransportSettings
            null, // MessageSettings
            new DataSetWriterDataType[] {dataSetWriter});

    var readerGroup =
        new ReaderGroupDataType(
            "rg",
            Boolean.TRUE,
            MessageSecurityMode.None,
            null,
            null,
            uint(0),
            null,
            null, // TransportSettings: no datagram ReaderGroup transport type in Part 14
            null, // MessageSettings
            new DataSetReaderDataType[0]);

    var connection =
        new PubSubConnectionDataType(
            "conn",
            Boolean.TRUE,
            new Variant(ushort(42)),
            "http://opcfoundation.org/UA-Profile/Transport/pubsub-udp-uadp",
            address,
            null,
            null, // TransportSettings
            new WriterGroupDataType[] {writerGroup},
            new ReaderGroupDataType[] {readerGroup});

    return new PubSubConfiguration2DataType(
        new PublishedDataSetDataType[0],
        new PubSubConnectionDataType[] {connection},
        Boolean.TRUE,
        new StandaloneSubscribedDataSetDataType[0],
        null,
        null,
        new SecurityGroupDataType[0],
        null,
        uint(1),
        null);
  }

  @Test
  void roundTripsAConfiguration() throws Exception {
    PubSubConfiguration2DataType original = sampleConfig();

    byte[] bytes = PubSubConfigFiles.write(original, context);
    assertNotNull(bytes);
    assertTrue(bytes.length > 0);

    PubSubConfiguration2DataType decoded = PubSubConfigFiles.read(bytes, context);

    assertEquals(original, decoded);
  }

  @Test
  void roundTripsAUdpConfigurationWithNullTransportSettings() throws Exception {
    // Regression: a UDP writer/reader leaves TransportSettings/MessageSettings null, which encode
    // as null ExtensionObjects. Reading the file back must decode those to null rather than
    // throwing Bad_TypeMismatch, otherwise CloseAndUpdate is unusable for the datagram transport.
    PubSubConfiguration2DataType original = udpConfig();

    byte[] bytes = PubSubConfigFiles.write(original, context);
    assertNotNull(bytes);
    assertTrue(bytes.length > 0);

    PubSubConfiguration2DataType decoded = PubSubConfigFiles.read(bytes, context);

    assertEquals(original, decoded);
  }

  @Test
  void toBinaryFileSkipsTheOpcUaNamespaceInTheHeader() {
    // a fresh DefaultEncodingContext has only the OPC UA namespace (index 0), which Table 88 skips
    var file = PubSubConfigFiles.toBinaryFile(sampleConfig(), context);
    assertEquals(0, file.getNamespaces() != null ? file.getNamespaces().length : 0);
  }

  @Test
  void readRejectsNonUaBinaryFileBytes() {
    // random bytes are not a decodable ExtensionObject-wrapped UABinaryFileDataType
    byte[] garbage = new byte[] {1, 2, 3, 4, 5, 6, 7, 8};

    UaException e = assertThrows(UaException.class, () -> PubSubConfigFiles.read(garbage, context));
    assertTrue(e.getStatusCode().isBad());
  }
}
