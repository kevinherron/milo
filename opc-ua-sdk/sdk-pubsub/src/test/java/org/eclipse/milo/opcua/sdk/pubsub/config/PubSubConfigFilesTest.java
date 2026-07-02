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

import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.uint;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.eclipse.milo.opcua.stack.core.UaException;
import org.eclipse.milo.opcua.stack.core.encoding.DefaultEncodingContext;
import org.eclipse.milo.opcua.stack.core.encoding.EncodingContext;
import org.eclipse.milo.opcua.stack.core.types.builtin.QualifiedName;
import org.eclipse.milo.opcua.stack.core.types.builtin.Variant;
import org.eclipse.milo.opcua.stack.core.types.structured.KeyValuePair;
import org.eclipse.milo.opcua.stack.core.types.structured.PubSubConfiguration2DataType;
import org.eclipse.milo.opcua.stack.core.types.structured.PubSubConnectionDataType;
import org.eclipse.milo.opcua.stack.core.types.structured.PublishedDataSetDataType;
import org.eclipse.milo.opcua.stack.core.types.structured.SecurityGroupDataType;
import org.eclipse.milo.opcua.stack.core.types.structured.StandaloneSubscribedDataSetDataType;
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
