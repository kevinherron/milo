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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.concurrent.TimeUnit;
import org.eclipse.milo.opcua.sdk.pubsub.config.PubSubConfig;
import org.eclipse.milo.opcua.sdk.server.nodes.UaVariableNode;
import org.eclipse.milo.opcua.stack.core.NodeIds;
import org.eclipse.milo.opcua.stack.core.types.builtin.NodeId;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.ULong;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UShort;
import org.junit.jupiter.api.Test;

/**
 * Verifies that enabling {@link ServerPubSubOptions.Builder#allowRemoteConfiguration} attaches the
 * FileType model: the flag no longer throws, the mandatory FileType properties are initialized, and
 * the three optional properties are created.
 */
class RemoteConfigurationServerAttachTest {

  @Test
  void attachInitializesTheFileTypeProperties() throws Exception {
    try (TestPubSubServer test = TestPubSubServer.create()) {
      var options = ServerPubSubOptions.builder().allowRemoteConfiguration(true).build();

      ServerPubSub serverPubSub =
          ServerPubSub.attach(test.getServer(), PubSubConfig.builder().build(), options);
      try {
        serverPubSub.startup().get(10, TimeUnit.SECONDS);

        assertEquals(
            Boolean.TRUE, ns0Value(test, NodeIds.PublishSubscribe_PubSubConfiguration_Writable));
        assertEquals(
            Boolean.TRUE,
            ns0Value(test, NodeIds.PublishSubscribe_PubSubConfiguration_UserWritable));
        assertEquals(
            UShort.valueOf(0),
            ns0Value(test, NodeIds.PublishSubscribe_PubSubConfiguration_OpenCount));

        UShort appNs = test.getServer().getServerNamespace().getNamespaceIndex();
        Object mimeType = appValue(test, new NodeId(appNs, "PubSub/PubSubConfiguration/MimeType"));
        assertEquals("application/opcua+uabinary", mimeType);

        // the MaxByteStringLength optional property exists (value is a UInt32)
        assertTrue(
            test.getServer()
                .getAddressSpaceManager()
                .getManagedNode(new NodeId(appNs, "PubSub/PubSubConfiguration/MaxByteStringLength"))
                .isPresent());
      } finally {
        serverPubSub.close();
      }
    }
  }

  @Test
  void attachInitializesFileTypePropertiesWhenRemoteConfigurationDisabled() throws Exception {
    try (TestPubSubServer test = TestPubSubServer.create()) {
      // default options: remote configuration disabled, information model not exposed
      ServerPubSub serverPubSub =
          ServerPubSub.attach(test.getServer(), PubSubConfig.builder().build());
      try {
        // the Mandatory FileType properties are set at
        // attach time reflecting allowRemoteConfiguration=false, even without startup
        assertEquals(
            Boolean.FALSE, ns0Value(test, NodeIds.PublishSubscribe_PubSubConfiguration_Writable));
        assertEquals(
            Boolean.FALSE,
            ns0Value(test, NodeIds.PublishSubscribe_PubSubConfiguration_UserWritable));
        assertEquals(
            UShort.valueOf(0),
            ns0Value(test, NodeIds.PublishSubscribe_PubSubConfiguration_OpenCount));
        // with remote configuration disabled the virtual file
        // can never be opened, so no read snapshot exists and Size is reported as 0 (the
        // configuration is deliberately not serialized at attach to derive a size)
        assertEquals(
            ULong.valueOf(0), ns0Value(test, NodeIds.PublishSubscribe_PubSubConfiguration_Size));
      } finally {
        serverPubSub.close();
      }
    }
  }

  private static Object ns0Value(TestPubSubServer test, NodeId nodeId) {
    return ((UaVariableNode)
            test.getServer().getAddressSpaceManager().getManagedNode(nodeId).orElseThrow())
        .getValue()
        .getValue()
        .getValue();
  }

  private static Object appValue(TestPubSubServer test, NodeId nodeId) {
    return ((UaVariableNode)
            test.getServer().getAddressSpaceManager().getManagedNode(nodeId).orElseThrow())
        .getValue()
        .getValue()
        .getValue();
  }
}
