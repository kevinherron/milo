package org.eclipse.milo.opcua.stack.core.types.builtin;

import static org.junit.jupiter.api.Assertions.*;

import org.eclipse.milo.opcua.stack.core.encoding.DefaultEncodingContext;
import org.eclipse.milo.opcua.stack.core.encoding.binary.OpcUaDefaultBinaryEncoding;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class ExtensionObjectTest {

  private static final Logger LOGGER = LoggerFactory.getLogger(ExtensionObjectTest.class);

  @Test
  void ofByteString() {
    ByteString byteString = new ByteString(new byte[] {1, 2, 3});
    ExtensionObject extensionObject = ExtensionObject.of(byteString, NodeId.NULL_VALUE);

    LOGGER.debug("{}", extensionObject);
    assertEquals(byteString, extensionObject.getBody());
    assertInstanceOf(ExtensionObject.Binary.class, extensionObject);
  }

  @Test
  void ofXmlElement() {
    XmlElement xmlElement = new XmlElement("<test>Test</test>");
    ExtensionObject extensionObject = ExtensionObject.of(xmlElement, NodeId.NULL_VALUE);

    LOGGER.debug("{}", extensionObject);
    assertEquals(xmlElement, extensionObject.getBody());
    assertInstanceOf(ExtensionObject.Xml.class, extensionObject);
  }

  @Test
  void ofJsonString() {
    String jsonString = "{\"test\": \"Test\"}";
    ExtensionObject extensionObject = ExtensionObject.of(jsonString, NodeId.NULL_VALUE);

    LOGGER.debug("{}", extensionObject);
    assertEquals(jsonString, extensionObject.getBody());
    assertInstanceOf(ExtensionObject.Json.class, extensionObject);
  }

  @Test
  void encodeNullValueYieldsNullExtensionObject() {
    var context = new DefaultEncodingContext();

    ExtensionObject encoded = ExtensionObject.encode(context, null);

    assertTrue(encoded.isNull());
    assertEquals(NodeId.NULL_VALUE, encoded.getEncodingOrTypeId());
  }

  @Test
  void encodeNullValueWithEncodingYieldsNullExtensionObject() {
    var context = new DefaultEncodingContext();

    ExtensionObject encoded =
        ExtensionObject.encode(context, null, OpcUaDefaultBinaryEncoding.getInstance());

    assertTrue(encoded.isNull());
    assertEquals(NodeId.NULL_VALUE, encoded.getEncodingOrTypeId());
  }
}
