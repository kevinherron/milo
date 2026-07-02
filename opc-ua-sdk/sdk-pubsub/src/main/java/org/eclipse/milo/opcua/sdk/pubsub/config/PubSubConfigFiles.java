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

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import java.util.Arrays;
import org.eclipse.milo.opcua.stack.core.StatusCodes;
import org.eclipse.milo.opcua.stack.core.UaException;
import org.eclipse.milo.opcua.stack.core.UaSerializationException;
import org.eclipse.milo.opcua.stack.core.encoding.EncodingContext;
import org.eclipse.milo.opcua.stack.core.encoding.binary.OpcUaBinaryDecoder;
import org.eclipse.milo.opcua.stack.core.encoding.binary.OpcUaBinaryEncoder;
import org.eclipse.milo.opcua.stack.core.types.UaStructuredType;
import org.eclipse.milo.opcua.stack.core.types.builtin.ExtensionObject;
import org.eclipse.milo.opcua.stack.core.types.builtin.Variant;
import org.eclipse.milo.opcua.stack.core.types.structured.PubSubConfiguration2DataType;
import org.eclipse.milo.opcua.stack.core.types.structured.UABinaryFileDataType;
import org.eclipse.milo.opcua.stack.core.util.BufferUtil;

/**
 * Reads and writes a PubSub configuration as an OPC UA Binary file, per OPC UA Part 5 §12.36 and
 * Part 14 §6.2.12.1 (Table 88): the file is a {@link UABinaryFileDataType}, encoded as an {@link
 * ExtensionObject}, whose {@code Body} is a {@link PubSubConfiguration2DataType} (also carried as
 * an {@link ExtensionObject}). This is the {@code .uabinary} on-disk convention and doubles as the
 * buffer codec for the {@code PubSubConfigurationType} FileType {@code CloseAndUpdate} flow (Part
 * 14 §9.1.3.7).
 *
 * <p>The {@code DataTypeSchemaHeader} {@code Namespaces} array is populated per Table 88 with the
 * namespace URIs used by NodeIds in the body — every namespace in the encoding context's {@link
 * org.eclipse.milo.opcua.stack.core.NamespaceTable} except the OPC UA namespace (index 0), which is
 * always skipped. {@code schemaLocation}, {@code fileHeader}, and the structure/enum/simple data
 * type arrays are left null (Milo's PubSub configuration uses no application-defined structures in
 * its configuration properties).
 *
 * <p>Because the namespace indices in the body are written as the encoding context's indices, the
 * caller must {@link #read} with an encoding context whose NamespaceArray agrees with the one used
 * to {@link #write} (for a live server this is "a Session with the Server", Part 14 §9.1.3.7.1).
 */
public final class PubSubConfigFiles {

  private PubSubConfigFiles() {}

  /**
   * Encode {@code configuration} as a {@code .uabinary} PubSub configuration file.
   *
   * @param configuration the configuration to encode.
   * @param context the {@link EncodingContext} whose NamespaceTable supplies the file's namespace
   *     header and the body's namespace indices.
   * @return the encoded file bytes.
   * @throws UaSerializationException if encoding fails.
   */
  public static byte[] write(PubSubConfiguration2DataType configuration, EncodingContext context) {
    UABinaryFileDataType file = toBinaryFile(configuration, context);

    ByteBuf buffer = BufferUtil.pooledBuffer();
    try {
      OpcUaBinaryEncoder encoder = new OpcUaBinaryEncoder(context).setBuffer(buffer);
      encoder.encodeExtensionObject("File", ExtensionObject.encode(context, file));

      byte[] bytes = new byte[buffer.readableBytes()];
      buffer.readBytes(bytes);
      return bytes;
    } finally {
      buffer.release();
    }
  }

  /**
   * Wrap {@code configuration} in a {@link UABinaryFileDataType} with the Table 88 header, without
   * serializing it — useful for callers that want to inspect or re-encode the file structure.
   *
   * @param configuration the configuration to wrap.
   * @param context the {@link EncodingContext} whose NamespaceTable supplies the namespace header.
   * @return the {@link UABinaryFileDataType} carrying {@code configuration} as its {@code Body}.
   */
  public static UABinaryFileDataType toBinaryFile(
      PubSubConfiguration2DataType configuration, EncodingContext context) {

    // Table 88: the OPC UA namespace (index 0) is skipped; the remaining namespaces are listed in
    // NamespaceArray order so the reading Session can map the body's namespace indices.
    String[] all = context.getNamespaceTable().toArray();
    String[] namespaces = all.length > 1 ? Arrays.copyOfRange(all, 1, all.length) : new String[0];

    return new UABinaryFileDataType(
        namespaces,
        null,
        null,
        null,
        null,
        null,
        new Variant(ExtensionObject.encode(context, configuration)));
  }

  /**
   * Decode a {@code .uabinary} PubSub configuration file produced by {@link #write}.
   *
   * @param bytes the encoded file bytes.
   * @param context the {@link EncodingContext} used to decode; its NamespaceArray must agree with
   *     the one used to write the file.
   * @return the decoded {@link PubSubConfiguration2DataType}.
   * @throws UaException with {@code Bad_TypeMismatch} if the content is not a {@link
   *     UABinaryFileDataType} whose {@code Body} is a {@link PubSubConfiguration2DataType} (the
   *     Part 14 §9.1.3.7.6 {@code CloseAndUpdate} contract), or with {@code Bad_DecodingError} if
   *     the bytes cannot be decoded at all.
   */
  public static PubSubConfiguration2DataType read(byte[] bytes, EncodingContext context)
      throws UaException {

    ExtensionObject fileObject;
    ByteBuf buffer = Unpooled.wrappedBuffer(bytes);
    try {
      OpcUaBinaryDecoder decoder = new OpcUaBinaryDecoder(context).setBuffer(buffer);
      fileObject = decoder.decodeExtensionObject("File");
    } catch (UaSerializationException e) {
      throw new UaException(StatusCodes.Bad_DecodingError, "not a valid UABinaryFile", e);
    }

    UaStructuredType fileStruct;
    try {
      fileStruct = fileObject.decode(context);
    } catch (UaSerializationException e) {
      throw new UaException(
          StatusCodes.Bad_TypeMismatch, "file content is not a UABinaryFileDataType", e);
    }

    if (!(fileStruct instanceof UABinaryFileDataType file)) {
      throw new UaException(
          StatusCodes.Bad_TypeMismatch, "file content is not a UABinaryFileDataType");
    }

    Object body = file.getBody().getValue();
    if (!(body instanceof ExtensionObject bodyObject)) {
      throw new UaException(
          StatusCodes.Bad_TypeMismatch, "file body is not a PubSubConfiguration2DataType");
    }

    UaStructuredType bodyStruct;
    try {
      bodyStruct = bodyObject.decode(context);
    } catch (UaSerializationException e) {
      throw new UaException(
          StatusCodes.Bad_TypeMismatch, "file body is not a PubSubConfiguration2DataType", e);
    }

    if (!(bodyStruct instanceof PubSubConfiguration2DataType configuration)) {
      throw new UaException(
          StatusCodes.Bad_TypeMismatch, "file body is not a PubSubConfiguration2DataType");
    }

    return configuration;
  }
}
