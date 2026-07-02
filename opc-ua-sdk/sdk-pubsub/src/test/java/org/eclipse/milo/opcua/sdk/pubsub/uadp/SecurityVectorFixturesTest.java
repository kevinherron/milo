/*
 * Copyright (c) 2026 the Eclipse Milo Authors
 *
 * This program and the accompanying materials are made
 * available under the terms of the Eclipse Public License 2.0
 * which is available at https://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 */

package org.eclipse.milo.opcua.sdk.pubsub.uadp;

import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.ubyte;
import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.uint;
import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.ushort;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;
import org.eclipse.milo.opcua.sdk.pubsub.config.DataSetWriterConfig;
import org.eclipse.milo.opcua.sdk.pubsub.config.PublishedDataSetRef;
import org.eclipse.milo.opcua.sdk.pubsub.config.PublisherId;
import org.eclipse.milo.opcua.sdk.pubsub.config.UadpDataSetWriterSettings;
import org.eclipse.milo.opcua.sdk.pubsub.config.UadpWriterGroupSettings;
import org.eclipse.milo.opcua.sdk.pubsub.config.WriterGroupConfig;
import org.eclipse.milo.opcua.sdk.pubsub.security.MessageSecurityContext;
import org.eclipse.milo.opcua.sdk.pubsub.security.PubSubSecurityPolicy;
import org.eclipse.milo.opcua.sdk.pubsub.security.SecurityContextResolver;
import org.eclipse.milo.opcua.sdk.pubsub.security.SecurityKeyMaterial;
import org.eclipse.milo.opcua.stack.core.UaException;
import org.eclipse.milo.opcua.stack.core.encoding.DefaultEncodingContext;
import org.eclipse.milo.opcua.stack.core.encoding.EncodingContext;
import org.eclipse.milo.opcua.stack.core.types.builtin.DataValue;
import org.eclipse.milo.opcua.stack.core.types.builtin.StatusCode;
import org.eclipse.milo.opcua.stack.core.types.builtin.Variant;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UInteger;
import org.eclipse.milo.opcua.stack.core.types.enumerated.MessageSecurityMode;
import org.eclipse.milo.opcua.stack.core.types.structured.ConfigurationVersionDataType;
import org.eclipse.milo.opcua.stack.core.types.structured.DataSetFieldContentMask;
import org.eclipse.milo.opcua.stack.core.types.structured.UadpDataSetMessageContentMask;
import org.eclipse.milo.opcua.stack.core.types.structured.UadpNetworkMessageContentMask;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Verified decode of the checked-in secured-NetworkMessage fixtures under {@code
 * src/test/resources/security-vectors/} (K20: computed vectors as checked-in test resources).
 *
 * <p>Each fixture is a {@code <name>.bin} (the full secured NetworkMessage bytes) plus a {@code
 * <name>.keys.json} (policy, keys, keyNonce, messageNonce, tokenId, mode) — the format is
 * documented in that directory's README.md. Every {@code *.bin} present is discovered and decoded
 * through {@link UadpNetworkMessageDecoder} with a static resolver built from its keys file, so
 * vectors captured from other implementations (open62541, OPC Labs) drop in without test changes.
 *
 * <p>The {@code computed-*} fixtures were generated and are independently re-verified — without any
 * Milo code — by {@code milo-pubsub-notes/captures/check-phase4-vectors.py} (Python stdlib
 * HMAC-SHA256, AES-CTR via the openssl CLI cross-checked against the {@code cryptography} package).
 * For those this test additionally asserts bit-exact encoder reproduction with the recorded
 * MessageNonce injected, closing the loop: hand-derived spec layout == independent recompute ==
 * checked-in bytes == Milo encoder output, and the Milo decoder verifies it.
 */
class SecurityVectorFixturesTest {

  private static final String COMPUTED_SIGN_AES256 = "computed-sign-aes256ctr";
  private static final String COMPUTED_ENCRYPT_AES128 = "computed-signandencrypt-aes128ctr";
  private static final String COMPUTED_ENCRYPT_AES256 = "computed-signandencrypt-aes256ctr";

  private final EncodingContext encodingContext = new DefaultEncodingContext();

  /** The three computed vectors pinned by K20 must be present in the resources directory. */
  @Test
  void pinnedComputedVectorsPresent() throws Exception {
    List<String> names = vectors().map(Object::toString).toList();

    assertTrue(names.contains(COMPUTED_SIGN_AES256), names.toString());
    assertTrue(names.contains(COMPUTED_ENCRYPT_AES128), names.toString());
    assertTrue(names.contains(COMPUTED_ENCRYPT_AES256), names.toString());
  }

  /**
   * Every fixture decodes to a verified message: no failure, the SecurityHeader surface matches the
   * keys file, and at least one valid DataSetMessage is delivered.
   */
  @ParameterizedTest(name = "{0}")
  @MethodSource("vectors")
  void fixtureDecodesVerified(String name) throws Exception {
    byte[] message = Files.readAllBytes(fixtureDirectory().resolve(name + ".bin"));
    KeysFile keys = readKeysFile(name);

    DecodedNetworkMessage decoded = decode(message, resolver(keys.material()));

    assertNull(decoded.failure());
    assertNotNull(decoded.security());
    assertEquals(keys.mode(), decoded.security().mode());
    assertEquals(keys.tokenId(), decoded.security().securityTokenId());

    assertTrue(decoded.messages().size() >= 1, "at least one DataSetMessage");
    decoded.messages().forEach(m -> assertTrue(m.valid()));
  }

  /** A wrong signing key never yields a verified decode (guards against a no-op verify path). */
  @ParameterizedTest(name = "{0}")
  @MethodSource("vectors")
  void fixtureRejectedWithWrongSigningKey(String name) throws Exception {
    byte[] message = Files.readAllBytes(fixtureDirectory().resolve(name + ".bin"));
    KeysFile keys = readKeysFile(name);

    byte[] wrongSigningKey = keys.signingKey().clone();
    wrongSigningKey[0] ^= 0x01;
    SecurityKeyMaterial material =
        SecurityKeyMaterial.of(
            keys.policy(), wrongSigningKey, keys.encryptingKey(), keys.keyNonce());

    DecodedNetworkMessage decoded = decode(message, resolver(material));

    assertTrue(decoded.messages().isEmpty());
    assertNotNull(decoded.failure());
    assertEquals(
        DecodedNetworkMessage.Failure.Reason.SIGNATURE_INVALID, decoded.failure().reason());
  }

  /**
   * The computed vectors decode to exactly the documented payload: one key frame from
   * DataSetWriterId 1 with fields Int32 42 and Boolean true.
   */
  @ParameterizedTest(name = "{0}")
  @MethodSource("computedVectors")
  void computedFixtureDecodesToDocumentedFields(String name) throws Exception {
    byte[] message = Files.readAllBytes(fixtureDirectory().resolve(name + ".bin"));
    KeysFile keys = readKeysFile(name);

    DecodedNetworkMessage decoded = decode(message, resolver(keys.material()));

    assertNull(decoded.failure());
    assertEquals(1, decoded.messages().size());
    DecodedDataSetMessage dataSetMessage = decoded.messages().get(0);
    assertEquals(ushort(1), dataSetMessage.dataSetWriterId());
    assertEquals(
        List.of(
            new DecodedField(0, goodValue(Variant.ofInt32(42))),
            new DecodedField(1, goodValue(Variant.ofBoolean(true)))),
        dataSetMessage.fields());
  }

  /**
   * The Milo encoder, fed the documented writer/group shape and the recorded MessageNonce,
   * reproduces the computed fixture bytes bit-exactly (encode-direction K20 check against the
   * independent Python/openssl recompute that generated the files).
   */
  @ParameterizedTest(name = "{0}")
  @MethodSource("computedVectors")
  void computedFixtureReproducedByEncoder(String name) throws Exception {
    byte[] expected = Files.readAllBytes(fixtureDirectory().resolve(name + ".bin"));
    KeysFile keys = readKeysFile(name);

    MessageSecurityContext securityContext =
        MessageSecurityContext.of(
            keys.mode(), keys.policy(), keys.tokenId(), keys.material(), keys::messageNonce);

    assertArrayEquals(expected, encodeToBytes(encodeContext(securityContext)));
  }

  // region fixture discovery and keys files

  static Stream<String> vectors() throws Exception {
    try (Stream<Path> files = Files.list(fixtureDirectory())) {
      return files
          .map(path -> path.getFileName().toString())
          .filter(fileName -> fileName.endsWith(".bin"))
          .map(fileName -> fileName.substring(0, fileName.length() - ".bin".length()))
          .sorted()
          .toList()
          .stream();
    }
  }

  static Stream<String> computedVectors() throws Exception {
    return vectors().filter(name -> name.startsWith("computed-"));
  }

  private static Path fixtureDirectory() throws Exception {
    URL url = SecurityVectorFixturesTest.class.getResource("/security-vectors");
    assertNotNull(url, "security-vectors test resources on the classpath");
    return Path.of(url.toURI());
  }

  /** The parsed {@code <name>.keys.json} companion; format per the directory README. */
  private record KeysFile(
      MessageSecurityMode mode,
      PubSubSecurityPolicy policy,
      byte[] signingKey,
      byte[] encryptingKey,
      byte[] keyNonce,
      byte[] messageNonce,
      UInteger tokenId) {

    SecurityKeyMaterial material() {
      return SecurityKeyMaterial.of(policy, signingKey, encryptingKey, keyNonce);
    }
  }

  private static KeysFile readKeysFile(String name) throws Exception {
    Path path = fixtureDirectory().resolve(name + ".keys.json");
    JsonObject json = JsonParser.parseString(Files.readString(path)).getAsJsonObject();

    Optional<PubSubSecurityPolicy> policy =
        PubSubSecurityPolicy.fromUri(json.get("securityPolicyUri").getAsString());
    assertTrue(policy.isPresent(), "supported securityPolicyUri in " + path.getFileName());

    HexFormat hex = HexFormat.of();
    return new KeysFile(
        MessageSecurityMode.valueOf(json.get("mode").getAsString()),
        policy.orElseThrow(),
        hex.parseHex(json.get("signingKey").getAsString()),
        hex.parseHex(json.get("encryptingKey").getAsString()),
        hex.parseHex(json.get("keyNonce").getAsString()),
        hex.parseHex(json.get("messageNonce").getAsString()),
        uint(json.get("tokenId").getAsLong()));
  }

  // endregion

  // region helpers (duplicated per class by convention)

  private static SecurityContextResolver resolver(SecurityKeyMaterial material) {
    return (publisherId, writerGroupId, dataSetWriterIds, receivedMode, securityTokenId) ->
        Optional.of(material);
  }

  private static DataValue goodValue(Variant value) {
    return new DataValue(value, StatusCode.GOOD, null, null, null, null);
  }

  private DecodedNetworkMessage decode(byte[] message, SecurityContextResolver resolver) {
    ByteBuf buffer = Unpooled.wrappedBuffer(message);
    try {
      return UadpNetworkMessageDecoder.decode(DecodeContext.of(encodingContext, resolver), buffer);
    } finally {
      buffer.release();
    }
  }

  /**
   * The writer/group shape all computed vectors were built from (identical to UadpSecurityCodecTest
   * and the README provenance section): PublisherId Byte 42, NM mask PublisherId|PayloadHeader, one
   * writer with DataSetWriterId 1 and all-zero DSM/field masks.
   */
  private EncodeContext encodeContext(MessageSecurityContext securityContext) {
    DataSetWriterConfig writer =
        DataSetWriterConfig.builder("writer-1")
            .dataSet(new PublishedDataSetRef("ds"))
            .dataSetWriterId(ushort(1))
            .fieldContentMask(new DataSetFieldContentMask(uint(0x00)))
            .settings(
                UadpDataSetWriterSettings.builder()
                    .dataSetMessageContentMask(new UadpDataSetMessageContentMask(uint(0x00)))
                    .build())
            .build();

    // NM mask 0x41: bit 0 PublisherId | bit 6 PayloadHeader (Table 97).
    WriterGroupConfig group =
        WriterGroupConfig.builder("group")
            .writerGroupId(ushort(258))
            .messageSettings(
                UadpWriterGroupSettings.builder()
                    .networkMessageContentMask(new UadpNetworkMessageContentMask(uint(0x41)))
                    .build())
            .dataSetWriter(writer)
            .build();

    DataSetMessageDraft draft =
        DataSetMessageDraft.of(
            writer,
            uint(0),
            null,
            null,
            new ConfigurationVersionDataType(uint(0), uint(0)),
            false,
            List.of(goodValue(Variant.ofInt32(42)), goodValue(Variant.ofBoolean(true))));

    return EncodeContext.of(
        encodingContext,
        PublisherId.ubyte(ubyte(42)),
        group,
        uint(1),
        ushort(1),
        ushort(16),
        null,
        List.of(draft),
        securityContext);
  }

  private byte[] encodeToBytes(EncodeContext context) throws UaException {
    List<EncodedNetworkMessage> encoded = new UadpMessageMapping().encode(context);
    assertEquals(1, encoded.size(), "UADP encode returns a singleton list");
    try {
      return ByteBufUtil.getBytes(encoded.get(0).data());
    } finally {
      encoded.get(0).data().release();
    }
  }

  // endregion
}
