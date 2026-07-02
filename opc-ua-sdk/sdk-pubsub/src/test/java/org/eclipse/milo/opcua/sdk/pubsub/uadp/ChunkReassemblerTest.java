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
import static org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned.ushort;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Duration;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicLong;
import org.eclipse.milo.opcua.sdk.pubsub.config.PublisherId;
import org.eclipse.milo.opcua.stack.core.StatusCodes;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UShort;
import org.junit.jupiter.api.Test;

/**
 * Boundary, bookkeeping, and eviction units for {@link ChunkReassembler}: coverage tracking with
 * out-of-order and duplicated chunks, the newer/older MessageSequenceNumber policy (Part 14 §7.2.3
 * window arithmetic, N=16), size and consistency rejections, the buffered-bytes budget with
 * least-recently-updated eviction, and idle-timeout eviction via an injectable clock.
 */
class ChunkReassemblerTest {

  private static final PublisherId PUBLISHER = PublisherId.ubyte(ubyte(42));
  private static final UShort WRITER_1 = ushort(1);
  private static final UShort WRITER_2 = ushort(2);

  private static final byte[] PAYLOAD = sequentialBytes(10);

  private final AtomicLong clock = new AtomicLong(0);

  private ChunkReassembler reassembler(int maxMessageSize, long maxBufferedBytes) {
    return new ChunkReassembler(
        maxMessageSize, maxBufferedBytes, Duration.ofSeconds(10), clock::get);
  }

  // region completion and coverage

  @Test
  void singleChunkCoveringWholePayloadCompletesImmediately() {
    ChunkReassembler r = reassembler(1024, 4096);

    ChunkReassembler.Result result = accept(r, WRITER_1, 1, 0, PAYLOAD.length, PAYLOAD);

    assertEquals(ChunkReassembler.Result.Status.COMPLETE, result.status());
    assertArrayEquals(PAYLOAD, result.payload());
    assertEquals(0, r.assemblyCount());
    assertEquals(0, r.bufferedBytes());
  }

  @Test
  void inOrderChunksComplete() {
    ChunkReassembler r = reassembler(1024, 4096);

    assertEquals(
        ChunkReassembler.Result.Status.PENDING,
        accept(r, WRITER_1, 1, 0, 10, Arrays.copyOfRange(PAYLOAD, 0, 6)).status());

    ChunkReassembler.Result result =
        accept(r, WRITER_1, 1, 6, 10, Arrays.copyOfRange(PAYLOAD, 6, 10));

    assertEquals(ChunkReassembler.Result.Status.COMPLETE, result.status());
    assertArrayEquals(PAYLOAD, result.payload());
    assertEquals(0, r.assemblyCount());
  }

  @Test
  void outOfOrderChunksComplete() {
    ChunkReassembler r = reassembler(1024, 4096);

    assertEquals(
        ChunkReassembler.Result.Status.PENDING,
        accept(r, WRITER_1, 1, 6, 10, Arrays.copyOfRange(PAYLOAD, 6, 10)).status());

    ChunkReassembler.Result result =
        accept(r, WRITER_1, 1, 0, 10, Arrays.copyOfRange(PAYLOAD, 0, 6));

    assertEquals(ChunkReassembler.Result.Status.COMPLETE, result.status());
    assertArrayEquals(PAYLOAD, result.payload());
  }

  /** Duplicated chunks (UDP) are tolerated: overlapping ranges are not double counted. */
  @Test
  void duplicateChunkIsTolerated() {
    ChunkReassembler r = reassembler(1024, 4096);

    byte[] firstHalf = Arrays.copyOfRange(PAYLOAD, 0, 6);
    assertEquals(
        ChunkReassembler.Result.Status.PENDING, accept(r, WRITER_1, 1, 0, 10, firstHalf).status());
    assertEquals(
        ChunkReassembler.Result.Status.PENDING, accept(r, WRITER_1, 1, 0, 10, firstHalf).status());

    ChunkReassembler.Result result =
        accept(r, WRITER_1, 1, 6, 10, Arrays.copyOfRange(PAYLOAD, 6, 10));

    assertEquals(ChunkReassembler.Result.Status.COMPLETE, result.status());
    assertArrayEquals(PAYLOAD, result.payload());
  }

  /** Overlapping chunks merge coverage correctly. */
  @Test
  void overlappingChunksComplete() {
    ChunkReassembler r = reassembler(1024, 4096);

    assertEquals(
        ChunkReassembler.Result.Status.PENDING,
        accept(r, WRITER_1, 1, 0, 10, Arrays.copyOfRange(PAYLOAD, 0, 7)).status());

    ChunkReassembler.Result result =
        accept(r, WRITER_1, 1, 4, 10, Arrays.copyOfRange(PAYLOAD, 4, 10));

    assertEquals(ChunkReassembler.Result.Status.COMPLETE, result.status());
    assertArrayEquals(PAYLOAD, result.payload());
  }

  /** Assemblies for different (PublisherId, DataSetWriterId) keys are independent. */
  @Test
  void keysAreIndependent() {
    ChunkReassembler r = reassembler(1024, 4096);

    accept(r, WRITER_1, 1, 0, 10, Arrays.copyOfRange(PAYLOAD, 0, 6));
    accept(r, WRITER_2, 1, 0, 10, Arrays.copyOfRange(PAYLOAD, 0, 6));
    assertEquals(2, r.assemblyCount());

    assertEquals(
        ChunkReassembler.Result.Status.COMPLETE,
        accept(r, WRITER_1, 1, 6, 10, Arrays.copyOfRange(PAYLOAD, 6, 10)).status());
    assertEquals(1, r.assemblyCount());
  }

  // endregion

  // region sequence-number policy

  /** A chunk of a newer payload generation abandons the incomplete previous assembly. */
  @Test
  void newerSequenceReplacesIncompleteAssembly() {
    ChunkReassembler r = reassembler(1024, 4096);

    accept(r, WRITER_1, 1, 0, 10, Arrays.copyOfRange(PAYLOAD, 0, 6));

    // Sequence 2 replaces the incomplete sequence-1 assembly...
    accept(r, WRITER_1, 2, 0, 10, Arrays.copyOfRange(PAYLOAD, 0, 6));
    assertEquals(1, r.assemblyCount());

    // ...whose final chunk can no longer complete it (it classifies stale).
    assertEquals(
        ChunkReassembler.Result.Status.STALE,
        accept(r, WRITER_1, 1, 6, 10, Arrays.copyOfRange(PAYLOAD, 6, 10)).status());

    // The sequence-2 assembly is unaffected and completes.
    assertEquals(
        ChunkReassembler.Result.Status.COMPLETE,
        accept(r, WRITER_1, 2, 6, 10, Arrays.copyOfRange(PAYLOAD, 6, 10)).status());
  }

  /** UInt16 wraparound: sequence 0 following 0xFFFF classifies newer (N=16 window math). */
  @Test
  void sequenceWraparoundClassifiesNewer() {
    ChunkReassembler r = reassembler(1024, 4096);

    accept(r, WRITER_1, 0xFFFF, 0, 10, Arrays.copyOfRange(PAYLOAD, 0, 6));

    // Sequence 0 replaces the 0xFFFF assembly rather than classifying stale.
    assertEquals(
        ChunkReassembler.Result.Status.PENDING,
        accept(r, WRITER_1, 0, 0, 10, Arrays.copyOfRange(PAYLOAD, 0, 6)).status());
    assertEquals(
        ChunkReassembler.Result.Status.COMPLETE,
        accept(r, WRITER_1, 0, 6, 10, Arrays.copyOfRange(PAYLOAD, 6, 10)).status());
  }

  // endregion

  // region rejections

  @Test
  void zeroTotalSizeIsRejected() {
    ChunkReassembler r = reassembler(1024, 4096);

    ChunkReassembler.Result result = accept(r, WRITER_1, 1, 0, 0, new byte[0]);

    assertEquals(ChunkReassembler.Result.Status.REJECTED, result.status());
    assertNotNull(result.statusCode());
    assertEquals(StatusCodes.Bad_DecodingError, result.statusCode().value());
  }

  @Test
  void oversizeTotalSizeIsRejected() {
    ChunkReassembler r = reassembler(16, 4096);

    ChunkReassembler.Result result = accept(r, WRITER_1, 1, 0, 32, new byte[4]);

    assertEquals(ChunkReassembler.Result.Status.REJECTED, result.status());
    assertNotNull(result.statusCode());
    assertEquals(StatusCodes.Bad_EncodingLimitsExceeded, result.statusCode().value());
    assertEquals(0, r.assemblyCount());
  }

  @Test
  void chunkBeyondTotalSizeIsRejected() {
    ChunkReassembler r = reassembler(1024, 4096);

    ChunkReassembler.Result result = accept(r, WRITER_1, 1, 8, 10, new byte[4]);

    assertEquals(ChunkReassembler.Result.Status.REJECTED, result.status());
    assertNotNull(result.statusCode());
    assertEquals(StatusCodes.Bad_DecodingError, result.statusCode().value());
  }

  /** A TotalSize mismatch within one generation poisons and discards the assembly. */
  @Test
  void totalSizeMismatchDiscardsAssembly() {
    ChunkReassembler r = reassembler(1024, 4096);

    accept(r, WRITER_1, 1, 0, 10, Arrays.copyOfRange(PAYLOAD, 0, 6));
    assertEquals(1, r.assemblyCount());

    ChunkReassembler.Result result = accept(r, WRITER_1, 1, 6, 12, new byte[4]);

    assertEquals(ChunkReassembler.Result.Status.REJECTED, result.status());
    assertEquals(0, r.assemblyCount());
    assertEquals(0, r.bufferedBytes());
  }

  // endregion

  // region bounds and eviction

  /** Budget eviction: the least-recently-updated assembly is evicted for a new one. */
  @Test
  void budgetEvictsLeastRecentlyUpdatedAssembly() {
    // Each assembly is charged max(totalSize, 1024) bytes; the budget fits exactly two.
    ChunkReassembler r = reassembler(1024, 2048);

    accept(r, WRITER_1, 1, 0, 10, Arrays.copyOfRange(PAYLOAD, 0, 6));
    accept(r, WRITER_2, 1, 0, 10, Arrays.copyOfRange(PAYLOAD, 0, 6));
    assertEquals(2, r.assemblyCount());
    assertEquals(2048, r.bufferedBytes());

    // Touch WRITER_1 so WRITER_2 becomes least recently updated.
    accept(r, WRITER_1, 1, 0, 10, Arrays.copyOfRange(PAYLOAD, 0, 6));

    // A third assembly evicts WRITER_2's (the least recently updated one).
    accept(r, ushort(3), 1, 0, 10, Arrays.copyOfRange(PAYLOAD, 0, 6));
    assertEquals(2, r.assemblyCount());
    assertEquals(2048, r.bufferedBytes());

    // WRITER_1's assembly survived the eviction and completes (freeing its budget charge).
    assertEquals(
        ChunkReassembler.Result.Status.COMPLETE,
        accept(r, WRITER_1, 1, 6, 10, Arrays.copyOfRange(PAYLOAD, 6, 10)).status());

    // WRITER_2's final chunk no longer completes anything: its assembly was evicted, so this
    // chunk starts a fresh, incomplete assembly.
    assertEquals(
        ChunkReassembler.Result.Status.PENDING,
        accept(r, WRITER_2, 1, 6, 10, Arrays.copyOfRange(PAYLOAD, 6, 10)).status());
  }

  /** Idle assemblies are discarded lazily once the idle timeout elapses. */
  @Test
  void idleAssembliesAreEvicted() {
    ChunkReassembler r = reassembler(1024, 4096);

    accept(r, WRITER_1, 1, 0, 10, Arrays.copyOfRange(PAYLOAD, 0, 6));
    assertEquals(1, r.assemblyCount());

    // Advance past the 10-second idle timeout; the next accept on ANY key evicts it.
    clock.addAndGet(Duration.ofSeconds(11).toNanos());

    accept(r, WRITER_2, 1, 0, 10, Arrays.copyOfRange(PAYLOAD, 0, 6));
    assertEquals(1, r.assemblyCount());

    // WRITER_1's final chunk starts over instead of completing.
    assertEquals(
        ChunkReassembler.Result.Status.PENDING,
        accept(r, WRITER_1, 1, 6, 10, Arrays.copyOfRange(PAYLOAD, 6, 10)).status());
  }

  @Test
  void clearDiscardsAllState() {
    ChunkReassembler r = reassembler(1024, 4096);

    accept(r, WRITER_1, 1, 0, 10, Arrays.copyOfRange(PAYLOAD, 0, 6));
    accept(r, WRITER_2, 1, 0, 10, Arrays.copyOfRange(PAYLOAD, 0, 6));

    r.clear();

    assertEquals(0, r.assemblyCount());
    assertEquals(0, r.bufferedBytes());
  }

  @Test
  void constructorRejectsNonPositiveBounds() {
    assertThrows(
        IllegalArgumentException.class,
        () -> ChunkReassembler.create(0, 4096, Duration.ofSeconds(10)));
    assertThrows(
        IllegalArgumentException.class,
        () -> ChunkReassembler.create(1024, 0, Duration.ofSeconds(10)));
    assertThrows(
        IllegalArgumentException.class, () -> ChunkReassembler.create(1024, 4096, Duration.ZERO));
  }

  // endregion

  // region secured / unsecured key-space isolation

  /**
   * PublisherId and DataSetWriterId are plaintext header fields even on secured chunks, so an
   * off-path attacker can spoof them in UNSECURED chunk NetworkMessages: without the secured
   * discriminator in the assembly key, a spoofed chunk with a newer MessageSequenceNumber would
   * abandon the in-progress secured reassembly (censoring every large secured message with no key
   * knowledge). Secured and unsecured chunks live in disjoint key spaces.
   */
  @Test
  void unsecuredChunkNeverAbandonsASecuredAssembly() {
    ChunkReassembler r = reassembler(1024, 4096);

    assertEquals(
        ChunkReassembler.Result.Status.PENDING,
        acceptSecured(r, WRITER_1, 5, 0, 10, Arrays.copyOfRange(PAYLOAD, 0, 6)).status());

    // the spoofed unsecured chunk carries the same (PublisherId, DataSetWriterId) and a NEWER
    // sequence number: it starts its own (unsecured) assembly instead of abandoning the secured
    // one
    assertEquals(
        ChunkReassembler.Result.Status.PENDING,
        accept(r, WRITER_1, 6, 0, 10, Arrays.copyOfRange(PAYLOAD, 0, 6)).status());
    assertEquals(2, r.assemblyCount());

    // the secured assembly is untouched and completes
    ChunkReassembler.Result result =
        acceptSecured(r, WRITER_1, 5, 6, 10, Arrays.copyOfRange(PAYLOAD, 6, 10));
    assertEquals(ChunkReassembler.Result.Status.COMPLETE, result.status());
    assertArrayEquals(PAYLOAD, result.payload());
  }

  /** The isolation holds in both directions: a secured chunk never joins an unsecured assembly. */
  @Test
  void securedChunkNeverAbandonsAnUnsecuredAssembly() {
    ChunkReassembler r = reassembler(1024, 4096);

    assertEquals(
        ChunkReassembler.Result.Status.PENDING,
        accept(r, WRITER_1, 5, 0, 10, Arrays.copyOfRange(PAYLOAD, 0, 6)).status());

    assertEquals(
        ChunkReassembler.Result.Status.PENDING,
        acceptSecured(r, WRITER_1, 6, 0, 10, Arrays.copyOfRange(PAYLOAD, 0, 6)).status());
    assertEquals(2, r.assemblyCount());

    ChunkReassembler.Result result =
        accept(r, WRITER_1, 5, 6, 10, Arrays.copyOfRange(PAYLOAD, 6, 10));
    assertEquals(ChunkReassembler.Result.Status.COMPLETE, result.status());
    assertArrayEquals(PAYLOAD, result.payload());
  }

  // endregion

  // region helpers

  private static byte[] sequentialBytes(int length) {
    byte[] bs = new byte[length];
    for (int i = 0; i < length; i++) {
      bs[i] = (byte) i;
    }
    return bs;
  }

  private static ChunkReassembler.Result accept(
      ChunkReassembler reassembler,
      UShort dataSetWriterId,
      int sequenceNumber,
      long chunkOffset,
      long totalSize,
      byte[] chunkData) {

    return reassembler.accept(
        PUBLISHER,
        dataSetWriterId,
        false,
        ushort(sequenceNumber),
        chunkOffset,
        totalSize,
        chunkData);
  }

  private static ChunkReassembler.Result acceptSecured(
      ChunkReassembler reassembler,
      UShort dataSetWriterId,
      int sequenceNumber,
      long chunkOffset,
      long totalSize,
      byte[] chunkData) {

    return reassembler.accept(
        PUBLISHER,
        dataSetWriterId,
        true,
        ushort(sequenceNumber),
        chunkOffset,
        totalSize,
        chunkData);
  }

  // endregion
}
