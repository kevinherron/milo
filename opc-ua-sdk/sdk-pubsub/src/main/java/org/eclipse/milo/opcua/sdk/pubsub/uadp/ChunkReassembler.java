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

import java.time.Duration;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;
import java.util.function.LongSupplier;
import org.eclipse.milo.opcua.sdk.pubsub.config.PublisherId;
import org.eclipse.milo.opcua.stack.core.StatusCodes;
import org.eclipse.milo.opcua.stack.core.types.builtin.StatusCode;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UShort;
import org.jspecify.annotations.Nullable;

/**
 * Reassembles chunked UADP NetworkMessage payloads (OPC UA Part 14 §7.2.4.4.4, Table 159) back into
 * the original DataSetMessage bytes.
 *
 * <p>Each chunk arrives as its own complete NetworkMessage, secured individually — the decoder
 * verifies and decrypts every chunk NetworkMessage <b>before</b> handing its plaintext chunk fields
 * here, so this class never sees ciphertext. Assemblies are keyed by (PublisherId, DataSetWriterId,
 * secured): a chunk NetworkMessage carries exactly one DataSetWriterId in its PayloadHeader (Table
 * 158) and "A chunk NetworkMessage can only contain chunked payload of one DataSetMessage". The
 * {@code secured} discriminator — whether the chunk arrived in a signature-verified NetworkMessage
 * — keeps unauthenticated input out of secured assemblies: PublisherId and DataSetWriterId are
 * plaintext header fields even on secured chunks, so without it an off-path attacker spoofing them
 * in UNSECURED chunk NetworkMessages could abandon an in-progress secured reassembly via the
 * newer-sequence rule below, censoring every large secured message with no key knowledge
 * (§7.2.4.4.4 secures each chunk individually; the reassembly state deciding whether a secured
 * message ever completes must not be mutable by unsigned input). At most one assembly is in
 * progress per key — the Table 159 MessageSequenceNumber identifies the payload generation, and per
 * its note a chunk bearing a <i>newer</i> sequence number (Part 14 §7.2.3 window arithmetic, N=16)
 * abandons the incomplete previous assembly, while chunks of an <i>older</i> generation are dropped
 * as stale. Chunks may arrive out of order and duplicated (UDP); coverage is tracked by byte range,
 * so duplicates and overlaps are tolerated.
 *
 * <p><b>Ownership and threading.</b> This is the only stateful piece of the otherwise stateless
 * UADP codec: the subscriber runtime creates one instance per connection, retains it across decode
 * calls, and carries it to the codec on {@link DecodeContext#chunkReassembler()} (a {@code null}
 * slot there means chunked NetworkMessages are dropped with {@code Bad_NotSupported}). It is <b>not
 * thread-safe</b>: like the rest of a connection's decode path it must be confined to the
 * connection's serialized dispatch thread. {@link #clear()} discards all state, e.g. when the
 * owning connection restarts.
 *
 * <p><b>Bounded memory and eviction policy.</b>
 *
 * <ul>
 *   <li>A chunk whose TotalSize exceeds {@code maxMessageSize} is rejected outright (the original
 *       payload would never be deliverable). The default is {@value #DEFAULT_MAX_MESSAGE_SIZE}
 *       bytes — generous against the Part 14 §7.3.2.1 per-NetworkMessage UDP cap of 65535 bytes,
 *       since a chunked original deliberately exceeds one NetworkMessage; owners may size it from
 *       reader-group limits instead.
 *   <li>Total buffered bytes across all assemblies are capped at {@code maxBufferedBytes} (default
 *       {@value #DEFAULT_MAX_BUFFERED_BYTES}); each assembly is charged {@code max(TotalSize,
 *       1024)} so tiny assemblies cannot proliferate unboundedly. When a new assembly would exceed
 *       the budget, least-recently-updated assemblies are evicted until it fits.
 *   <li>Assemblies idle longer than {@code idleTimeout} (default 10 seconds; no chunk received on
 *       them) are discarded lazily on the next {@link #accept} call. Part 14 defines no chunk
 *       staleness rule; owners may derive the timeout from 2× messageReceiveTimeout to mirror the
 *       §7.2.3 record-discard convention.
 * </ul>
 *
 * <p>A limitation of the one-assembly-per-key model: a duplicate chunk arriving after its message
 * completed starts a fresh (never-completing) assembly, which is bounded by the newer-sequence
 * replacement and idle eviction above.
 */
public final class ChunkReassembler {

  /** The default per-message TotalSize cap in bytes: 1 MiB. */
  public static final int DEFAULT_MAX_MESSAGE_SIZE = 1024 * 1024;

  /** The default total buffered-bytes budget across all assemblies: 4 MiB. */
  public static final long DEFAULT_MAX_BUFFERED_BYTES = 4L * 1024 * 1024;

  /** The default idle timeout after which an incomplete assembly is discarded. */
  public static final Duration DEFAULT_IDLE_TIMEOUT = Duration.ofSeconds(10);

  /**
   * The minimum budget charge per assembly, bounding the number of concurrent assemblies to {@code
   * maxBufferedBytes / 1024}.
   */
  private static final long MIN_ASSEMBLY_CHARGE = 1024;

  /** Assemblies in least-recently-updated iteration order (access-order LinkedHashMap). */
  private final LinkedHashMap<Key, Assembly> assemblies = new LinkedHashMap<>(16, 0.75f, true);

  private long bufferedBytes = 0;

  private final int maxMessageSize;
  private final long maxBufferedBytes;
  private final long idleTimeoutNanos;
  private final LongSupplier nanoTime;

  ChunkReassembler(
      int maxMessageSize, long maxBufferedBytes, Duration idleTimeout, LongSupplier nanoTime) {

    if (maxMessageSize <= 0) {
      throw new IllegalArgumentException("maxMessageSize must be positive: " + maxMessageSize);
    }
    if (maxBufferedBytes <= 0) {
      throw new IllegalArgumentException("maxBufferedBytes must be positive: " + maxBufferedBytes);
    }
    if (idleTimeout.isNegative() || idleTimeout.isZero()) {
      throw new IllegalArgumentException("idleTimeout must be positive: " + idleTimeout);
    }

    this.maxMessageSize = maxMessageSize;
    this.maxBufferedBytes = maxBufferedBytes;
    this.idleTimeoutNanos = idleTimeout.toNanos();
    this.nanoTime = nanoTime;
  }

  /**
   * Create a {@link ChunkReassembler} with the default bounds: {@value #DEFAULT_MAX_MESSAGE_SIZE}
   * bytes per message, {@value #DEFAULT_MAX_BUFFERED_BYTES} bytes buffered in total, and a
   * 10-second idle timeout.
   *
   * @return a new {@link ChunkReassembler}.
   */
  public static ChunkReassembler create() {
    return new ChunkReassembler(
        DEFAULT_MAX_MESSAGE_SIZE,
        DEFAULT_MAX_BUFFERED_BYTES,
        DEFAULT_IDLE_TIMEOUT,
        System::nanoTime);
  }

  /**
   * Create a {@link ChunkReassembler} with explicit bounds.
   *
   * @param maxMessageSize the maximum TotalSize of a reassembled message in bytes; chunks of larger
   *     messages are rejected.
   * @param maxBufferedBytes the total buffered-bytes budget across all in-progress assemblies;
   *     least-recently-updated assemblies are evicted to stay within it.
   * @param idleTimeout how long an incomplete assembly may go without receiving a chunk before it
   *     is discarded.
   * @return a new {@link ChunkReassembler}.
   * @throws IllegalArgumentException if any bound is not positive.
   */
  public static ChunkReassembler create(
      int maxMessageSize, long maxBufferedBytes, Duration idleTimeout) {

    return new ChunkReassembler(maxMessageSize, maxBufferedBytes, idleTimeout, System::nanoTime);
  }

  /** Discard all in-progress assemblies, e.g. when the owning connection restarts. */
  public void clear() {
    assemblies.clear();
    bufferedBytes = 0;
  }

  /**
   * Offer one verified, decrypted chunk (the Table 159 fields of one chunk NetworkMessage) to the
   * assembly identified by ({@code publisherId}, {@code dataSetWriterId}, {@code secured}).
   *
   * @param publisherId the PublisherId from the NetworkMessage header, or {@code null} if not
   *     present on the wire (participates in the key).
   * @param dataSetWriterId the single DataSetWriterId from the chunk PayloadHeader (Table 158).
   * @param secured whether the chunk NetworkMessage passed signature verification (participates in
   *     the key: secured and unsecured chunks never share an assembly, so a spoofed unsecured chunk
   *     can neither abandon nor contribute to a secured reassembly — see the class Javadoc).
   * @param messageSequenceNumber the Table 159 MessageSequenceNumber identifying the payload
   *     generation.
   * @param chunkOffset the Table 159 ChunkOffset: the byte offset of this chunk's data in the
   *     original payload.
   * @param totalSize the Table 159 TotalSize: the total size of the original payload in bytes.
   * @param chunkData this chunk's piece of the original payload.
   * @return the outcome; {@link Result#payload()} carries the complete original payload when {@link
   *     Result#status()} is {@link Result.Status#COMPLETE}.
   */
  Result accept(
      @Nullable PublisherId publisherId,
      UShort dataSetWriterId,
      boolean secured,
      UShort messageSequenceNumber,
      long chunkOffset,
      long totalSize,
      byte[] chunkData) {

    long now = nanoTime.getAsLong();
    evictIdle(now);

    var key = new Key(publisherId, dataSetWriterId, secured);
    int sequenceNumber = messageSequenceNumber.intValue();

    Assembly existing = assemblies.get(key);
    if (existing != null) {
      if (existing.sequenceNumber == sequenceNumber) {
        if (totalSize != existing.totalSize) {
          discard(key, existing);
          return Result.rejected(
              new StatusCode(StatusCodes.Bad_DecodingError),
              "chunk TotalSize %d does not match the assembly's TotalSize %d"
                  .formatted(totalSize, existing.totalSize));
        }
        if (chunkOffset + chunkData.length > totalSize) {
          discard(key, existing);
          return Result.rejected(
              new StatusCode(StatusCodes.Bad_DecodingError),
              "chunk [%d, %d) exceeds TotalSize %d"
                  .formatted(chunkOffset, chunkOffset + chunkData.length, totalSize));
        }
        if (existing.write(chunkOffset, chunkData, now)) {
          discard(key, existing);
          return Result.complete(existing.data);
        }
        return Result.pending();
      } else if (isNewer(sequenceNumber, existing.sequenceNumber)) {
        // Table 159: a chunk of the next payload abandons the incomplete previous payload.
        discard(key, existing);
      } else {
        // A chunk of an already-abandoned older payload generation.
        return Result.stale();
      }
    }

    if (totalSize <= 0) {
      return Result.rejected(
          new StatusCode(StatusCodes.Bad_DecodingError),
          "chunk TotalSize must be positive: " + totalSize);
    }
    if (totalSize > maxMessageSize) {
      return Result.rejected(
          new StatusCode(StatusCodes.Bad_EncodingLimitsExceeded),
          "chunk TotalSize %d exceeds the maximum message size %d"
              .formatted(totalSize, maxMessageSize));
    }
    if (chunkOffset + chunkData.length > totalSize) {
      return Result.rejected(
          new StatusCode(StatusCodes.Bad_DecodingError),
          "chunk [%d, %d) exceeds TotalSize %d"
              .formatted(chunkOffset, chunkOffset + chunkData.length, totalSize));
    }

    long charge = Math.max(totalSize, MIN_ASSEMBLY_CHARGE);
    if (charge > maxBufferedBytes) {
      return Result.rejected(
          new StatusCode(StatusCodes.Bad_EncodingLimitsExceeded),
          "chunk TotalSize %d exceeds the reassembly buffer budget %d"
              .formatted(totalSize, maxBufferedBytes));
    }
    evictForBudget(charge);

    var assembly = new Assembly(sequenceNumber, (int) totalSize, charge);
    if (assembly.write(chunkOffset, chunkData, now)) {
      // A single chunk covering the whole payload; nothing to buffer.
      return Result.complete(assembly.data);
    }

    assemblies.put(key, assembly);
    bufferedBytes += charge;

    return Result.pending();
  }

  /** The number of in-progress assemblies; test seam. */
  int assemblyCount() {
    return assemblies.size();
  }

  /** The buffered-bytes budget currently consumed; test seam. */
  long bufferedBytes() {
    return bufferedBytes;
  }

  private void discard(Key key, Assembly assembly) {
    if (assemblies.remove(key) != null) {
      bufferedBytes -= assembly.charge;
    }
  }

  private void evictIdle(long now) {
    Iterator<Map.Entry<Key, Assembly>> iterator = assemblies.entrySet().iterator();
    while (iterator.hasNext()) {
      Assembly assembly = iterator.next().getValue();
      if (now - assembly.lastUpdateNanos > idleTimeoutNanos) {
        iterator.remove();
        bufferedBytes -= assembly.charge;
      }
    }
  }

  private void evictForBudget(long charge) {
    Iterator<Map.Entry<Key, Assembly>> iterator = assemblies.entrySet().iterator();
    while (bufferedBytes + charge > maxBufferedBytes && iterator.hasNext()) {
      // access-order iteration: the first entry is the least recently updated
      Assembly assembly = iterator.next().getValue();
      iterator.remove();
      bufferedBytes -= assembly.charge;
    }
  }

  /**
   * Part 14 §7.2.3 window arithmetic for the UInt16 MessageSequenceNumber (N=16): {@code received}
   * is newer than {@code current} iff {@code (received - 1 - current) mod 2^16 < 2^14}.
   */
  private static boolean isNewer(int received, int current) {
    return ((received - 1 - current) & 0xFFFF) < 0x4000;
  }

  /**
   * Assembly key: the wire-derived stream tuple plus the verified-security discriminator; a null
   * PublisherId participates in the key. {@code secured} keeps unauthenticated (spoofable) input in
   * a key space disjoint from signature-verified assemblies.
   */
  private record Key(@Nullable PublisherId publisherId, UShort dataSetWriterId, boolean secured) {}

  /** One in-progress reassembly: the payload buffer plus byte-range coverage tracking. */
  private static final class Assembly {

    final int sequenceNumber;
    final long totalSize;
    final long charge;
    final byte[] data;

    /** Covered byte ranges, start (inclusive) to end (exclusive), non-overlapping and merged. */
    final TreeMap<Long, Long> ranges = new TreeMap<>();

    long covered = 0;
    long lastUpdateNanos;

    Assembly(int sequenceNumber, int totalSize, long charge) {
      this.sequenceNumber = sequenceNumber;
      this.totalSize = totalSize;
      this.charge = charge;
      this.data = new byte[totalSize];
    }

    /**
     * Copy one chunk into the payload buffer and update coverage; the caller has validated {@code
     * offset + chunk.length <= totalSize}.
     *
     * @return {@code true} if the payload is now completely covered.
     */
    boolean write(long offset, byte[] chunk, long now) {
      lastUpdateNanos = now;

      if (chunk.length > 0) {
        System.arraycopy(chunk, 0, data, (int) offset, chunk.length);
        addRange(offset, offset + chunk.length);
      }

      return covered == totalSize;
    }

    private void addRange(long start, long end) {
      Map.Entry<Long, Long> floor = ranges.floorEntry(start);
      if (floor != null && floor.getValue() >= start) {
        start = floor.getKey();
        end = Math.max(end, floor.getValue());
        covered -= floor.getValue() - floor.getKey();
        ranges.remove(floor.getKey());
      }

      Map.Entry<Long, Long> next = ranges.ceilingEntry(start);
      while (next != null && next.getKey() <= end) {
        end = Math.max(end, next.getValue());
        covered -= next.getValue() - next.getKey();
        ranges.remove(next.getKey());
        next = ranges.ceilingEntry(start);
      }

      ranges.put(start, end);
      covered += end - start;
    }
  }

  /**
   * The outcome of offering one chunk to the reassembler.
   *
   * @param status the outcome kind.
   * @param payload the complete original payload; non-null iff {@code status} is {@link
   *     Status#COMPLETE}.
   * @param statusCode the rejection status code; non-null iff {@code status} is {@link
   *     Status#REJECTED}.
   * @param message the rejection description; non-null iff {@code status} is {@link
   *     Status#REJECTED}.
   */
  record Result(
      Status status,
      byte @Nullable [] payload,
      @Nullable StatusCode statusCode,
      @Nullable String message) {

    enum Status {
      /** The chunk was buffered; the payload is not yet complete. */
      PENDING,

      /** The chunk completed the payload; {@link Result#payload()} carries it. */
      COMPLETE,

      /** The chunk belongs to an older, already-abandoned payload generation; it was dropped. */
      STALE,

      /**
       * The chunk was rejected: inconsistent or out-of-bounds fields, or a size or budget bound was
       * exceeded. Any assembly poisoned by the inconsistency has been discarded.
       */
      REJECTED
    }

    static Result pending() {
      return new Result(Status.PENDING, null, null, null);
    }

    static Result complete(byte[] payload) {
      return new Result(Status.COMPLETE, payload, null, null);
    }

    static Result stale() {
      return new Result(Status.STALE, null, null, null);
    }

    static Result rejected(StatusCode statusCode, String message) {
      return new Result(Status.REJECTED, null, statusCode, message);
    }
  }
}
