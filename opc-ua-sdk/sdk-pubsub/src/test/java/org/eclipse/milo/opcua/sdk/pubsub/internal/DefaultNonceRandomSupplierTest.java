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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.HashSet;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;

/**
 * The default 4-byte MessageNonce random-part supplier (Table 156): backed by a directly
 * constructed, self-seeded {@code SecureRandom} — never a time-seeded PRNG fallback — because on a
 * static-key publisher the random part is the only cross-restart defense against AES-CTR (key,
 * nonce) reuse (the nonce counter restarts at 1 on every restart under a never-rotating key).
 */
class DefaultNonceRandomSupplierTest {

  @Test
  void suppliesFreshFourByteRandomParts() {
    Supplier<byte[]> supplier = PubSubServiceImpl.defaultNonceRandomSupplier();

    var values = new HashSet<String>();
    byte[] previous = null;
    for (int i = 0; i < 16; i++) {
      byte[] random = supplier.get();
      assertEquals(4, random.length);
      if (previous != null) {
        // each draw is a fresh array: token nonce state must never share/alias the random part
        assertNotSame(previous, random);
      }
      values.add(Arrays.toString(random));
      previous = random;
    }

    // 16 draws of 4 secure-random bytes collide with probability ~2^-25 per pair; all-identical
    // draws (the signature of a broken/constant source) are astronomically unlikely
    assertTrue(values.size() > 1, "consecutive random parts must not all be identical");
  }
}
