/*
 * Copyright (c) 2026 the Eclipse Milo Authors
 *
 * This program and the accompanying materials are made
 * available under the terms of the Eclipse Public License 2.0
 * which is available at https://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 */

package org.eclipse.milo.opcua.sdk.pubsub.sks;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import org.eclipse.milo.opcua.stack.core.types.enumerated.MessageSecurityMode;
import org.eclipse.milo.opcua.stack.core.types.structured.ApplicationDescription;
import org.eclipse.milo.opcua.stack.core.types.structured.EndpointDescription;
import org.jspecify.annotations.Nullable;

/**
 * Pure functions implementing the endpoint-selection steps of the Part 14 §6.2.5.4 Table 40
 * resolution algorithm: a {@code SecurityKeyServices} entry identifies an SKS by {@code
 * server.applicationUri} and names discovery targets; the connectable endpoints come from running
 * GetEndpoints at those targets and filtering/ranking the result.
 */
final class SksEndpointSelector {

  private SksEndpointSelector() {}

  /**
   * The discovery URLs to run GetEndpoints at for {@code entry}, in configured order.
   *
   * <p>Table 40: the targets are {@code server.discoveryUrls}. Tolerance fallback (pinned on): when
   * the entry carries no discovery URL but a non-conformant filled {@code endpointUrl} (the
   * open62541 ecosystem shape — Table 40 says it "Shall be null or empty."), the {@code
   * endpointUrl} is used as a discovery target instead — most servers answer GetEndpoints on
   * session endpoints too — followed by the same URL with {@code /discovery} appended (the retry
   * {@code OpcUaClient.create} performs).
   *
   * @param entry a Server-typed SecurityKeyServices entry.
   * @return the discovery targets in the order they should be attempted; empty only for entries
   *     {@code SecurityKeyServiceValidator} would have rejected.
   */
  static List<String> discoveryTargets(EndpointDescription entry) {
    var targets = new ArrayList<String>();

    ApplicationDescription server = entry.getServer();
    String[] discoveryUrls = server != null ? server.getDiscoveryUrls() : null;
    if (discoveryUrls != null) {
      for (String url : discoveryUrls) {
        if (!nullOrEmpty(url)) {
          targets.add(url);
        }
      }
    }

    if (targets.isEmpty() && !nullOrEmpty(entry.getEndpointUrl())) {
      String endpointUrl = entry.getEndpointUrl();
      targets.add(endpointUrl);
      if (!endpointUrl.endsWith("/discovery")) {
        targets.add(
            endpointUrl.endsWith("/") ? endpointUrl + "discovery" : endpointUrl + "/discovery");
      }
    }

    return targets;
  }

  /**
   * Filter and rank the endpoints discovered for {@code entry}.
   *
   * <p>Kept are endpoints whose {@code server.applicationUri} equals the entry's (the primary key
   * of the whole lookup) and whose {@code securityMode} is {@code SignAndEncrypt} (Table 40:
   * "Encryption is required for this Method."). When the entry pins a {@code securityPolicyUri},
   * only exact matches survive; otherwise ("the pull access shall use the best available security
   * policy") candidates are ranked by the discovered {@code securityLevel}, descending (Part 4
   * Table 135: "A higher value indicates better security."). The sort is stable, so equally ranked
   * endpoints keep the server's order.
   *
   * @param entry a Server-typed SecurityKeyServices entry.
   * @param discovered the endpoints returned by GetEndpoints at one of the entry's discovery
   *     targets.
   * @return the candidate endpoints in the order they should be attempted; possibly empty.
   */
  static List<EndpointDescription> selectCandidates(
      EndpointDescription entry, List<EndpointDescription> discovered) {

    ApplicationDescription server = entry.getServer();
    String applicationUri = server != null ? server.getApplicationUri() : null;
    if (nullOrEmpty(applicationUri)) {
      return List.of();
    }

    String policyUri = entry.getSecurityPolicyUri();

    var candidates = new ArrayList<EndpointDescription>();
    for (EndpointDescription endpoint : discovered) {
      ApplicationDescription endpointServer = endpoint.getServer();
      if (endpointServer == null || !applicationUri.equals(endpointServer.getApplicationUri())) {
        continue;
      }
      if (endpoint.getSecurityMode() != MessageSecurityMode.SignAndEncrypt) {
        continue;
      }
      if (!nullOrEmpty(policyUri) && !policyUri.equals(endpoint.getSecurityPolicyUri())) {
        continue;
      }
      candidates.add(endpoint);
    }

    candidates.sort(
        Comparator.comparingInt(
                (EndpointDescription e) ->
                    e.getSecurityLevel() != null ? e.getSecurityLevel().intValue() : 0)
            .reversed());

    return candidates;
  }

  private static boolean nullOrEmpty(@Nullable String s) {
    return s == null || s.isEmpty();
  }
}
