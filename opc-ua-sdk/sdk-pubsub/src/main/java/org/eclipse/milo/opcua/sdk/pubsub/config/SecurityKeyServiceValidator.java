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

import java.util.ArrayList;
import java.util.List;
import org.eclipse.milo.opcua.stack.core.types.builtin.ByteString;
import org.eclipse.milo.opcua.stack.core.types.enumerated.ApplicationType;
import org.eclipse.milo.opcua.stack.core.types.enumerated.MessageSecurityMode;
import org.eclipse.milo.opcua.stack.core.types.structured.ApplicationDescription;
import org.eclipse.milo.opcua.stack.core.types.structured.EndpointDescription;
import org.eclipse.milo.opcua.stack.core.types.structured.UserTokenPolicy;
import org.jspecify.annotations.Nullable;

/**
 * Validates SecurityKeyServices entries against the Part 14 §6.2.5.4 Table 40 identity-record
 * contract: each entry is an {@link EndpointDescription} that identifies a Security Key Service by
 * its {@code ApplicationUri} (with {@code ApplicationType} {@code Server} for pull access via
 * GetSecurityKeys and {@code Client} for push targets), not a literal endpoint to connect to.
 *
 * <p>Builders and the Part 14 mapper deliberately impose none of these constraints (foreign configs
 * must round-trip untouched); callers that consume the entries — key provider construction, engine
 * startup of a secured group, and remote-configuration writes — invoke this validator and decide
 * how to surface the result. {@code errors} make an entry unusable and should be rejected; {@code
 * warnings} flag non-conformant producer fields ("shall" violations in Table 40) on entries a
 * tolerant consumer can still resolve, and should be logged rather than failed.
 */
public final class SecurityKeyServiceValidator {

  private SecurityKeyServiceValidator() {}

  /**
   * The outcome of validating one or more SecurityKeyServices entries.
   *
   * @param errors problems that make an entry unusable; empty if the entries are usable.
   * @param warnings conformance violations (Table 40) a tolerant consumer can proceed past.
   */
  public record Result(List<String> errors, List<String> warnings) {

    /**
     * Create a new {@link Result}, copying both lists.
     *
     * @param errors problems that make an entry unusable.
     * @param warnings conformance violations a tolerant consumer can proceed past.
     */
    public Result {
      errors = List.copyOf(errors);
      warnings = List.copyOf(warnings);
    }

    /**
     * Check if validation found no errors (warnings do not affect validity).
     *
     * @return {@code true} if there are no errors.
     */
    public boolean isValid() {
      return errors.isEmpty();
    }
  }

  /**
   * Validate a list of SecurityKeyServices entries; messages are prefixed with the entry index. An
   * empty list is valid: whether key services are required at all depends on the component's
   * security mode and key provider, not on the entries themselves.
   *
   * @param entries the SecurityKeyServices entries to validate.
   * @return the aggregated {@link Result}.
   */
  public static Result validate(List<EndpointDescription> entries) {
    List<String> errors = new ArrayList<>();
    List<String> warnings = new ArrayList<>();

    for (int i = 0; i < entries.size(); i++) {
      String prefix = "securityKeyServices[%d]: ".formatted(i);
      Result result = validate(entries.get(i));
      result.errors().forEach(e -> errors.add(prefix + e));
      result.warnings().forEach(w -> warnings.add(prefix + w));
    }

    return new Result(errors, warnings);
  }

  /**
   * Validate a single SecurityKeyServices entry.
   *
   * @param entry the SecurityKeyServices entry to validate.
   * @return the {@link Result}.
   */
  public static Result validate(EndpointDescription entry) {
    List<String> errors = new ArrayList<>();
    List<String> warnings = new ArrayList<>();

    ApplicationDescription server = entry.getServer();
    ApplicationType applicationType = server != null ? server.getApplicationType() : null;

    if (server == null || applicationType == null) {
      errors.add("server ApplicationDescription with an ApplicationType is required (Table 40)");
      return new Result(errors, warnings);
    }

    switch (applicationType) {
      case Server -> validateServerEntry(entry, server, errors, warnings);
      case Client -> validateClientEntry(entry, warnings);
      default ->
          errors.add(
              "invalid ApplicationType %s (Table 40: Server = pull access, Client = push target)"
                  .formatted(applicationType));
    }

    if (entry.getSecurityMode() != MessageSecurityMode.SignAndEncrypt) {
      warnings.add(
          "securityMode is %s; Table 40 requires SignAndEncrypt for the SKS channel"
              .formatted(entry.getSecurityMode()));
    }
    if (entry.getSecurityLevel() != null && entry.getSecurityLevel().intValue() != 0) {
      warnings.add("securityLevel is %s; Table 40 requires 0".formatted(entry.getSecurityLevel()));
    }
    if (isPresent(entry.getServerCertificate())) {
      warnings.add("serverCertificate shall be null or empty (Table 40)");
    }

    return new Result(errors, warnings);
  }

  private static void validateServerEntry(
      EndpointDescription entry,
      ApplicationDescription server,
      List<String> errors,
      List<String> warnings) {

    if (nullOrEmpty(server.getApplicationUri())) {
      errors.add("server.applicationUri is required for a pull (Server) entry");
    }

    boolean hasDiscoveryUrl = false;
    String[] discoveryUrls = server.getDiscoveryUrls();
    if (discoveryUrls != null) {
      for (String url : discoveryUrls) {
        if (!nullOrEmpty(url)) {
          hasDiscoveryUrl = true;
          break;
        }
      }
    }
    boolean hasEndpointUrl = !nullOrEmpty(entry.getEndpointUrl());

    if (!hasDiscoveryUrl && !hasEndpointUrl) {
      errors.add(
          "a pull (Server) entry requires at least one server.discoveryUrls entry "
              + "(or a non-conformant endpointUrl usable as a discovery target)");
    }
    if (hasEndpointUrl) {
      warnings.add(
          "endpointUrl shall be null or empty (Table 40 identifies the SKS by "
              + "server.discoveryUrls); tolerated as a discovery target");
    }
    if (!nullOrEmpty(server.getGatewayServerUri())) {
      warnings.add("server.gatewayServerUri shall be null or empty (Table 40)");
    }
    if (!nullOrEmpty(server.getDiscoveryProfileUri())) {
      warnings.add("server.discoveryProfileUri shall be null or empty (Table 40)");
    }
  }

  private static void validateClientEntry(EndpointDescription entry, List<String> warnings) {
    if (!nullOrEmpty(entry.getSecurityPolicyUri())) {
      warnings.add("securityPolicyUri shall be null or empty for a push (Client) entry (Table 40)");
    }
    UserTokenPolicy[] userIdentityTokens = entry.getUserIdentityTokens();
    if (userIdentityTokens != null && userIdentityTokens.length > 0) {
      warnings.add(
          "userIdentityTokens shall be null or empty for a push (Client) entry (Table 40)");
    }
  }

  private static boolean nullOrEmpty(@Nullable String s) {
    return s == null || s.isEmpty();
  }

  private static boolean isPresent(@Nullable ByteString bs) {
    return bs != null && !bs.isNullOrEmpty();
  }
}
