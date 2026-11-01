module Safire
  module Protocols
    # Decides whether a UDAP authorization request (the first step of the
    # authorization code flow) can be built against trusted discovery
    # metadata, following the runtime-readiness classification in ADR-015.
    #
    # The +metadata+ must already be the trusted result of
    # {Udap#server_metadata}: +signed_metadata+ validated and signed endpoint
    # claims (including +authorization_endpoint+) merged over unsigned values.
    # This class performs no network activity; it only reports the
    # authorization endpoint a caller should redirect to, or raises.
    #
    # Runtime hard failures ({Errors::DiscoveryError}) — Safire cannot build a
    # usable authorization request:
    # - +authorization_code+ is not in +grant_types_supported+, including an
    #   empty or non-array value. Normative
    #   ({https://hl7.org/fhir/us/udap-security/STU2/discovery.html#required-udap-metadata
    #   STU2 §2.2}): "clients SHALL interpret an empty array value to mean that
    #   the corresponding capability is NOT supported by the server."
    # - +authorization_endpoint+ is missing. Normative (§2.2): it "SHALL be
    #   present if the value of the +grant_types_supported+ parameter includes
    #   the string +"authorization_code"+".
    # - +authorization_endpoint+ is not an absolute HTTPS URI with a host
    #   (HTTP loopback only when +allow_insecure_localhost+ is enabled), or has
    #   a fragment. Implementation choice mirroring SMART authorization-endpoint
    #   readiness: the user agent must only be sent to a protected endpoint,
    #   and RFC 6749 §3.1 says the endpoint URI "MUST NOT include a fragment
    #   component" (RFC text not fetched in this environment).
    # - Only for a Tiered OAuth request (+tiered_oauth: true+): +udap_to+ is
    #   not in +udap_profiles_supported+, or +"udap"+ is not in
    #   +scopes_supported+ (including empty or non-array values). Normative
    #   basis: discovery.md §2.2, the profiles array "SHALL also include
    #   +"udap_to"+" if the server supports the Tiered OAuth workflow, and
    #   {https://hl7.org/fhir/us/udap-security/STU2/user.html#client-authorization-request-to-data-holder
    #   STU2 §6.1}: "A data holder that supports UDAP Tiered OAuth SHALL
    #   include +"udap"+ in the array of scopes returned for the
    #   +scopes_supported+ parameter". Hard-failing is an implementation
    #   choice (client apps "MAY use this workflow with data holders that
    #   support it, as indicated in the data holder's UDAP metadata"): Safire
    #   does not send a Tiered OAuth request to a server that does not
    #   advertise it. A warning-only alternative was considered and rejected.
    #
    # Value-free warnings — the request can still be sent and the server
    # remains authoritative:
    # - Requested wildcard scopes that are not advertised exactly in
    #   +scopes_supported+, or that cannot be confirmed because
    #   +scopes_supported+ is unusable, via {UdapScopeNegotiation} with
    #   operation +:authorize+. STU2 §7.3 names registration and token requests
    #   only, so Safire does not hard-fail authorization requests on this rule.
    # - Non-wildcard scope coverage warnings from {UdapScopeNegotiation}.
    #
    # Token-endpoint readiness (+udap_authn+, +private_key_jwt+, signing
    # algorithms) is checked by {UdapTokenRequestReadiness} when the code is
    # exchanged, not here.
    #
    # @example
    #   UdapAuthorizationRequestReadiness.new(
    #     metadata: discovered,
    #     discovery_endpoint: 'https://fhir.example.com/.well-known/udap'
    #   ).evaluate!(scopes: %w[openid patient/Patient.rs])
    #   # => "https://fhir.example.com/authorize"
    #
    # @api private
    class UdapAuthorizationRequestReadiness
      include URIValidation

      GRANT_TYPE = 'authorization_code'.freeze
      DISCOVERY_LABEL = 'UDAP metadata'.freeze
      TIERED_OAUTH_PROFILE = 'udap_to'.freeze
      TIERED_OAUTH_SCOPE = 'udap'.freeze

      private_constant :GRANT_TYPE, :DISCOVERY_LABEL, :TIERED_OAUTH_PROFILE, :TIERED_OAUTH_SCOPE

      # @param metadata [UdapMetadata] trusted discovery metadata with signed
      #   endpoint claims already applied
      # @param discovery_endpoint [String] UDAP well-known URL (including any
      #   +community+ query) reported as {Errors::DiscoveryError#endpoint}
      # @param allow_insecure_localhost [Boolean] permit an HTTP loopback
      #   authorization endpoint for local development
      def initialize(metadata:, discovery_endpoint:, allow_insecure_localhost: false)
        @metadata = metadata
        @discovery_endpoint = discovery_endpoint
        @allow_insecure_localhost = validate_localhost_policy(allow_insecure_localhost)
        freeze
      end

      # Evaluates readiness for one authorization request.
      #
      # @param scopes [Array<String>] normalized, non-blank requested scope
      #   tokens (non-empty)
      # @param tiered_oauth [Boolean] whether the request uses UDAP Tiered OAuth
      #   (+idp+ parameter); enables the +udap_to+ and +"udap"+ scope checks
      # @return [String] authoritative authorization endpoint, unchanged
      # @raise [Errors::DiscoveryError] when trusted metadata cannot support an
      #   authorization code request
      # @raise [ArgumentError] when +scopes+ is not a non-empty array
      def evaluate!(scopes:, tiered_oauth: false)
        raise ArgumentError, 'authorization requests require a non-empty scopes array' unless
          scopes.is_a?(Array) && scopes.any?

        validate_grant_type!
        endpoint = validate_authorization_endpoint!
        validate_tiered_oauth! if tiered_oauth
        UdapScopeNegotiation.new(
          scopes_supported: @metadata.scopes_supported,
          operation: :authorize,
          discovery_endpoint: @discovery_endpoint
        ).evaluate!(scopes)
        endpoint
      end

      private

      def validate_grant_type!
        grants = @metadata.grant_types_supported
        return if grants.is_a?(Array) && grants.include?(GRANT_TYPE)

        discovery_error!("server does not advertise the #{GRANT_TYPE} grant in grant_types_supported")
      end

      def validate_tiered_oauth!
        unless @metadata.supports_tiered_oauth?
          discovery_error!("server does not advertise the #{TIERED_OAUTH_PROFILE} profile in udap_profiles_supported")
        end
        scopes = @metadata.scopes_supported
        return if scopes.is_a?(Array) && scopes.include?(TIERED_OAUTH_SCOPE)

        discovery_error!("server does not advertise the #{TIERED_OAUTH_SCOPE} scope in scopes_supported")
      end

      def validate_authorization_endpoint!
        endpoint = @metadata.authorization_endpoint
        discovery_error!("response missing required field 'authorization_endpoint'") if endpoint.nil?

        description = endpoint_problem(endpoint)
        discovery_error!(description) if description
        endpoint.dup.freeze
      end

      def endpoint_problem(endpoint)
        case classify_uri(endpoint, allow_insecure_localhost: @allow_insecure_localhost, allow_fragment: false)
        when :invalid then "response field 'authorization_endpoint' must be an absolute URI"
        when :fragment then "response field 'authorization_endpoint' must not include a fragment"
        when :non_https then "response field 'authorization_endpoint' must use HTTPS"
        else
          "response field 'authorization_endpoint' must be an absolute URI" if
            Addressable::URI.parse(endpoint).host.blank?
        end
      end

      def discovery_error!(description)
        raise Errors::DiscoveryError.new(
          endpoint: @discovery_endpoint,
          error_description: description,
          label: DISCOVERY_LABEL
        )
      end
    end
  end
end
