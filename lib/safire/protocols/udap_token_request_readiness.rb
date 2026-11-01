module Safire
  module Protocols
    # Decides whether a UDAP token request can proceed against trusted
    # discovery metadata, following the runtime-readiness classification in
    # ADR-015.
    #
    # The +metadata+ must already be the trusted result of
    # {Udap#server_metadata}: +signed_metadata+ validated and signed endpoint
    # claims merged over unsigned values. This class performs no network
    # activity and does not sign anything; it only reports the token endpoint
    # and signing algorithms a caller should use, or raises.
    #
    # The +grant_type+ parameter lets one readiness policy serve
    # +client_credentials+ (implemented) and +authorization_code+ /
    # +refresh_token+ (planned) token requests.
    #
    # Runtime hard failures ({Errors::DiscoveryError}) — Safire cannot send a
    # conformant token request:
    # - +udap_authn+ is not in +udap_profiles_supported+. Normative
    #   ({https://hl7.org/fhir/us/udap-security/STU2/discovery.html#required-udap-metadata
    #   STU2 §2.2}): the array "SHALL include ... +"udap_authn"+ for UDAP
    #   JWT-Based Client Authentication".
    # - The requested grant is not in +grant_types_supported+, including an
    #   empty or non-array value. Normative (§2.2): "clients SHALL interpret an
    #   empty array value to mean that the corresponding capability is NOT
    #   supported by the server."
    # - +token_endpoint+ is missing, not an absolute HTTPS URI with a host
    #   (HTTP loopback only when +allow_insecure_localhost+ is enabled), or has
    #   a fragment. Implementation choice mirroring SMART token-endpoint
    #   readiness: the Authentication Token and client credentials must only be
    #   sent to a usable, protected endpoint.
    # - +token_endpoint_auth_methods_supported+ is not an array including
    #   +private_key_jwt+ (§2.2: "Fixed array with one value:
    #   +["private_key_jwt"]+"). Safire accepts additional entries.
    # - +token_endpoint_auth_signing_alg_values_supported+ is not a non-empty
    #   array of strings, so no Authentication Token algorithm can be selected.
    # - +udap_authorization_extensions_required+ is present but not an array of
    #   strings.
    #
    # Runtime hard failures ({Errors::ValidationError}) — the caller's request
    # cannot satisfy the server:
    # - An extension key listed in +udap_authorization_extensions_required+
    #   ("required by the Authorization Server in every token request", §2.2)
    #   is absent from the request's extension keys (attribute +:extensions+;
    #   the message names the missing key names, which are protocol
    #   identifiers rather than request values).
    # - Scope negotiation failures from {UdapScopeNegotiation} with operation
    #   +:token+ (unadvertised wildcard scopes;
    #   {https://hl7.org/fhir/us/udap-security/STU2/general.html#scope-negotiation
    #   STU2 §7.3}).
    #
    # Value-free warnings — the request can still be sent and the server
    # remains authoritative:
    # - +token_endpoint_auth_signing_alg_values_supported+ omits RS256, the
    #   algorithm "Implementers SHALL support" (STU2 §7.1.2).
    # - For +client_credentials+, +udap_authz+ is not advertised although §2.2
    #   says the array "SHALL also include" it when +grant_types_supported+
    #   includes +client_credentials+.
    # - One or more sent extension keys are not listed in a usable
    #   +udap_authorization_extensions_supported+ array. Normative
    #   ({https://hl7.org/fhir/us/udap-security/STU2/b2b.html#constructing-authentication-token
    #   STU2 §5.2.1}): "The Authorization Server MAY ignore any unrecognized
    #   claims in the Authentication Token."
    #
    # Broader conformance (for example the exact fixed-value arrays) remains
    # the explicit {UdapMetadata#valid?} diagnostic.
    #
    # @example
    #   readiness = UdapTokenRequestReadiness.new(
    #     metadata: discovered,
    #     grant_type: 'client_credentials',
    #     discovery_endpoint: 'https://fhir.example.com/.well-known/udap'
    #   ).evaluate!(scopes: %w[system/Patient.rs], extension_keys: ['hl7-b2b'])
    #   readiness.token_endpoint     # => "https://fhir.example.com/token"
    #   readiness.signing_algorithms # => ["RS256"]
    #
    # @api private
    class UdapTokenRequestReadiness
      # Readiness outcome.
      #
      # @!attribute [r] token_endpoint
      #   @return [String] authoritative token endpoint, unchanged; use it as
      #     the Authentication Token +aud+ and as the POST target
      # @!attribute [r] signing_algorithms
      #   @return [Array<String>] advertised
      #     +token_endpoint_auth_signing_alg_values_supported+
      Result = Data.define(:token_endpoint, :signing_algorithms)

      include URIValidation

      GRANT_TYPES = %w[client_credentials authorization_code refresh_token].freeze
      AUTHENTICATION_METHOD = 'private_key_jwt'.freeze
      MANDATORY_ALGORITHM = 'RS256'.freeze
      DISCOVERY_LABEL = 'UDAP metadata'.freeze

      private_constant :GRANT_TYPES, :AUTHENTICATION_METHOD, :MANDATORY_ALGORITHM, :DISCOVERY_LABEL

      # @param metadata [UdapMetadata] trusted discovery metadata with signed
      #   endpoint claims already applied
      # @param grant_type [String] +client_credentials+, +authorization_code+,
      #   or +refresh_token+
      # @param discovery_endpoint [String] UDAP well-known URL (including any
      #   +community+ query) reported as {Errors::DiscoveryError#endpoint}
      # @param allow_insecure_localhost [Boolean] permit an HTTP loopback token
      #   endpoint for local development
      # @raise [ArgumentError] when +grant_type+ is not supported
      def initialize(metadata:, grant_type:, discovery_endpoint:, allow_insecure_localhost: false)
        raise ArgumentError, "unsupported UDAP token grant type: #{grant_type.inspect}" unless
          GRANT_TYPES.include?(grant_type)

        @metadata = metadata
        @grant_type = grant_type
        @discovery_endpoint = discovery_endpoint
        @allow_insecure_localhost = validate_localhost_policy(allow_insecure_localhost)
        freeze
      end

      # Evaluates readiness for one token request.
      #
      # @param scopes [Array<String>, nil] normalized, non-blank requested
      #   scope tokens; +nil+ skips scope negotiation (for grants whose token
      #   request carries no +scope+). Required and non-empty for
      #   +client_credentials+.
      # @param extension_keys [Array<String>] key names of the Authentication
      #   Token +extensions+ claim the request will send
      # @return [Result] token endpoint and signing algorithms to use
      # @raise [Errors::DiscoveryError] when trusted metadata cannot support
      #   the token request
      # @raise [Errors::ValidationError] when a required extension is missing or
      #   a requested wildcard scope is not advertised
      # @raise [ArgumentError] when +scopes+ or +extension_keys+ are malformed
      def evaluate!(scopes: nil, extension_keys: [])
        validate_arguments!(scopes, extension_keys)
        validate_authentication_profile!
        validate_grant_type!
        token_endpoint = validate_token_endpoint!
        validate_authentication_method!
        algorithms = validate_signing_algorithms!
        validate_required_extensions!(extension_keys)
        negotiate_scopes!(scopes)
        emit_warnings(algorithms, extension_keys)
        Result.new(token_endpoint:, signing_algorithms: algorithms)
      end

      private

      def validate_arguments!(scopes, extension_keys)
        unless extension_keys.is_a?(Array) && extension_keys.all?(String)
          raise ArgumentError, 'extension_keys must be an array of strings'
        end
        return unless @grant_type == 'client_credentials' && (!scopes.is_a?(Array) || scopes.empty?)

        raise ArgumentError, 'client_credentials token requests require a non-empty scopes array'
      end

      def validate_authentication_profile!
        return if @metadata.jwt_client_auth_profile?

        discovery_error!('server does not advertise the udap_authn profile required for UDAP JWT client authentication')
      end

      def validate_grant_type!
        grants = @metadata.grant_types_supported
        return if grants.is_a?(Array) && grants.include?(@grant_type)

        discovery_error!("server does not advertise the #{@grant_type} grant in grant_types_supported")
      end

      def validate_token_endpoint!
        endpoint = @metadata.token_endpoint
        discovery_error!("response missing required field 'token_endpoint'") if endpoint.nil?

        description = token_endpoint_problem(endpoint)
        discovery_error!(description) if description
        endpoint.dup.freeze
      end

      def token_endpoint_problem(endpoint)
        case classify_uri(endpoint, allow_insecure_localhost: @allow_insecure_localhost, allow_fragment: false)
        when :invalid then "response field 'token_endpoint' must be an absolute URI"
        when :fragment then "response field 'token_endpoint' must not include a fragment"
        when :non_https then "response field 'token_endpoint' must use HTTPS"
        else
          "response field 'token_endpoint' must be an absolute URI" if Addressable::URI.parse(endpoint).host.blank?
        end
      end

      def validate_authentication_method!
        methods = @metadata.token_endpoint_auth_methods_supported
        return if methods.is_a?(Array) && methods.include?(AUTHENTICATION_METHOD)

        discovery_error!('token_endpoint_auth_methods_supported must be an array including private_key_jwt')
      end

      def validate_signing_algorithms!
        algorithms = @metadata.token_endpoint_auth_signing_alg_values_supported
        return algorithms.map { |alg| alg.dup.freeze }.freeze if string_array?(algorithms) && algorithms.any?

        discovery_error!('token endpoint signing algorithm metadata must be a non-empty array of strings')
      end

      def validate_required_extensions!(extension_keys)
        required = @metadata.udap_authorization_extensions_required
        unless required.nil? || string_array?(required)
          discovery_error!('udap_authorization_extensions_required must be an array of strings when present')
        end

        missing = Array(required).uniq - extension_keys
        return if missing.empty?

        raise Errors::ValidationError.new(
          attribute: :extensions,
          reason: 'must include every extension listed in udap_authorization_extensions_required; ' \
                  "missing: #{missing.join(', ')}"
        )
      end

      def negotiate_scopes!(scopes)
        return if scopes.nil?

        UdapScopeNegotiation.new(
          scopes_supported: @metadata.scopes_supported,
          operation: :token,
          discovery_endpoint: @discovery_endpoint
        ).evaluate!(scopes)
      end

      def emit_warnings(algorithms, extension_keys)
        warn_missing_mandatory_algorithm(algorithms)
        warn_missing_authorization_profile
        warn_unlisted_extensions(extension_keys)
      end

      def warn_missing_mandatory_algorithm(algorithms)
        return if algorithms.include?(MANDATORY_ALGORITHM)

        Safire.logger.warn(
          '[UDAP] token endpoint metadata does not advertise the required RS256 baseline; ' \
          'the token request may proceed only with another advertised, supported, key-compatible algorithm'
        )
      end

      def warn_missing_authorization_profile
        return unless @grant_type == 'client_credentials'
        return if @metadata.client_authorization_profile?

        Safire.logger.warn(
          '[UDAP] udap_profiles_supported does not include udap_authz, which UDAP Security STU2 requires ' \
          'when client_credentials is supported; proceeding with the client_credentials token request'
        )
      end

      def warn_unlisted_extensions(extension_keys)
        supported = @metadata.udap_authorization_extensions_supported
        supported = supported.is_a?(Array) ? supported.grep(String) : []
        unlisted = extension_keys.uniq - supported
        return if unlisted.empty?

        Safire.logger.warn(
          "[UDAP] token request extension count=#{unlisted.length} not listed in " \
          'udap_authorization_extensions_supported; the authorization server MAY ignore unrecognized claims'
        )
      end

      def string_array?(value)
        value.is_a?(Array) && value.all?(String)
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
