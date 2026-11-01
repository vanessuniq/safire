module Safire
  module Protocols
    # UDAP Security STU2 protocol implementation.
    #
    # Handles server metadata discovery from the UDAP well-known endpoint
    # (per {https://hl7.org/fhir/us/udap-security/STU2/discovery.html STU2 §2})
    # and Dynamic Client Registration (per
    # {https://hl7.org/fhir/us/udap-security/STU2/registration.html STU2 §3}).
    # It also requests B2B access tokens with the client credentials grant and
    # UDAP JWT-based client authentication (per
    # {https://hl7.org/fhir/us/udap-security/STU2/b2b.html STU2 §5}).
    # Discovery results are cached per community within each instance.
    #
    # Other UDAP flows (authorization code, refresh token, and Tiered OAuth)
    # raise +NotImplementedError+ and remain planned for future releases.
    #
    # This is an internal class used exclusively by {Safire::Client}. Do not
    # instantiate it directly — use {Safire::Client} instead.
    #
    # @note For internal use by {Safire::Client} only.
    # @api private
    class Udap
      include Behaviours
      include OAuthResponseHandling

      WELL_KNOWN_PATH = '/.well-known/udap'.freeze
      REGISTRATION_HEADERS = { content_type: 'application/json' }.freeze
      SUCCESSFUL_REGISTRATION_STATUSES = [200, 201].freeze
      SUCCESSFUL_CANCELLATION_STATUSES = 200..299
      MANDATORY_REGISTRATION_ALGORITHM = 'RS256'.freeze
      REGISTER_ACTION = 'Registering client via UDAP Dynamic Client Registration...'.freeze
      CANCEL_ACTION = 'Cancelling client registration via UDAP Dynamic Client Registration...'.freeze
      TOKEN_HEADERS = { content_type: 'application/x-www-form-urlencoded' }.freeze
      CLIENT_ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'.freeze
      CLIENT_CREDENTIALS_GRANT = 'client_credentials'.freeze
      CLIENT_CREDENTIALS_ACTION = 'Requesting UDAP B2B access token (client_credentials grant)...'.freeze
      SCOPE_TOKEN_PATTERN = /\A[\x21\x23-\x5B\x5D-\x7E]+\z/
      private_constant :REGISTRATION_HEADERS, :SUCCESSFUL_REGISTRATION_STATUSES, :SUCCESSFUL_CANCELLATION_STATUSES,
                       :MANDATORY_REGISTRATION_ALGORITHM, :REGISTER_ACTION, :CANCEL_ACTION, :TOKEN_HEADERS,
                       :CLIENT_ASSERTION_TYPE, :CLIENT_CREDENTIALS_GRANT, :CLIENT_CREDENTIALS_ACTION,
                       :SCOPE_TOKEN_PATTERN

      def initialize(config)
        @base_url = config.base_url
        @client_id = config.client_id
        @scopes = config.scopes
        @allow_insecure_localhost = config.allow_insecure_localhost
        @private_key = config.private_key
        @certificate_chain = config.certificate_chain
        @jwt_algorithm = config.jwt_algorithm
        @http_client = Safire::HTTPClient.new(allow_insecure_localhost: @allow_insecure_localhost)
        @metadata_cache = {}
      end

      # Retrieves and parses UDAP server metadata from the well-known endpoint.
      #
      # When a +community+ URI is provided, the request is scoped to that community
      # by appending +?community=<encoded-uri>+ to the endpoint URL. Results are
      # cached per community — subsequent calls with the same +community+ return the
      # cached result without a second HTTP request, as long as its +signed_metadata+
      # still validates against the current trust policy.
      #
      # The +signed_metadata+ JWT in the discovery response is validated per UDAP Security STU2.
      # Signed endpoint claims (+token_endpoint+, +registration_endpoint+, and optionally
      # +authorization_endpoint+) are merged over the unsigned values before the metadata object
      # is constructed.
      #
      # @param community [String, nil] optional UDAP community URI; scopes discovery
      # @param trusted_anchors [Array<OpenSSL::X509::Certificate>] X.509 trust anchors for
      #   +signed_metadata+ chain verification; required for production use
      # @param crls [Array<OpenSSL::X509::CRL>] certificate revocation lists for production chain validation
      # @param revocation_checker [#call, nil] custom revocation policy; must return +true+ to pass
      # @param verify_chain [Boolean] when +false+, skips X.509 chain validation (dev/test only)
      # @return [Safire::Protocols::UdapMetadata] parsed UDAP metadata with authoritative signed endpoint claims
      # @raise [Safire::Errors::DiscoveryError] if the server returns an HTTP error, a 204 response,
      #   a body that is not a usable JSON object, or if +signed_metadata+ JWT validation fails
      # @raise [Safire::Errors::NetworkError] on connection failure, timeout, SSL error,
      #   or a redirect to a non-HTTPS URL
      # @raise [Safire::Errors::ConfigurationError] if +community+ is not a URI
      def server_metadata(community: nil, trusted_anchors: [], crls: [], revocation_checker: nil, verify_chain: true)
        community = normalize_community(community)
        trust_policy = {
          trusted_anchors:,
          crls:,
          revocation_checker:,
          verify_chain:,
          allow_insecure_localhost: @allow_insecure_localhost
        }
        cache_key = build_cache_key(community, trusted_anchors, crls, revocation_checker, verify_chain)
        cached_entry = @metadata_cache[cache_key]
        return cached_entry.fetch(:metadata) if cached_entry && cached_entry_valid?(cached_entry, trust_policy)

        @metadata_cache.delete(cache_key)

        entry = fetch_metadata(
          community:,
          trust_policy:
        )
        @metadata_cache[cache_key] = entry
        entry.fetch(:metadata)
      end

      # Dynamically registers or modifies a UDAP client using STU2 Dynamic Client Registration.
      #
      # UDAP registration is discovery-bound: Safire validates caller metadata,
      # discovers trusted UDAP metadata, checks the fields required by DCR, then
      # posts a fixed request envelope to the discovered +registration_endpoint+.
      # Caller metadata is signed into the +software_statement+ JWT; it is not
      # duplicated at the top level.
      #
      # Calling this method again with the same +client_uri+ and community requests
      # modification of the existing registration. Safire accepts both 201 Created
      # and update-style 200 responses as long as the response is a JSON object with
      # a non-blank string +client_id+.
      #
      # UDAP Security STU2 lets a client request a wildcard scope only if wildcards
      # are listed in the server's +scopes_supported+ metadata (see
      # {https://hl7.org/fhir/us/udap-security/STU2/general.html#scope-negotiation
      # STU2 General Guidance: Scope negotiation}). Safire applies this stricter
      # local check: a requested scope token containing a literal +*+ is treated
      # as a wildcard and must appear exactly in +scopes_supported+. Non-wildcard
      # scopes remain subject to server-side negotiation and produce at most a
      # value-free warning.
      #
      # @param metadata [Hash] caller-controlled UDAP registration metadata
      # @param client_uri [String] exact URI used as +iss+ and +sub+ and required
      #   to appear as a URI SAN in the leaf certificate
      # @param community [String, nil] optional UDAP community URI for discovery
      # @param certifications [Array<String>, nil] optional client-operator or third-party
      #   certification/endorsement JWTs; +nil+ omits the field and +[]+ sends an explicit empty collection
      # @param trusted_anchors [Array<OpenSSL::X509::Certificate>] server trust anchors
      #   for signed metadata validation
      # @param crls [Array<OpenSSL::X509::CRL>] revocation lists for signed metadata validation
      # @param revocation_checker [#call, nil] custom server certificate revocation policy
      # @param verify_chain [Boolean] whether discovery signed_metadata chain validation is required
      # @param private_key [OpenSSL::PKey::RSA, OpenSSL::PKey::EC, String, nil]
      #   client signing private key; defaults to configuration
      # @param certificate_chain [Array<String, OpenSSL::X509::Certificate>, nil]
      #   leaf-first client signing certificate chain; defaults to configuration
      # @param jwt_algorithm [String, nil] optional explicit registration signing algorithm
      # @return [Hash] registration response from the authorization server
      # @raise [Safire::Errors::DiscoveryError] when UDAP discovery is unavailable or
      #   untrusted, required DCR capability metadata cannot be used safely, or
      #   +scopes_supported+ provides no usable scope strings while a requested
      #   wildcard scope must be evaluated
      # @raise [Safire::Errors::ValidationError] when caller metadata or certifications are
      #   invalid, or a requested wildcard scope is not advertised exactly in +scopes_supported+
      # @raise [Safire::Errors::ConfigurationError] when signing configuration is missing or incompatible
      # @raise [Safire::Errors::CertificateError] when the client certificate chain cannot support signing
      # @raise [Safire::Errors::RegistrationError] when the server rejects registration,
      #   returns an unconfirmed pending outcome, or returns a malformed completed response
      # @raise [Safire::Errors::NetworkError] on connection failure, timeout, SSL error,
      #   or a redirect to a non-HTTPS URL
      def register_client(metadata, client_uri:, community: nil, certifications: nil, trusted_anchors: [],
                          crls: [], revocation_checker: nil, verify_chain: true,
                          private_key: @private_key, certificate_chain: @certificate_chain,
                          jwt_algorithm: @jwt_algorithm)
        response = submit_registration_request(
          metadata,
          operation: :register,
          action: REGISTER_ACTION,
          client_uri:,
          community:,
          trusted_anchors:,
          crls:,
          revocation_checker:,
          verify_chain:,
          certifications:,
          private_key:,
          certificate_chain:,
          jwt_algorithm:
        )
        validate_registration_response_status!(response)
        parse_registration_response(response.body)
      rescue Faraday::Error => e
        raise registration_error_from(e)
      end

      # Cancels an existing UDAP Dynamic Client Registration.
      #
      # Cancellation uses the same discovery-bound endpoint, trust policy,
      # certifications, and X.509-backed software-statement signing as
      # {#register_client}. Safire builds the software statement in cancellation
      # mode, which injects an empty +grant_types+ array and rejects any
      # caller-supplied +grant_types+ value.
      #
      # STU2 defines cancellation confirmation by the successful response body:
      # +client_id+ must be present and +grant_types+ must be an empty array.
      #
      # Unlike registration, cancellation never fails on scope-advertisement
      # drift: a registered wildcard the server no longer advertises produces a
      # warning while cleanup proceeds, so scope-advertisement drift alone
      # cannot strand an existing registration. Other failures, such as trust,
      # capability, signing, transport, or confirmation problems, still raise.
      #
      # @param metadata [Hash] identifying UDAP client metadata; omit +grant_types+
      # @param client_uri [String] exact URI used as +iss+ and +sub+ and required
      #   to appear as a URI SAN in the leaf certificate
      # @param community [String, nil] optional UDAP community URI for discovery
      # @param certifications [Array<String>, nil] optional client-operator or third-party
      #   certification/endorsement JWTs; +nil+ omits the field and +[]+ sends an explicit empty collection
      # @param trusted_anchors [Array<OpenSSL::X509::Certificate>] server trust anchors
      #   for signed metadata validation
      # @param crls [Array<OpenSSL::X509::CRL>] revocation lists for signed metadata validation
      # @param revocation_checker [#call, nil] custom server certificate revocation policy
      # @param verify_chain [Boolean] whether discovery signed_metadata chain validation is required
      # @param private_key [OpenSSL::PKey::RSA, OpenSSL::PKey::EC, String, nil]
      #   client signing private key; defaults to configuration
      # @param certificate_chain [Array<String, OpenSSL::X509::Certificate>, nil]
      #   leaf-first client signing certificate chain; defaults to configuration
      # @param jwt_algorithm [String, nil] optional explicit registration signing algorithm
      # @return [Hash] cancellation response from the authorization server
      # @raise [Safire::Errors::DiscoveryError] when UDAP discovery is unavailable or
      #   untrusted, or required DCR capability metadata cannot be used safely
      # @raise [Safire::Errors::ValidationError] when caller metadata or certifications are invalid
      # @raise [Safire::Errors::ConfigurationError] when signing configuration is missing or incompatible
      # @raise [Safire::Errors::CertificateError] when the client certificate chain cannot support signing
      # @raise [Safire::Errors::RegistrationError] when the server rejects cancellation or fails to confirm it
      # @raise [Safire::Errors::NetworkError] on connection failure, timeout, SSL error,
      #   or a redirect to a non-HTTPS URL
      def cancel_registration(metadata, client_uri:, community: nil, certifications: nil, trusted_anchors: [],
                              crls: [], revocation_checker: nil, verify_chain: true,
                              private_key: @private_key, certificate_chain: @certificate_chain,
                              jwt_algorithm: @jwt_algorithm)
        response = submit_registration_request(
          metadata,
          operation: :cancel,
          action: CANCEL_ACTION,
          client_uri:,
          community:,
          trusted_anchors:,
          crls:,
          revocation_checker:,
          verify_chain:,
          certifications:,
          private_key:,
          certificate_chain:,
          jwt_algorithm:
        )
        parse_cancellation_response(response)
      rescue Faraday::Error => e
        raise registration_error_from(e)
      end

      # Requests a B2B access token with the client credentials grant and UDAP
      # JWT-based client authentication.
      #
      # This is the UDAP implementation behind {Safire::Client#request_backend_token},
      # which serves the client credentials grant for every protocol. The method
      # name and keyword contract are stable; any future protocol-neutral alias
      # would be an addition, not a replacement.
      #
      # Order of operations: validate caller input (identity, scopes, extensions)
      # before any network activity; discover trusted UDAP metadata (signed
      # metadata must validate before the client proceeds,
      # {https://hl7.org/fhir/us/udap-security/STU2/discovery.html#signed-metadata-elements
      # STU2 §2.3}); check token-request readiness
      # ({UdapTokenRequestReadiness}); sign an Authentication Token; then POST
      # exactly once. Safire never retries a token request.
      #
      # The Authentication Token ({UdapAuthenticationToken}) uses the configured
      # +client_id+ as +iss+ and +sub+, the authoritative signed +token_endpoint+
      # as +aud+ (and as the POST target), a 300-second lifetime, a fresh +jti+,
      # and +extensions+ containing +hl7-b2b+ plus any +extensions:+ entries.
      # STU2 b2b §5.2.1: the B2B Authorization Extension Object "is required for
      # B2B client apps using the +client_credentials+ flow".
      #
      # The form-encoded request body contains exactly +grant_type+, +scope+,
      # +client_assertion_type+, +client_assertion+, and +udap=1+
      # ({https://hl7.org/fhir/us/udap-security/STU2/b2b.html#client-credentials-grant
      # STU2 §5.2.2}). No +Authorization+ header, +client_id+, or
      # +client_secret+ is sent: clients "SHALL NOT include an HTTP
      # Authorization header or client secret in its token endpoint request".
      #
      # STU2 b2b §5.2.4: "A client application SHALL only use an access token in
      # a manner consistent with any assertions made when requesting that
      # token." Request a new token whenever the requestor, purpose of use, or
      # other +hl7-b2b+ context changes; Safire does not cache tokens.
      #
      # Scopes come from +scopes:+ when it yields at least one scope, otherwise
      # from configured +scopes+. Each source may be an Array of Strings or a
      # space-delimited String; values are split on whitespace, blanks dropped,
      # and duplicates removed. STU2 §5.2.2 marks +scope+ required, so Safire
      # has no default scope. Wildcard scopes must be advertised exactly in
      # +scopes_supported+
      # ({https://hl7.org/fhir/us/udap-security/STU2/general.html#scope-negotiation
      # STU2 §7.3}).
      #
      # @param scopes [Array<String>, String, nil] requested scopes; falls back to configured +scopes+
      # @param b2b [Hash] B2B Authorization Extension Object members (+organization_id+,
      #   +purpose_of_use+, and optional members); Safire adds +version: "1"+.
      #   See {UdapB2bAuthorizationExtension}
      # @param extensions [Hash{String, Symbol => Hash}, nil] additional Authorization Extension
      #   Objects keyed by extension name; must not contain +hl7-b2b+ (use +b2b:+)
      # @param community [String, nil] optional UDAP community URI for discovery
      # @param trusted_anchors [Array<OpenSSL::X509::Certificate>] server trust anchors
      #   for signed metadata validation
      # @param crls [Array<OpenSSL::X509::CRL>] revocation lists for signed metadata validation
      # @param revocation_checker [#call, nil] custom server certificate revocation policy
      # @param verify_chain [Boolean] whether discovery signed_metadata chain validation is required
      # @param private_key [OpenSSL::PKey::RSA, OpenSSL::PKey::EC, String, nil]
      #   client signing private key; defaults to configuration
      # @param certificate_chain [Array<String, OpenSSL::X509::Certificate>, nil]
      #   leaf-first client signing certificate chain; defaults to configuration
      # @param jwt_algorithm [String, nil] optional explicit Authentication Token signing algorithm
      # @return [Hash] token response from the authorization server, including a non-blank
      #   +"access_token"+; other members (+token_type+, +expires_in+, +scope+) are returned as sent
      # @raise [Safire::Errors::ConfigurationError] when +client_id+, scopes, +private_key+, or
      #   +certificate_chain+ are missing, or signing configuration is invalid or incompatible
      # @raise [Safire::Errors::ValidationError] when +b2b:+ is missing or invalid, +extensions:+
      #   is invalid, a scope is malformed, a required server extension is missing, or a
      #   requested wildcard scope is not advertised
      # @raise [Safire::Errors::DiscoveryError] when trusted UDAP discovery fails or the
      #   metadata cannot support a client_credentials token request
      # @raise [Safire::Errors::CertificateError] when the client certificate chain cannot support signing
      # @raise [Safire::Errors::TokenError] when the server rejects the request (OAuth +error+
      #   codes such as +invalid_scope+ or +invalid_client+ are preserved) or returns a body
      #   that is not a JSON object with a non-blank +access_token+
      # @raise [Safire::Errors::NetworkError] on connection failure, timeout, SSL error,
      #   or a redirect to a non-HTTPS URL
      # @see https://hl7.org/fhir/us/udap-security/STU2/b2b.html#obtaining-an-access-token
      def request_backend_token(scopes: nil, b2b: nil, extensions: nil, community: nil, trusted_anchors: [],
                                crls: [], revocation_checker: nil, verify_chain: true,
                                private_key: @private_key, certificate_chain: @certificate_chain,
                                jwt_algorithm: @jwt_algorithm)
        validate_token_identity!(private_key, certificate_chain)
        request = {
          scopes: resolve_token_scopes(scopes),
          extensions: client_credentials_extensions(b2b, extensions),
          community: normalize_community(community)
        }
        readiness = client_credentials_readiness(
          request, trusted_anchors:, crls:, revocation_checker:, verify_chain:
        )
        assertion = build_authentication_token(
          readiness, request[:extensions], private_key:, certificate_chain:, jwt_algorithm:
        )
        post_client_credentials_request(readiness.token_endpoint, request[:scopes], assertion.to_jwt)
      rescue Faraday::Error => e
        raise token_error_from(e)
      end

      private

      # Shared request preparation and POST for both :register and :cancel operations.
      def submit_registration_request(metadata, operation:, action:, **)
        endpoint, software_statement, certifications = prepare_registration_request(
          metadata,
          operation:,
          **
        )
        post_registration_request(endpoint, software_statement, certifications, action:)
      end

      def prepare_registration_request(metadata, operation:, client_uri:, community:, trusted_anchors:, crls:,
                                       revocation_checker:, verify_chain:, certifications:, private_key:,
                                       certificate_chain:, jwt_algorithm:)
        registration_metadata = build_registration_metadata(metadata, operation:)
        certifications = normalize_certifications!(certifications)
        community = normalize_community(community)
        discovered = registration_server_metadata(
          community:, trusted_anchors:, crls:, revocation_checker:, verify_chain:
        )
        validate_required_certifications!(certifications, discovered, community:)
        validate_registration_scopes!(registration_metadata, discovered, operation:, community:)
        software_statement = build_software_statement(
          registration_metadata,
          discovered,
          client_uri:,
          private_key:,
          certificate_chain:,
          jwt_algorithm:
        )
        [discovered.registration_endpoint, software_statement, certifications]
      end

      def registration_server_metadata(community:, trusted_anchors:, crls:, revocation_checker:, verify_chain:)
        discovered = server_metadata(community:, trusted_anchors:, crls:, revocation_checker:, verify_chain:)
        validate_registration_discovery!(discovered, community:)
        validate_registration_signing_algorithms!(discovered, community:)
        discovered
      end

      def validate_registration_discovery!(metadata, community:)
        return if metadata.supports_dynamic_registration?

        registration_discovery_error!(
          'server does not advertise UDAP Dynamic Client Registration support',
          community
        )
      end

      def validate_registration_signing_algorithms!(metadata, community:)
        algorithms = metadata.registration_endpoint_jwt_signing_alg_values_supported
        unless algorithms.is_a?(Array) && algorithms.any? && algorithms.all?(String)
          registration_discovery_error!(
            'registration signing algorithm metadata must be a non-empty array of strings',
            community
          )
        end
        return if algorithms.include?(MANDATORY_REGISTRATION_ALGORITHM)

        Safire.logger.warn(
          '[UDAP] registration metadata does not advertise the required RS256 baseline; ' \
          'registration may proceed only with another advertised, supported, key-compatible algorithm'
        )
      end

      def registration_discovery_error!(description, community)
        raise Errors::DiscoveryError.new(
          endpoint: well_known_endpoint(community:),
          error_description: description,
          label: 'UDAP metadata'
        )
      end

      def validate_required_certifications!(certifications, metadata, community:)
        required = metadata.udap_certifications_required
        unless required.nil? || (required.is_a?(Array) && required.all?(String))
          registration_discovery_error!(
            'udap_certifications_required must be an array of strings when present',
            community
          )
        end
        return if required.blank? || certifications.present?

        raise Errors::ValidationError.new(
          attribute: :certifications,
          reason: 'must not be nil or empty when UDAP metadata advertises required certification URIs: ' \
                  "#{required.join(', ')}"
        )
      end

      def validate_registration_scopes!(registration_metadata, discovered, operation:, community:)
        UdapScopeNegotiation.new(
          scopes_supported: discovered.scopes_supported,
          operation:,
          discovery_endpoint: well_known_endpoint(community:)
        ).evaluate!(registration_metadata.to_h.fetch('scope').split)
      end

      def normalize_certifications!(certifications)
        return if certifications.nil?

        unless certifications.is_a?(Array) && certifications.all? { |entry| compact_jws?(entry) }
          raise Errors::ValidationError.new(
            attribute: :certifications,
            reason: 'must be nil or an array of compact JWS strings'
          )
        end

        certifications.map { |entry| entry.dup.freeze }.freeze
      end

      def build_registration_metadata(metadata, operation:)
        UdapRegistrationMetadata.new(
          metadata,
          operation:,
          allow_insecure_localhost: @allow_insecure_localhost
        )
      end

      def compact_jws?(value)
        return false unless value.is_a?(String) && value.present?

        parts = value.split('.', -1)
        parts.length == 3 && parts.all? { |part| Safire::Protocols::COMPACT_JWS_SEGMENT.match?(part) }
      end

      def build_software_statement(metadata, discovered, client_uri:, private_key:, certificate_chain:, jwt_algorithm:)
        UdapSoftwareStatement.new(
          metadata:,
          client_uri:,
          registration_endpoint: discovered.registration_endpoint,
          private_key:,
          certificate_chain:,
          supported_algorithms: discovered.registration_endpoint_jwt_signing_alg_values_supported,
          algorithm: jwt_algorithm,
          allow_insecure_localhost: @allow_insecure_localhost
        )
      end

      def post_registration_request(endpoint, software_statement, certifications, action:)
        Safire.logger.info(action)

        @http_client.post(
          endpoint,
          body: registration_request_body(software_statement.to_jwt, certifications),
          headers: REGISTRATION_HEADERS
        )
      end

      def validate_registration_response_status!(response)
        return if SUCCESSFUL_REGISTRATION_STATUSES.include?(response.status)

        description =
          if response.status == 202
            'registration response did not confirm completion: HTTP 202 indicates pending processing'
          else
            'registration response did not confirm completion: expected HTTP 200 or 201'
          end

        raise Errors::RegistrationError.new(
          status: response.status,
          error_description: description
        )
      end

      def parse_cancellation_response(response)
        validate_cancellation_response_status!(response)
        parsed = parse_registration_response(response.body)
        return parsed if parsed['grant_types'].is_a?(Array) && parsed['grant_types'].empty?

        raise Errors::RegistrationError.new(
          status: response.status,
          error_description: 'cancellation response did not confirm cancellation: expected an empty grant_types array'
        )
      end

      def validate_cancellation_response_status!(response)
        return if SUCCESSFUL_CANCELLATION_STATUSES.cover?(response.status)

        raise Errors::RegistrationError.new(
          status: response.status,
          error_description: 'cancellation response did not confirm cancellation: expected a final 2xx status'
        )
      end

      def registration_request_body(software_statement, certifications)
        body = {
          software_statement:,
          udap: '1'
        }
        body[:certifications] = certifications unless certifications.nil?
        body.to_json
      end

      def registration_error_from(faraday_error)
        oauth_error_from(faraday_error, Errors::RegistrationError)
      end

      # -- client_credentials token request ----------------------------------

      def validate_token_identity!(private_key, certificate_chain)
        missing = []
        missing << :client_id if @client_id.blank?
        missing << :private_key if private_key.blank?
        missing << :certificate_chain if certificate_chain.blank?
        raise Errors::ConfigurationError.new(missing_attributes: missing) if missing.any?
      end

      def resolve_token_scopes(requested)
        scopes = normalize_token_scopes(requested)
        scopes = normalize_token_scopes(@scopes) if scopes.empty?
        raise Errors::ConfigurationError.new(missing_attributes: [:scopes]) if scopes.empty?

        scopes
      end

      def normalize_token_scopes(value)
        entries = value.is_a?(Array) ? value : [value]
        tokens = entries.flat_map do |entry|
          next [] if entry.nil?

          invalid_token_scopes!(entry) unless entry.is_a?(String)
          entry.split
        end
        return tokens.uniq if tokens.all? { |token| SCOPE_TOKEN_PATTERN.match?(token) }

        raise Errors::ValidationError.new(
          attribute: :scope,
          reason: 'must contain only RFC 6749 scope-token characters'
        )
      end

      def invalid_token_scopes!(entry)
        raise Errors::ConfigurationError.new(
          invalid_attribute: :scopes,
          invalid_value: entry.class,
          valid_values: ['Array<String>', 'space-delimited String']
        )
      end

      def client_credentials_extensions(b2b, extensions)
        if b2b.nil?
          raise Errors::ValidationError.new(
            attribute: :b2b,
            reason: 'is required: UDAP Security STU2 requires the hl7-b2b extension ' \
                    'for B2B client apps using the client_credentials flow'
          )
        end

        hl7_b2b = UdapB2bAuthorizationExtension.new(b2b).to_h
        { UdapB2bAuthorizationExtension::EXTENSION_KEY => hl7_b2b }.merge(additional_token_extensions(extensions))
      end

      def additional_token_extensions(extensions)
        return {} if extensions.nil?

        extensions_error!('must be a Hash or nil') unless extensions.is_a?(Hash)
        extensions.each_with_object({}) do |(key, value), normalized|
          name = token_extension_name(key)
          extensions_error!('must not specify an extension more than once') if normalized.key?(name)
          extensions_error!('each extension must be a non-empty Hash') unless value.is_a?(Hash) && value.any?

          normalized[name] = value
        end
      end

      def token_extension_name(key)
        unless (key.is_a?(String) || key.is_a?(Symbol)) && key.to_s.present?
          extensions_error!('keys must be non-blank Strings or Symbols')
        end

        name = key.to_s
        return name unless name == UdapB2bAuthorizationExtension::EXTENSION_KEY

        extensions_error!('must not include hl7-b2b; pass the B2B Authorization Extension Object with b2b:')
      end

      def extensions_error!(reason)
        raise Errors::ValidationError.new(attribute: :extensions, reason:)
      end

      def client_credentials_readiness(request, trusted_anchors:, crls:, revocation_checker:, verify_chain:)
        community = request[:community]
        discovered = server_metadata(community:, trusted_anchors:, crls:, revocation_checker:, verify_chain:)
        UdapTokenRequestReadiness.new(
          metadata: discovered,
          grant_type: CLIENT_CREDENTIALS_GRANT,
          discovery_endpoint: well_known_endpoint(community:),
          allow_insecure_localhost: @allow_insecure_localhost
        ).evaluate!(scopes: request[:scopes], extension_keys: request[:extensions].keys)
      end

      def build_authentication_token(readiness, extensions, private_key:, certificate_chain:, jwt_algorithm:)
        UdapAuthenticationToken.new(
          client_id: @client_id,
          token_endpoint: readiness.token_endpoint,
          private_key:,
          certificate_chain:,
          supported_algorithms: readiness.signing_algorithms,
          algorithm: jwt_algorithm,
          extensions:,
          allow_insecure_localhost: @allow_insecure_localhost
        )
      end

      # STU2 b2b §5.2.2: exactly these parameters; no Authorization header,
      # client_id, or client_secret.
      def post_client_credentials_request(endpoint, scopes, client_assertion)
        Safire.logger.info(CLIENT_CREDENTIALS_ACTION)

        response = @http_client.post(
          endpoint,
          body: {
            grant_type: CLIENT_CREDENTIALS_GRANT,
            scope: scopes.join(' '),
            client_assertion_type: CLIENT_ASSERTION_TYPE,
            client_assertion:,
            udap: '1'
          },
          headers: TOKEN_HEADERS
        )
        parse_token_response(response.body)
      end

      def fetch_metadata(community:, trust_policy:)
        endpoint = well_known_endpoint(community:)
        response = @http_client.get(endpoint)
        check_204!(response, endpoint:, community:)
        raw = parse_discovery_body(response.body, endpoint)
        signed_claims = validate_signed_metadata!(
          raw,
          endpoint:,
          community:,
          trust_policy:
        )
        build_cache_entry(raw, signed_claims)
      rescue Faraday::Error => e
        status = e.response&.dig(:status)
        Safire.logger.error("UDAP discovery failed for `#{endpoint}`: HTTP #{status}")
        raise Errors::DiscoveryError.new(endpoint: endpoint, status:, label: 'UDAP metadata')
      end

      def validate_signed_metadata!(
        raw,
        endpoint:,
        community:,
        trust_policy:
      )
        validator = UdapSignedMetadataValidator.new(raw['signed_metadata'], raw)
        claims = validator.signed_endpoint_claims(
          base_url: normalized_base_url,
          **trust_policy
        )
        return claims if claims

        raise Errors::DiscoveryError.new(
          endpoint: endpoint,
          error_description: community_scoped('signed_metadata validation failed', community),
          label: 'UDAP metadata'
        )
      end

      def build_cache_entry(raw, signed_claims)
        {
          metadata: UdapMetadata.new(
            raw.merge(signed_claims),
            allow_insecure_localhost: @allow_insecure_localhost
          ),
          raw:
        }
      end

      def cached_entry_valid?(entry, trust_policy)
        validator = UdapSignedMetadataValidator.new(entry.fetch(:raw)['signed_metadata'], entry.fetch(:raw))
        validator.signed_endpoint_claims(base_url: normalized_base_url, **trust_policy).present?
      end

      def community_scoped(description, community)
        community ? "#{description} for community #{community}" : description
      end

      def build_cache_key(community, trusted_anchors, crls, revocation_checker, verify_chain)
        [
          community || :default,
          verify_chain,
          trusted_anchors.map(&:to_der).sort,
          crls.map(&:to_der).sort,
          revocation_checker
        ]
      end

      def normalized_base_url
        @base_url.to_s.chomp('/')
      end

      def normalize_community(community)
        return if community.nil?

        return invalid_community!(community) unless community.respond_to?(:to_str)

        community = community.to_str.strip
        return if community.blank?
        return community if valid_uri?(community)

        invalid_community!(community)
      end

      def invalid_community!(community)
        raise Errors::ConfigurationError.new(
          invalid_attribute: :community,
          invalid_value: community,
          valid_values: ['URI string']
        )
      end

      def valid_uri?(value)
        uri = Addressable::URI.parse(value)
        uri.scheme.present? && (uri.host.present? || uri.path.present?)
      rescue Addressable::URI::InvalidURIError
        false
      end

      def well_known_endpoint(community:)
        base = "#{normalized_base_url}#{WELL_KNOWN_PATH}"
        return base unless community

        uri = Addressable::URI.parse(base)
        uri.query_values = { 'community' => community }
        uri.to_s
      end

      def check_204!(response, endpoint:, community:)
        return unless response.status == 204

        raise Errors::DiscoveryError.new(
          endpoint: endpoint,
          status: 204,
          error_description: community_scoped('no UDAP workflows supported', community),
          label: 'UDAP metadata'
        )
      end

      def parse_discovery_body(body, endpoint)
        parsed = JSONResponseParsing.parse_object(body)
        return parsed if parsed

        raise Errors::DiscoveryError.new(
          endpoint: endpoint,
          error_description: 'response is not a usable JSON object',
          label: 'UDAP metadata'
        )
      end
    end
  end
end
