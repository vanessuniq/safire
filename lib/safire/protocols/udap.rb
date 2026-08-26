module Safire
  module Protocols
    # UDAP Security STU2 protocol implementation.
    #
    # Handles server metadata discovery from the UDAP well-known endpoint
    # (per {https://hl7.org/fhir/us/udap-security/STU2/discovery.html STU2 §2})
    # and Dynamic Client Registration (per
    # {https://hl7.org/fhir/us/udap-security/STU2/registration.html STU2 §3}).
    # Discovery results are cached per community within each instance.
    #
    # Other UDAP flows (B2B client credentials token acquisition, B2C authorization
    # code, and Tiered OAuth) raise +NotImplementedError+ and remain planned for
    # future releases.
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
      private_constant :REGISTRATION_HEADERS, :SUCCESSFUL_REGISTRATION_STATUSES, :SUCCESSFUL_CANCELLATION_STATUSES,
                       :MANDATORY_REGISTRATION_ALGORITHM, :REGISTER_ACTION, :CANCEL_ACTION

      def initialize(config)
        @base_url = config.base_url
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
      #   untrusted, or required DCR capability metadata cannot be used safely
      # @raise [Safire::Errors::ValidationError] when caller metadata or certifications are invalid
      # @raise [Safire::Errors::ConfigurationError] when signing configuration is missing or incompatible
      # @raise [Safire::Errors::CertificateError] when the client certificate chain cannot support signing
      # @raise [Safire::Errors::RegistrationError] when the server rejects registration or returns malformed success
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
        validate_registration_scopes!(registration_metadata, discovered, operation:)
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

      def validate_registration_scopes!(registration_metadata, discovered, operation:)
        wildcards, non_wildcards = registration_scope_groups(registration_metadata)
        advertised = discovered.scopes_supported

        unless usable_scope_advertisement?(advertised)
          return warn_unconfirmed_scopes(wildcards, non_wildcards, operation:)
        end

        coverage = UdapScopeCoverage.new(advertised)
        unadvertised_wildcards = wildcards.reject { |scope| coverage.advertised_exactly?(scope) }
        warn_unadvertised_wildcards(unadvertised_wildcards, operation:)
        uncovered = coverage.uncovered_non_wildcards_for_warning(non_wildcards)
        warn_uncovered_non_wildcards(uncovered)
      end

      def registration_scope_groups(registration_metadata)
        requested = registration_metadata.to_h.fetch('scope').split.uniq
        requested.partition { |scope| UdapScopeCoverage.requested_wildcard?(scope) }
      end

      def warn_unconfirmed_scopes(wildcards, non_wildcards, operation:)
        warn_unconfirmed_wildcards(wildcards, operation:)
        warn_unconfirmed_non_wildcards(non_wildcards)
      end

      def usable_scope_advertisement?(scopes)
        scopes.is_a?(Array) && scopes.any? && scopes.all? { |scope| scope.is_a?(String) && scope.present? }
      end

      def warn_unadvertised_wildcards(scopes, operation:)
        return if scopes.empty?

        Safire.logger.warn(
          "[UDAP] requested wildcard scope(s) #{scopes.join(', ')} are not advertised exactly in " \
          "scopes_supported; #{scope_warning_lifecycle(operation)}"
        )
      end

      def warn_unconfirmed_wildcards(scopes, operation:)
        return if scopes.empty?

        Safire.logger.warn(
          "[UDAP] requested wildcard scope(s) #{scopes.join(', ')} cannot be confirmed as advertised exactly " \
          "because scopes_supported is missing, empty, or malformed; #{scope_warning_lifecycle(operation)}"
        )
      end

      def warn_uncovered_non_wildcards(scopes)
        return if scopes.empty?

        Safire.logger.warn(
          '[UDAP] requested non-wildcard scope(s) are not listed or locally covered by scopes_supported: ' \
          "#{scopes.join(', ')}; proceeding with server-side scope negotiation"
        )
      end

      def warn_unconfirmed_non_wildcards(scopes)
        return if scopes.empty?

        Safire.logger.warn(
          '[UDAP] cannot confirm requested non-wildcard scope coverage because scopes_supported is missing, ' \
          "empty, or malformed: #{scopes.join(', ')}; proceeding with server-side scope negotiation"
        )
      end

      def scope_warning_lifecycle(operation)
        if operation == :cancel
          return 'cancellation proceeds and remains warning-only so existing access can be removed'
        end

        'registration proceeds in v0.4.1, but registration and modification will fail in v0.5.0'
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

        raise Errors::RegistrationError.new(
          status: response.status,
          error_description: 'unexpected registration response status'
        )
      end

      def parse_cancellation_response(response)
        validate_cancellation_response_status!(response)
        parsed = parse_registration_response(response.body)
        return parsed if parsed['grant_types'].is_a?(Array) && parsed['grant_types'].empty?

        raise Errors::RegistrationError.new(
          status: response.status,
          error_description: 'cancellation response must include an empty grant_types array'
        )
      end

      def validate_cancellation_response_status!(response)
        return if SUCCESSFUL_CANCELLATION_STATUSES.cover?(response.status)

        raise Errors::RegistrationError.new(
          status: response.status,
          error_description: 'unexpected cancellation response status'
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
