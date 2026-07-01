module Safire
  module Protocols
    # UDAP Security STU2 protocol implementation.
    #
    # Handles server metadata discovery from the UDAP well-known endpoint
    # (per {https://hl7.org/fhir/us/udap-security/STU2/discovery.html STU2 §2}).
    # Results are cached per community within each instance.
    #
    # All other UDAP flows (B2B client credentials, B2C authorization code,
    # Tiered OAuth, Dynamic Client Registration) raise {NotImplementedError}
    # and are planned for future PRs.
    #
    # This is an internal class used exclusively by {Safire::Client}. Do not
    # instantiate it directly — use {Safire::Client} instead.
    #
    # @note For internal use by {Safire::Client} only.
    # @api private
    class Udap
      include Behaviours

      WELL_KNOWN_PATH = '/.well-known/udap'.freeze

      def initialize(config)
        @base_url = config.base_url
        @allow_insecure_localhost = config.allow_insecure_localhost
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
      #   a body that is not a JSON object, or if +signed_metadata+ JWT validation fails
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

      private

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
        return body if body.is_a?(Hash)

        raise Errors::DiscoveryError.new(
          endpoint: endpoint,
          error_description: 'response is not a JSON object',
          label: 'UDAP metadata'
        )
      end
    end
  end
end
