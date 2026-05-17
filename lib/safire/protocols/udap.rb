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
        @base_url       = config.base_url
        @http_client    = Safire::HTTPClient.new
        @metadata_cache = {}
      end

      # Retrieves and parses UDAP server metadata from the well-known endpoint.
      #
      # When a +community+ URI is provided, the request is scoped to that community
      # by appending +?community=<encoded-uri>+ to the endpoint URL. Results are
      # cached per community — subsequent calls with the same +community+ return the
      # cached result without a second HTTP request.
      #
      # @param community [String, nil] optional UDAP community URI; scopes discovery
      # @return [Safire::Protocols::UdapMetadata] parsed UDAP metadata
      # @raise [Safire::Errors::DiscoveryError] if the server returns an HTTP error,
      #   a 204 response, or a body that is not a JSON object
      # @raise [Safire::Errors::NetworkError] on connection failure, timeout, SSL error,
      #   or a redirect to a non-HTTPS URL
      # @raise [Safire::Errors::ConfigurationError] if +community+ is not a URI
      def server_metadata(community: nil)
        community = normalize_community(community)
        cache_key = community || :default
        return @metadata_cache[cache_key] if @metadata_cache.key?(cache_key)

        @metadata_cache[cache_key] = fetch_metadata(community:)
      end

      private

      def fetch_metadata(community:)
        endpoint = well_known_endpoint(community:)
        response = @http_client.get(endpoint)
        check_204!(response, endpoint:, community:)
        UdapMetadata.new(parse_discovery_body(response.body, endpoint))
      rescue Faraday::Error => e
        status = e.response&.dig(:status)
        Safire.logger.error("UDAP discovery failed for `#{endpoint}`: HTTP #{status}")
        raise Errors::DiscoveryError.new(endpoint: endpoint, status:, label: 'UDAP metadata')
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
        base = "#{@base_url.to_s.chomp('/')}#{WELL_KNOWN_PATH}"
        return base unless community

        uri = Addressable::URI.parse(base)
        uri.query_values = { 'community' => community }
        uri.to_s
      end

      def check_204!(response, endpoint:, community:)
        return unless response.status == 204

        description = 'no UDAP workflows supported'
        description += " for community #{community}" if community
        raise Errors::DiscoveryError.new(
          endpoint: endpoint,
          status: 204,
          error_description: description,
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
