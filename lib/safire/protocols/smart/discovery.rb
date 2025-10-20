module Safire
  module Protocols
    module Smart
      class Discovery
        WELL_KNOWN_PATH = '/.well-known/smart-configuration'.freeze

        # Initialize Discovery service with the FHIR server base URL
        #
        # @param base_url the base URL of the FHIR service
        def initialize(base_url, http_client: nil)
          @base_url = base_url
          @http_client = http_client || Safire::HTTPClient.new(base_url:)
          @logger = Safire::SafireLogger.new
        end

        # Fetch and Parse SMART configuration
        def discover
          enpoint = "#{@base_url}#{WELL_KNOWN_PATH}"
          response = @http_client.get(enpoint)
          metadata = parse_metadata(response.body)

          @logger.info('SMART discovery successful',
                       token_endpoint: metadata['token_endpoint'],
                       capabilities: metadata['capabilities'].inspect)

          SmartMetadata.new(metadata)
        rescue StandardError => e
          @logger.error('SMART discovery failed', error: e.message, base_url: @base_url)
          raise Errors::DiscoveryError, "Failed to discover SMART configuration: #{e.message.inspect}"
        end

        private

        def parse_metadata(metadata)
          unless metadata.is_a?(Hash)
            raise Errors::DiscoveryError,
                  "Invalid SMART configuration format: SMART Discovery response should be JSON,
                  but obtained #{metadata.inspect}"
          end

          validate_required_fields(metadata)
          metadata
        end

        def validate_required_fields(metadata)
          required_fields = %w[grant_types_supported token_endpoint capabilities code_challenge_methods_supported]
          required_fields.push('issuer', 'jwks_uri') if issuer_and_jwks_uri_required?(metadata['capabilities'])
          required_fields.push('authorization_endpoint') if authorization_endpoint_required?(metadata['capabilities'])

          missing_fields = required_fields.reject { |field| metadata[field] }

          return if missing_fields.empty?

          raise Errors::DiscoveryError, "Missing required SMART configuration fields: #{missing_fields.to_sentence}"
        end

        def issuer_and_jwks_uri_required?(capabilities)
          capabilities&.include?('sso-openid-connect')
        end

        def authorization_endpoint_required?(capabilities)
          capabilities&.include?('launch-ehr') || capabilities&.include?('launch-standalone')
        end
      end
    end
  end
end
