module Safire
  module Protocols
    module Smart
      class Discovery
        attr_reader :endpoint

        WELL_KNOWN_PATH = '/.well-known/smart-configuration'.freeze

        # Initialize Discovery service with the FHIR server base URL
        #
        # @param base_url the base URL of the FHIR service
        def initialize(base_url)
          @endpoint = "#{base_url.to_s.chomp('/')}#{WELL_KNOWN_PATH}"
          @http_client = Safire.http_client
        end

        # Fetch and Parse SMART configuration metadata
        # @return [SmartMetadata] parsed SMART metadata object Safire::Protocols::Smart::SmartMetadata
        # @raise [Errors::DiscoveryError] if discovery fails, response body format is not JSON,
        #   or required fields are missing
        def discover
          response = @http_client.get(endpoint)
          metadata = parse_metadata(response.body)

          SmartMetadata.new(metadata)
        rescue StandardError => e
          Safire.logger.error('SMART discovery failed', error: e.message, endpoint:)
          raise Errors::DiscoveryError, "Failed to discover SMART configuration: #{e.message.inspect}"
        end

        private

        def parse_metadata(metadata)
          unless metadata.is_a?(Hash)
            raise Errors::DiscoveryError,
                  "Invalid SMART configuration format: SMART Discovery response should be JSON,
                  but obtained #{metadata.inspect}"
          end

          metadata
        end
      end
    end
  end
end
