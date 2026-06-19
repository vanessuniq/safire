module Safire
  module Protocols
    # Shared translation of OAuth-style wire responses into Safire values and errors.
    #
    # Protocol implementations remain responsible for HTTP requests, endpoint
    # selection, and protocol-specific policy.
    #
    # @api private
    module OAuthResponseHandling
      private

      def oauth_error_from(faraday_error, error_class)
        response = faraday_error.response
        status = response&.dig(:status)
        body = json_object(response&.dig(:body))

        error_class.new(
          status:,
          error_code: body&.fetch('error', nil),
          error_description: body&.fetch('error_description', nil)
        )
      end

      def parse_registration_response(body)
        response = json_object(body)
        raise Errors::RegistrationError.new(error_description: 'response is not a JSON object') unless response

        client_id = response['client_id']
        return response if client_id.is_a?(String) && client_id.present?

        if response.key?('client_id')
          raise Errors::RegistrationError.new(
            error_description: 'response client_id must be a non-blank string'
          )
        end

        raise Errors::RegistrationError.new(received_fields: response.keys)
      end

      def json_object(body)
        parsed = body.is_a?(String) ? JSON.parse(body) : body
        parsed.deep_stringify_keys if parsed.is_a?(Hash)
      rescue JSON::ParserError
        nil
      end
    end
  end
end
