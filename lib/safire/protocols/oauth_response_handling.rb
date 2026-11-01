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

      def token_error_from(faraday_error)
        oauth_error_from(faraday_error, Errors::TokenError)
      end

      # Validates a successful token endpoint response body.
      #
      # RFC 6749 §5.1 marks +access_token+ as REQUIRED in a successful response.
      # Implementation choice: only an already-parsed Hash (as produced by the
      # Faraday JSON response middleware) is accepted; a raw String body is
      # rejected, unlike {#parse_registration_response}.
      #
      # @param token_response [Object] the response body
      # @return [Hash] the response body unchanged
      # @raise [Safire::Errors::TokenError] if the body is not a Hash, or if
      #   +access_token+ is missing or blank (field names only, no values)
      def parse_token_response(token_response)
        unless token_response.is_a?(Hash)
          raise Errors::TokenError.new(error_description: 'response is not a JSON object')
        end

        return token_response if token_response['access_token'].present?

        raise Errors::TokenError.new(received_fields: token_response.keys)
      end

      def parse_registration_response(body)
        response = json_object(body)
        raise Errors::RegistrationError.new(error_description: 'response is not a usable JSON object') unless response

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
        JSONResponseParsing.parse_object(body)
      end
    end
  end
end
