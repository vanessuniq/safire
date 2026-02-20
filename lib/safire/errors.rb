module Safire
  # Namespace for all Safire error classes.
  #
  # Every Safire error inherits from {Error} and carries an optional {Error#details details}
  # attribute with structured context about the failure (HTTP status, response body, etc.).
  #
  # @example Rescuing and inspecting error details
  #   begin
  #     tokens = client.request_access_token(code: code, code_verifier: verifier)
  #   rescue Safire::Errors::TokenError => e
  #     puts e.message              # Human-readable error message
  #     if e.details
  #       puts e.details[:status]   # HTTP status code (e.g., 401)
  #       puts e.details[:body]     # Raw response body (JSON string)
  #     end
  #   end
  module Errors
    # Base error class for all Safire errors.
    #
    # All Safire errors support an optional +details+ keyword argument that carries
    # structured context about the failure. When an error originates from an HTTP request,
    # +details+ is typically a Hash with +:status+ (Integer) and +:body+ (String) keys.
    #
    # @!attribute [r] details
    #   @return [Hash, nil] structured error context; +nil+ when no additional details are available.
    #     For HTTP-originated errors the hash contains:
    #     * +:status+ [Integer] — HTTP response status code
    #     * +:body+ [String] — raw JSON response body from the server
    class Error < StandardError
      attr_reader :details

      def initialize(message = nil, details: nil)
        super(message)
        @details = details
      end
    end

    # Raised when client configuration is missing or invalid.
    class ConfigurationError < Error; end

    # Raised when an authorization request fails.
    # The +details+ attribute may contain the HTTP status and OAuth2 error response body.
    class AuthError < Error; end

    # Raised when SMART configuration discovery fails or returns an invalid response.
    # The +details+ attribute may contain the HTTP status and response body from the
    # +.well-known/smart-configuration+ endpoint.
    class DiscoveryError < Error; end

    # Raised for token-related errors.
    class TokenError < Error; end

    # Raised for certificate-related errors (e.g., UDAP flows).
    class CertificateError < Error; end

    # Raised for protocol-level errors.
    class ProtocolError < Error; end

    # Raised when an HTTP request fails at the network level (connection refused, timeout, etc.).
    # The +details+ attribute contains +:status+ and +:body+ extracted from the HTTP response
    # when available.
    class NetworkError < Error; end

    # Raised for input validation errors.
    class ValidationError < Error; end
  end
end
