module Safire
  module Errors
    # Base error class for all Safire errors
    class Error < StandardError
      attr_reader :details

      def initialize(message = nil, details: nil)
        super(message)
        @details = details
      end
    end

    class ConfigurationError < Error; end

    class AuthError < Error; end

    class DiscoveryError < Error; end

    class TokenError < Error; end

    class CertificateError < Error; end

    class ProtocolError < Error; end

    class NetworkError < Error; end

    class ValidationError < Error; end
  end
end
