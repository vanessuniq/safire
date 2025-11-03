module Safire
  # PKCE (Proof Key for Code Exchange) implementation
  # This class generates a code verifier and corresponding code challenge for use in OAuth2 authorization flows.
  # It supports the S256 code challenge method.
  # @see https://datatracker.ietf.org/doc/html/rfc7636
  class PKCE
    class << self
      def generate_code_verifier
        # Using 96 bytes will produce a 128-character URL-safe base64 string which is the max length allowed
        SecureRandom.urlsafe_base64(96).tr('=', '')
      end

      # Generates a code challenge from the given code verifier using SHA256 and base64url encoding
      # @param code_verifier [String] the code verifier
      # @return [String] the generated code challenge
      # @raise [ArgumentError] if the code verifier is invalid
      def generate_code_challenge(code_verifier)
        validate_verifier(code_verifier)

        digest = Digest::SHA256.digest(code_verifier)
        Base64.urlsafe_encode64(digest).tr('=', '')
      end

      private

      def validate_verifier(code_verifier)
        length = code_verifier.length
        unless length.between?(43, 128)
          raise ArgumentError, "Code verifier must be between 43 and 128 characters long, got #{length}"
        end

        # RFC 7636: unreserved characters only
        return if code_verifier.match?(/\A[A-Za-z0-9\-._~]+\z/)

        raise ArgumentError, 'Code verifier contains invalid characters. Only unreserved characters are allowed.'
      end
    end
  end
end
