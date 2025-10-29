module Safire
  # PKCE (Proof Key for Code Exchange) implementation
  # This class generates a code verifier and corresponding code challenge for use in OAuth2 authorization flows.
  # It supports the S256 code challenge method.
  # @see https://datatracker.ietf.org/doc/html/rfc7636
  #
  # @!attribute [r] code_verifier
  #   @return [String] the generated code verifier
  # @!attribute [r] code_challenge
  #   @return [String] the generated code challenge
  # @!attribute [r] code_challenge_method
  #   @return [String] the code challenge method used ('S256')
  class PKCE
    attr_reader :code_verifier, :code_challenge, :code_challenge_method

    def initialize
      generate_code_verifier
      generate_code_challenge
    end

    # Returns a hash of PKCE parameters to be included in the authorization request
    # @return [Hash] PKCE parameters
    def auth_params
      {
        code_challenge:,
        code_challenge_method:
      }
    end

    private

    def generate_code_verifier
      # Using 96 bytes will produce a 128-character URL-safe base64 string which is the max length allowed
      @code_verifier = SecureRandom.urlsafe_base64(96).tr('=', '')
    end

    def generate_code_challenge
      digest = Digest::SHA256.digest(@code_verifier)
      @code_challenge = Base64.urlsafe_encode64(digest).tr('=', '')
      @code_challenge_method = 'S256'
    end
  end
end
