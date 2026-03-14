module Safire
  module Protocols
    # Abstract contract that all Safire protocol implementations must satisfy.
    #
    # Include this module in a protocol class to declare conformance with the
    # Safire protocol interface. Each method raises +NotImplementedError+ by
    # default; concrete protocol classes must override every method.
    #
    # @abstract
    # @api private
    module Behaviours
      # Returns protocol-specific server metadata from discovery.
      # @abstract
      def server_metadata(...)
        raise NotImplementedError, "#{self.class}#server_metadata is not implemented"
      end

      # Builds the authorization request URL/data.
      # @abstract
      def authorization_url(...)
        raise NotImplementedError, "#{self.class}#authorization_url is not implemented"
      end

      # Exchanges an authorization code for an access token.
      # @abstract
      def request_access_token(...)
        raise NotImplementedError, "#{self.class}#request_access_token is not implemented"
      end

      # Exchanges a refresh token for a new access token.
      # @abstract
      def refresh_token(...)
        raise NotImplementedError, "#{self.class}#refresh_token is not implemented"
      end

      # Validates a token response for compliance with this protocol's specification.
      # @abstract
      def token_response_valid?(...)
        raise NotImplementedError, "#{self.class}#token_response_valid? is not implemented"
      end

      # Dynamically registers this client with the authorization server (RFC 7591).
      #
      # SMART App Launch 2.2.0 encourages implementers to consider the OAuth 2.0
      # Dynamic Client Registration Protocol for an out-of-the-box solution.
      # Implementations should override this method when registration is supported.
      #
      # @abstract
      def register_client(...)
        raise NotImplementedError, "#{self.class}#register_client is not implemented"
      end
    end
  end
end
