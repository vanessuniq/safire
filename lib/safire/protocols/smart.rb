module Safire
  module Protocols
    # SMART on FHIR OAuth2 client for authorization code, access token, and refresh token flows.
    #
    # This class wraps the core SMART on FHIR authorization sequence:
    # - Builds an authorization URL with PKCE and state for CSRF protection.
    # - Exchanges an authorization code for an access token.
    # - Exchanges a refresh token for a new access token.
    #
    # Configuration is provided as a Hash and validated on initialization. All of the
    # following keys are required unless noted:
    #
    # * :base_url [String] FHIR server base URL
    # * :client_id [String] OAuth2 client identifier
    # * :client_secret [String, optional] client secret for confidential symmetric clients
    # * :redirect_uri [String] redirect URI registered with the authorization server
    # * :scopes [Array<String>, optional] default scopes requested during authorization
    # * :issuer [String, optional] issuer identifier. Defaults to base_url if not provided
    # * :authorization_endpoint [String, optional] SMART authorization endpoint URL
    # * :token_endpoint [String, optional] SMART token endpoint URL
    # * :private_key [OpenSSL::PKey, String, optional] private key for confidential asymmetric clients
    # * :kid [String, optional] key ID matching the registered public key for asymmetric clients
    # * :jwt_algorithm [String, optional] JWT signing algorithm (RS384 or ES384). Auto-detected if not provided
    # * :jwks_uri [String, optional] URL to client's JWKS for jku header in JWT assertions
    #
    # authorization_endpoint and token_endpoint will be retrieved from the server's smart configuration if not provided.
    #
    # The `auth_type` controls how the client authenticates:
    #
    # * :public — public client; `client_id` is sent in token and refresh requests
    # * :confidential_symmetric — confidential client using client_secret with HTTP Basic auth
    # * :confidential_asymmetric — confidential client using private_key_jwt authentication (JWT assertion)
    #
    # Token responses returned by {#request_access_token} and {#refresh_token} are
    # parsed JSON objects with **string keys**, and are validated to include
    # `"access_token"`; otherwise a {Safire::Errors::AuthError} is raised.
    #
    # @raise [Safire::Errors::ConfigurationError]
    #   if required configuration attributes are missing or invalid
    #
    # @example Initialize a public SMART client
    #   smart_client = Safire::Protocols::Smart.new({
    #     client_id: 'my_client_id',
    #     redirect_uri: 'https://myapp.example.com/callback',
    #     scopes: ['launch/patient', 'openid', 'fhirUser', 'patient/*.read'],
    #     issuer: 'https://fhir.example.com',
    #     authorization_endpoint: 'https://fhir.example.com/authorize',
    #     token_endpoint: 'https://fhir.example.com/token'
    #   })
    #
    # @example Generate an authorization URL
    #   auth_data = smart_client.authorization_url
    #   auth_data[:auth_url]      # redirect the user to this URL
    #   auth_data[:state]         # store and verify on callback
    #   auth_data[:code_verifier] # store for the token request
    #
    # @example Exchange authorization code for tokens
    #   token_data = smart_client.request_access_token(
    #     code: 'abc123',
    #     code_verifier: auth_data[:code_verifier]
    #   )
    #   token_data["access_token"]
    #
    # @example Refresh an access token
    #   new_tokens = smart_client.refresh_token(
    #     refresh_token: token_data["refresh_token"]
    #   )
    #   new_tokens["access_token"]

    class Smart < Entity
      ATTRIBUTES = %i[
        base_url client_id client_secret redirect_uri scopes issuer
        authorization_endpoint token_endpoint
        private_key kid jwt_algorithm jwks_uri
      ].freeze

      # Attributes that are not required during validation
      OPTIONAL_ATTRIBUTES = %i[scopes client_secret private_key kid jwt_algorithm jwks_uri].freeze

      WELL_KNOWN_PATH = '/.well-known/smart-configuration'.freeze

      attr_reader(*ATTRIBUTES, :auth_type)

      def initialize(config, auth_type: :public)
        super(config, ATTRIBUTES)

        @auth_type = auth_type.to_sym
        @http_client = Safire.http_client
        @issuer ||= base_url
        @authorization_endpoint ||= well_known_config.authorization_endpoint
        @token_endpoint ||= well_known_config.token_endpoint

        validate!
      end

      # Retrieves and parses SMART on FHIR configuration metadata from the FHIR server.
      #
      # This method sends a GET request to the server’s
      # `/.well-known/smart-configuration` endpoint, validates the response format,
      # and builds a {Safire::Protocols::SmartMetadata} object containing the
      # authorization and token endpoints, among other SMART metadata fields.
      #
      # The result is cached after the first successful discovery and reused on
      # subsequent calls within the same instance.
      #
      # @return [Safire::Protocols::SmartMetadata]
      #   Parsed SMART configuration metadata object.
      # @raise [Safire::Errors::DiscoveryError]
      #   If the discovery request fails or the response is not valid JSON.
      def well_known_config
        return @well_known_config if @well_known_config

        response = @http_client.get(well_known_endpoint)
        metadata = parse_metadata(response.body)

        @well_known_config = SmartMetadata.new(metadata)
      rescue StandardError => e
        msg = "Failed to discover SMART configuration: #{e.message.inspect}"
        details = e.try(:details)
        log_msg = "SMART discovery for endpoint `#{well_known_endpoint}` failed: #{msg}"
        log_msg += " (details: #{details.inspect})" if details
        Safire.logger.error(log_msg)
        raise Errors::DiscoveryError.new(msg, details: details)
      end

      # Builds the authorization URL to request an authorization code.
      #
      # See {Safire::Protocols::Smart} for configuration details and supported auth types.
      #
      # @param launch [String, nil] optional launch parameter
      # @param custom_scopes [Array<String>, nil] optional custom scopes to override the configured ones
      # @return [Hash] containing:
      #   * :auth_url [String] the authorization URL to redirect the user to
      #   * :state [String] the state parameter for CSRF protection
      #   * :code_verifier [String] the PKCE code verifier for the token exchange
      # @raise [Errors::ConfigurationError] if no scopes are configured or provided
      def authorization_url(launch: nil, custom_scopes: nil)
        validate_presence_of_scopes(custom_scopes)

        Safire.logger.info("Generating authorization URL for SMART #{auth_type}...")

        code_verifier = PKCE.generate_code_verifier

        uri = Addressable::URI.parse(authorization_endpoint)
        uri.query_values = authorization_params(launch:, custom_scopes:, code_verifier:)

        { auth_url: uri.to_s, state: uri.query_values['state'], code_verifier: }
      end

      # Exchanges the authorization code for an access token.
      #
      # See {Safire::Protocols::Smart} for authentication modes and client configuration.
      # @param code [String] authorization code from the authorization server
      # @param code_verifier [String] PKCE code verifier from the authorization step
      # @param client_secret [String, nil] optional; used for confidential symmetric clients when not already configured
      # @param private_key [OpenSSL::PKey, String, nil] optional; private key for asymmetric auth (overrides configured)
      # @param kid [String, nil] optional; key ID for asymmetric auth (overrides configured)
      # @return [Hash] token response parsed from the authorization server, including:
      #   * "access_token" [String] new access token issued by the authorization server (required)
      #   * "token_type"  [String] token type, fixed value "bearer" (required)
      #   * "expires_in"  [Integer] lifetime of the access token in seconds (required)
      #   * "scope"       [String] authorized scopes for this token (required)
      #   * "refresh_token"           [String] refresh token, if issued (optional)
      #   * "authorization_details"   [Hash] additional authorization details, if provided (optional)
      #   * Context parameters such as "patient" or "encounter" MAY be present, depending on server behavior.
      # @raise [Safire::Errors::AuthError] if the request fails or response is invalid
      def request_access_token(code:, code_verifier:, client_secret: self.client_secret,
                               private_key: self.private_key, kid: self.kid)
        Safire.logger.info('Requesting access token using authorization code...')

        response = @http_client.post(
          token_endpoint,
          body: access_token_params(code, code_verifier, private_key:, kid:),
          headers: oauth2_headers(client_secret)
        )

        parse_token_response(response.body)
      rescue StandardError => e
        msg = "Failed to obtain access token: #{e.message.inspect}"
        details = e.try(:details)
        raise Errors::AuthError.new(msg, details: details)
      end

      # Exchanges a refresh token for a new access token.
      #
      # @param refresh_token [String] the refresh token issued by the authorization server (required)
      # @param scopes [Array<String>, nil] optional reduced scope list
      #   If omitted, the same scopes as the original token are requested.
      # @param client_secret [String, nil] optional; used for confidential symmetric clients when not already configured
      # @param private_key [OpenSSL::PKey, String, nil] optional; private key for asymmetric auth (overrides configured)
      # @param kid [String, nil] optional; key ID for asymmetric auth (overrides configured)
      # @return [Hash] token response parsed from the authorization server.
      #   See {Safire::Protocols::Smart#request_access_token} for token response format.
      #
      # @raise [Safire::Errors::AuthError] if the refresh request fails or the response is invalid
      def refresh_token(refresh_token:, scopes: nil, client_secret: self.client_secret,
                        private_key: self.private_key, kid: self.kid)
        Safire.logger.info('Refreshing access token...')

        response = @http_client.post(
          token_endpoint,
          body: refresh_token_params(refresh_token:, scopes:, private_key:, kid:),
          headers: oauth2_headers(client_secret)
        )

        parse_token_response(response.body)
      rescue StandardError => e
        msg = "Failed to refresh access token: #{e.message.inspect}"
        details = e.try(:details)
        raise Errors::AuthError.new(msg, details: details)
      end

      private

      def validate!
        missing = (ATTRIBUTES - OPTIONAL_ATTRIBUTES).select { |attr| send(attr).blank? }
        return if missing.empty?

        raise Errors::ConfigurationError,
              "SMART Client configuration missing attributes: #{missing.to_sentence}"
      end

      def validate_presence_of_scopes(custom_scopes = nil)
        return if (scopes || custom_scopes).present?

        raise Errors::ConfigurationError,
              'SMART Client auth flow requires scopes (Array)'
      end

      def validate_client_secret(secret)
        return if secret.present?

        raise Errors::ConfigurationError, "client_secret is needed to request access token for #{auth_type}"
      end

      def parse_json_response(data, error_class, context)
        unless data.is_a?(Hash)
          raise error_class,
                "Invalid #{context} format: expected JSON object but received #{data.inspect}"
        end

        data
      end

      def parse_token_response(token_response)
        parse_json_response(token_response, Errors::AuthError, 'token response').tap do |parsed|
          unless parsed['access_token'].present?
            raise Errors::AuthError, "Missing access token in response: #{parsed.inspect}"
          end
        end
      end

      def parse_metadata(metadata)
        parse_json_response(metadata, Errors::DiscoveryError, 'SMART configuration')
      end

      def authorization_params(launch:, custom_scopes:, code_verifier:)
        {
          response_type: 'code',
          client_id:,
          redirect_uri:,
          launch:,
          scope: [custom_scopes || scopes].flatten.join(' '),
          state: SecureRandom.hex(16),
          aud: issuer.to_s,
          code_challenge_method: 'S256',
          code_challenge: PKCE.generate_code_challenge(code_verifier)
        }.compact
      end

      def access_token_params(code, code_verifier, private_key:, kid:)
        {
          grant_type: 'authorization_code',
          code:,
          redirect_uri:,
          code_verifier:
        }.merge(client_auth_params(private_key:, kid:))
      end

      def refresh_token_params(refresh_token:, scopes:, private_key:, kid:)
        params = {
          grant_type: 'refresh_token',
          refresh_token:
        }
        params[:scope] = [scopes].flatten.join(' ') if scopes.present?
        params.merge(client_auth_params(private_key:, kid:))
      end

      def client_auth_params(private_key:, kid:)
        case auth_type
        when :public
          { client_id: client_id }
        when :confidential_asymmetric
          jwt_assertion_params(private_key:, kid:)
        else
          {}
        end
      end

      def oauth2_headers(secret)
        headers = {
          content_type: 'application/x-www-form-urlencoded'
        }
        if auth_type == :confidential_symmetric
          headers[:Authorization] = authentication_header(secret.presence || client_secret)
        end

        headers
      end

      def authentication_header(secret)
        validate_client_secret(secret)

        "Basic #{Base64.strict_encode64("#{client_id}:#{secret}")}"
      end

      def jwt_assertion_params(private_key:, kid:)
        validate_asymmetric_credentials!(private_key, kid)

        assertion = Safire::JWTAssertion.new(
          client_id: client_id,
          token_endpoint: token_endpoint,
          private_key: private_key,
          kid: kid,
          algorithm: jwt_algorithm,
          jku: jwks_uri
        )

        {
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
          client_assertion: assertion.to_jwt
        }
      end

      def validate_asymmetric_credentials!(private_key, kid)
        missing = []
        missing << :private_key if private_key.blank?
        missing << :kid if kid.blank?
        return if missing.empty?

        raise Errors::ConfigurationError, "Missing required asymmetric credentials: #{missing.to_sentence}"
      end

      def well_known_endpoint
        "#{base_url.to_s.chomp('/')}#{WELL_KNOWN_PATH}"
      end
    end
  end
end
