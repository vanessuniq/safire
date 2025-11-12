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
    # * :client_id [String] OAuth2 client identifier
    # * :client_secret [String, optional] client secret for confidential symmetric clients
    # * :redirect_uri [String] redirect URI registered with the authorization server
    # * :scopes [Array<String>, optional] default scopes requested during authorization
    # * :issuer [String] FHIR server base URL / issuer identifier
    # * :authorization_endpoint [String, optional] SMART authorization endpoint URL
    # * :token_endpoint [String, optional] SMART token endpoint URL
    # authorization_endpoint and token_endpoint will be retrieved from the server's smart configuration if not provided.
    #
    # The `auth_type` controls how the client authenticates:
    #
    # * :public — public client; `client_id` is sent in token and refresh requests
    # * :confidential_symmetric — confidential client using client_secret with HTTP Basic auth
    # * :confidential_asymmetric — (planned) confidential client using private_key_jwt authentication
    #
    # Future versions will include private_key_jwt support for confidential asymmetric flows.
    #
    # Token responses returned by {#request_access_token} and {#refresh_token} are
    # parsed JSON objects with **string keys**, and are validated to include
    # `"access_token"`; otherwise a {Safire::Errors::AuthError} is raised.
    #
    # @raise [Safire::Errors::ConfigurationError]
    #   if required configuration attributes are missing or invalid
    #
    # @example Initialize a public SMART client
    #   smart_client = Safire::Protocols::Smart.new(
    #     client_id: 'my_client_id',
    #     redirect_uri: 'https://myapp.example.com/callback',
    #     scopes: ['launch/patient', 'openid', 'fhirUser', 'patient/*.read'],
    #     issuer: 'https://fhir.example.com',
    #     authorization_endpoint: 'https://fhir.example.com/authorize',
    #     token_endpoint: 'https://fhir.example.com/token'
    #   )
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
        client_id client_secret redirect_uri scopes issuer
        authorization_endpoint token_endpoint
      ].freeze

      WELL_KNOWN_PATH = '/.well-known/smart-configuration'.freeze

      attr_reader(*ATTRIBUTES, :auth_type)

      def initialize(config, auth_type: :public)
        super(config, ATTRIBUTES)

        @auth_type = auth_type.to_sym
        @http_client = Safire.http_client
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
        Safire.logger.error("SMART discovery for enpoint `#{well_known_endpoint}` failed: #{e.message.inspect}")
        raise Errors::DiscoveryError, "Failed to discover SMART configuration: #{e.message.inspect}"
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
      # @return [Hash] token response parsed from the authorization server, including:
      #   * "access_token" [String] new access token issued by the authorization server (required)
      #   * "token_type"  [String] token type, fixed value "bearer" (required)
      #   * "expires_in"  [Integer] lifetime of the access token in seconds (required)
      #   * "scope"       [String] authorized scopes for this token (required)
      #   * "refresh_token"           [String] refresh token, if issued (optional)
      #   * "authorization_details"   [Hash] additional authorization details, if provided (optional)
      #   * Context parameters such as "patient" or "encounter" MAY be present, depending on server behavior.
      # @raise [Safire::Errors::AuthError] if the request fails or response is invalid
      def request_access_token(code:, code_verifier:, client_secret: self.client_secret)
        Safire.logger.info('Requesting access token using authorization code...')

        response = @http_client.post(
          token_endpoint,
          body: access_token_params(code, code_verifier),
          headers: oauth2_headers(client_secret)
        )

        parse_token_response(response.body)
      rescue Faraday::ClientError => e
        raise Errors::AuthError, "Failed to obtain access token: #{e.response[:body].inspect}"
      rescue StandardError => e
        raise Errors::AuthError, "Failed to obtain access token: #{e.message.inspect}"
      end

      # Exchanges a refresh token for a new access token.
      #
      # @param refresh_token [String] the refresh token issued by the authorization server (required)
      # @param scopes [Array<String>, nil] optional reduced scope list
      #   If omitted, the same scopes as the original token are requested.
      # @param client_secret [String, nil] optional; used for confidential symmetric clients when not already configured
      # @return [Hash] token response parsed from the authorization server.
      #   See {Safire::Protocols::Smart#request_access_token} for token response format.
      #
      # @raise [Safire::Errors::AuthError] if the refresh request fails or the response is invalid
      def refresh_token(refresh_token:, scopes: nil, client_secret: self.client_secret)
        Safire.logger.info('Refreshing access token...')

        response = @http_client.post(
          token_endpoint,
          body: refresh_token_params(refresh_token:, scopes:),
          headers: oauth2_headers(client_secret)
        )

        parse_token_response(response.body)
      rescue Faraday::ClientError => e
        raise Errors::AuthError, "Failed to refresh access token: #{e.response[:body].inspect}"
      rescue StandardError => e
        raise Errors::AuthError, "Failed to refresh access token: #{e.message.inspect}"
      end

      private

      def validate!
        nil_vars = ATTRIBUTES.select { |attr| send(attr).nil? }
        nil_vars.reject! { |attr| %i[scopes client_secret].include?(attr) }
        return if nil_vars.empty?

        raise Errors::ConfigurationError,
              "SMART Client configuration missing attributes: #{nil_vars.to_sentence}"
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

      def access_token_params(code, code_verifier)
        params = {
          grant_type: 'authorization_code',
          code:,
          redirect_uri:,
          code_verifier:
        }
        params[:client_id] = client_id if auth_type == :public

        params
      end

      def refresh_token_params(refresh_token:, scopes:)
        params = {
          grant_type: 'refresh_token',
          refresh_token:
        }
        params[:scope] = [scopes].flatten.join(' ') if scopes.present?
        params[:client_id] = client_id if auth_type == :public

        params
      end

      def oauth2_headers(secret)
        headers = {
          content_type: 'application/x-www-form-urlencoded'
        }
        headers[:Authorization] = authentication_header(secret || client_secret) if auth_type == :confidential_symmetric

        headers
      end

      def authentication_header(secret)
        validate_client_secret(secret)

        "Basic #{Base64.strict_encode64("#{client_id}:#{secret}")}"
      end

      def well_known_endpoint
        "#{issuer.to_s.chomp('/')}#{WELL_KNOWN_PATH}"
      end
    end
  end
end
