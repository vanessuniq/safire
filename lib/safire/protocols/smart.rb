module Safire
  module Protocols
    # SMART on FHIR OAuth2 implementation for app launch (authorization code, token exchange, refresh)
    # and backend services (client credentials) flows.
    #
    # This is an internal class used exclusively by {Safire::Client}. Do not instantiate it directly —
    # use {Safire::Client} instead.
    #
    # Accepts a {Safire::ClientConfig} and a +client_type+ symbol. Reads all configuration
    # attributes directly from the +ClientConfig+ object. Discovery of authorization and token
    # endpoints from the FHIR server's +/.well-known/smart-configuration+ metadata is performed
    # automatically when those endpoints are not present in the config.
    #
    # @note For internal use by {Safire::Client} only.
    # @api private
    #
    # @raise [Safire::Errors::ConfigurationError]
    #   if required configuration attributes are missing or invalid
    class Smart
      include Behaviours

      ATTRIBUTES = %i[
        base_url client_id client_secret redirect_uri scopes issuer
        authorization_endpoint token_endpoint
        private_key kid jwt_algorithm jwks_uri
      ].freeze

      # Attributes that are not required during validation
      OPTIONAL_ATTRIBUTES = %i[
        redirect_uri authorization_endpoint scopes client_secret private_key kid jwt_algorithm jwks_uri
      ].freeze

      WELL_KNOWN_PATH = '/.well-known/smart-configuration'.freeze

      attr_reader(*ATTRIBUTES)
      attr_accessor :client_type

      # @api private
      def initialize(config, client_type: :public)
        ATTRIBUTES.each { |attr| instance_variable_set("@#{attr}", config.public_send(attr)) }

        @client_type = client_type.to_sym
        @http_client = Safire::HTTPClient.new
        @issuer ||= base_url

        validate!
      end

      def authorization_endpoint
        @authorization_endpoint ||= server_metadata.authorization_endpoint
      end

      def token_endpoint
        @token_endpoint ||= server_metadata.token_endpoint
      end

      # Retrieves and parses SMART on FHIR configuration metadata from the FHIR server.
      #
      # This method sends a GET request to the server's
      # +/.well-known/smart-configuration+ endpoint, validates the response format,
      # and builds a {Safire::Protocols::SmartMetadata} object containing the
      # authorization and token endpoints, among other SMART metadata fields.
      #
      # The result is cached after the first successful discovery and reused on
      # subsequent calls within the same instance.
      #
      # @return [Safire::Protocols::SmartMetadata]
      #   Parsed SMART configuration metadata object.
      # @raise [Safire::Errors::DiscoveryError]
      #   If the discovery request fails or the response is not a valid JSON object.
      def server_metadata
        return @server_metadata if @server_metadata

        response = @http_client.get(well_known_endpoint)
        @server_metadata = SmartMetadata.new(parse_discovery_body(response.body))
      rescue Faraday::Error => e
        status = e.response&.dig(:status)
        Safire.logger.error("SMART discovery failed for `#{well_known_endpoint}`: HTTP #{status}")
        raise Errors::DiscoveryError.new(endpoint: well_known_endpoint, status: status)
      end

      # Builds the authorization request data for the authorization code flow.
      #
      # @param launch [String, nil] optional launch parameter
      # @param custom_scopes [Array<String>, nil] optional custom scopes to override the configured ones
      # @param method [Symbol, String] authorization request method; +:get+ (default) or +:post+.
      #   Both symbol and string forms are accepted (e.g. +method: :post+ or +method: 'post'+).
      #   * +:get+  — builds a redirect URL with all parameters in the query string (standard flow)
      #   * +:post+ — returns the endpoint and parameters separately for POST-based authorization
      #     (SMART App Launch 2.2.0 +authorize-post+ capability)
      # @return [Hash] containing:
      #   * :auth_url [String] authorization URL (GET) or bare endpoint URL (POST)
      #   * :state [String] state parameter for CSRF protection; store and verify on callback
      #   * :code_verifier [String] PKCE code verifier for the token exchange
      #   * :params [Hash] (POST only) authorization parameters to submit as the request body
      # @raise [Errors::ConfigurationError] if method is invalid, scopes are missing,
      #   or +redirect_uri+ / +authorization_endpoint+ are not configured or resolvable via discovery
      def authorization_url(launch: nil, custom_scopes: nil, method: :get)
        method = method.to_sym
        custom_scopes ||= scopes
        validate_authorization_method(method)
        validate_presence_of_scopes(custom_scopes)
        validate_app_launch_attrs!

        Safire.logger.info("Generating authorization URL for SMART #{client_type} (method: #{method})...")

        code_verifier = PKCE.generate_code_verifier
        params = authorization_params(launch:, custom_scopes:, code_verifier:)

        build_authorization_response(method, params, code_verifier)
      end

      # Exchanges the authorization code for an access token.
      #
      # @param code [String] authorization code from the authorization server
      # @param code_verifier [String] PKCE code verifier from the authorization step
      # @param client_secret [String, nil] optional; used for confidential symmetric clients when not already configured
      # @param private_key [OpenSSL::PKey, String, nil] optional; private key for asymmetric auth (overrides configured)
      # @param kid [String, nil] optional; key ID for asymmetric auth (overrides configured)
      # @return [Hash] token response parsed from the authorization server, including:
      #   * "access_token" [String] new access token issued by the authorization server (required)
      #   * "token_type"  [String] token type, exactly +"Bearer"+ (required, case-sensitive per SMART spec)
      #   * "expires_in"  [Integer] lifetime of the access token in seconds (RECOMMENDED)
      #   * "scope"       [String] authorized scopes for this token (required)
      #   * "refresh_token"           [String] refresh token, if issued (optional)
      #   * "authorization_details"   [Hash] additional authorization details, if provided (optional)
      #   * Context parameters such as "patient" or "encounter" MAY be present, depending on server behavior.
      # @raise [Safire::Errors::TokenError] if the request fails or response is invalid.
      # @raise [Safire::Errors::NetworkError] on connection failure, timeout, or SSL error.
      def request_access_token(code:, code_verifier:, client_secret: self.client_secret,
                               private_key: self.private_key, kid: self.kid)
        Safire.logger.info('Requesting access token using authorization code...')

        response = @http_client.post(
          token_endpoint,
          body: access_token_params(code, code_verifier, private_key:, kid:),
          headers: oauth2_headers(client_secret)
        )

        parse_token_response(response.body)
      rescue Faraday::Error => e
        raise token_error_from(e)
      end

      # Exchanges a refresh token for a new access token.
      #
      # @param refresh_token [String] the refresh token issued by the authorization server (required)
      # @param scopes [Array<String>, nil] optional reduced scope list;
      #   if omitted, the same scopes as the original token are requested
      # @param client_secret [String, nil] optional; used for confidential symmetric clients when not already configured
      # @param private_key [OpenSSL::PKey, String, nil] optional; private key for asymmetric auth (overrides configured)
      # @param kid [String, nil] optional; key ID for asymmetric auth (overrides configured)
      # @return [Hash] token response parsed from the authorization server.
      #   See {#request_access_token} for token response format.
      # @raise [Safire::Errors::TokenError] if the refresh request fails or the response is invalid.
      # @raise [Safire::Errors::NetworkError] on connection failure, timeout, or SSL error.
      def refresh_token(refresh_token:, scopes: nil, client_secret: self.client_secret,
                        private_key: self.private_key, kid: self.kid)
        Safire.logger.info('Refreshing access token...')

        response = @http_client.post(
          token_endpoint,
          body: refresh_token_params(refresh_token:, scopes:, private_key:, kid:),
          headers: oauth2_headers(client_secret)
        )

        parse_token_response(response.body)
      rescue Faraday::Error => e
        raise token_error_from(e)
      end

      # Requests an access token using the client credentials grant (SMART Backend Services).
      #
      # Implements the SMART Backend Services Authorization flow per
      # https://hl7.org/fhir/smart-app-launch/backend-services.html
      #
      # No user interaction, redirect, or PKCE is involved. The client authenticates
      # exclusively via a signed JWT assertion (RS384 or ES384).
      #
      # @param scopes [Array<String>, nil] scope override; uses configured scopes if nil,
      #   falling back to +["system/*.rs"]+ when neither is provided
      # @param private_key [OpenSSL::PKey] private key for JWT assertion; uses configured key if not provided.
      #   Required — must be present either in configuration or passed here.
      # @param kid [String] key ID for JWT assertion header; uses configured kid if not provided.
      #   Required — must be present either in configuration or passed here.
      # @return [Hash] token response from the authorization server, including:
      #   * "access_token" [String] access token (required)
      #   * "token_type"  [String] token type, value +"Bearer"+ (required)
      #   * "expires_in"  [Integer] lifetime of the access token in seconds (required per Backend Services spec)
      #   * "scope"       [String] authorized scopes (required)
      # @raise [Safire::Errors::ConfigurationError] if private_key or kid are missing
      # @raise [Safire::Errors::TokenError] if the server returns an error or invalid response
      # @raise [Safire::Errors::NetworkError] on connection failure, timeout, or SSL error
      def request_backend_token(scopes: nil, private_key: self.private_key, kid: self.kid)
        scopes ||= self.scopes.presence || ['system/*.rs']

        Safire.logger.info('Requesting backend services access token (client_credentials grant)...')

        response = @http_client.post(
          token_endpoint,
          body: backend_services_token_params(scopes:, private_key:, kid:),
          headers: { content_type: 'application/x-www-form-urlencoded' }
        )

        parse_token_response(response.body)
      rescue Faraday::Error => e
        raise token_error_from(e)
      end

      # Validates a token response for SMART App Launch 2.2.0 compliance.
      #
      # Checks all required token response fields per SMART App Launch 2.2.0 §Token Response:
      # - +access_token+ must be present (SHALL)
      # - +token_type+ must be present and exactly +"Bearer"+ (SHALL, case-sensitive)
      # - +scope+ must be present (SHALL)
      #
      # Logs a warning via {Safire.logger} for each violation found and returns false.
      # Never raises an exception.
      #
      # @param response [Hash] the token response returned by the server
      # @return [Boolean] true if the response is compliant, false otherwise
      def token_response_valid?(response)
        unless response.is_a?(Hash)
          Safire.logger.warn('SMART token response non-compliance: response is not a JSON object')
          return false
        end

        valid = true

        %w[access_token scope].each do |field|
          next if response[field].present?

          Safire.logger.warn(
            "SMART token response non-compliance: required field '#{field}' is missing"
          )
          valid = false
        end

        token_type_valid?(response) && valid
      end

      private

      def validate!
        missing = (ATTRIBUTES - OPTIONAL_ATTRIBUTES).select { |attr| send(attr).blank? }
        return if missing.empty?

        raise Errors::ConfigurationError.new(missing_attributes: missing)
      end

      def validate_authorization_method(method)
        return if %i[get post].include?(method)

        raise Errors::ConfigurationError.new(
          invalid_attribute: :method,
          invalid_value: method,
          valid_values: %i[get post]
        )
      end

      def build_authorization_response(method, params, code_verifier)
        if method == :post
          { auth_url: authorization_endpoint, params:, state: params[:state], code_verifier: }
        else
          uri = Addressable::URI.parse(authorization_endpoint)
          uri.query_values = params
          { auth_url: uri.to_s, state: uri.query_values['state'], code_verifier: }
        end
      end

      def validate_app_launch_attrs!
        missing = []
        missing << :redirect_uri if redirect_uri.blank?
        missing << :authorization_endpoint if authorization_endpoint.blank?
        return if missing.empty?

        raise Errors::ConfigurationError.new(missing_attributes: missing)
      end

      def validate_presence_of_scopes(scopes_value)
        return if scopes_value.present?

        raise Errors::ConfigurationError.new(missing_attributes: [:scopes])
      end

      def validate_client_secret(secret)
        return if secret.present?

        raise Errors::ConfigurationError.new(missing_attributes: [:client_secret])
      end

      def parse_discovery_body(body)
        return body if body.is_a?(Hash)

        raise Errors::DiscoveryError.new(
          endpoint: well_known_endpoint,
          error_description: 'response is not a JSON object'
        )
      end

      def parse_token_response(token_response)
        unless token_response.is_a?(Hash)
          raise Errors::TokenError.new(error_description: 'response is not a JSON object')
        end

        return token_response if token_response['access_token'].present?

        raise Errors::TokenError.new(received_fields: token_response.keys)
      end

      def token_type_valid?(response)
        if response['token_type'].blank?
          Safire.logger.warn(
            "SMART token response non-compliance: required field 'token_type' is missing"
          )
          return false
        end

        return true if response['token_type'] == 'Bearer'

        Safire.logger.warn(
          "SMART token response non-compliance: token_type is #{response['token_type'].inspect}; " \
          "expected 'Bearer' (SMART App Launch 2.2.0 requires token_type \"Bearer\")"
        )
        false
      end

      def authorization_params(launch:, custom_scopes:, code_verifier:)
        {
          response_type: 'code',
          client_id:,
          redirect_uri:,
          launch:,
          scope: [custom_scopes].flatten.join(' '),
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

      def backend_services_token_params(scopes:, private_key:, kid:)
        {
          grant_type: 'client_credentials',
          scope: [scopes].flatten.join(' ')
        }.merge(jwt_assertion_params(private_key:, kid:))
      end

      def client_auth_params(private_key:, kid:)
        case client_type
        when :public
          { client_id: client_id }
        when :confidential_asymmetric
          jwt_assertion_params(private_key:, kid:)
        else
          {}
        end
      end

      def oauth2_headers(secret)
        headers = { content_type: 'application/x-www-form-urlencoded' }

        if client_type == :confidential_symmetric
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

        raise Errors::ConfigurationError.new(missing_attributes: missing)
      end

      def token_error_from(faraday_error)
        response = faraday_error.response
        status   = response&.dig(:status)
        body     = JSON.parse(response&.dig(:body))

        Errors::TokenError.new(
          status:,
          error_code: body.is_a?(Hash) ? body['error'] : nil,
          error_description: body.is_a?(Hash) ? body['error_description'] : nil
        )
      rescue JSON::ParserError
        Errors::TokenError.new(status:)
      end

      def well_known_endpoint
        "#{base_url.to_s.chomp('/')}#{WELL_KNOWN_PATH}"
      end
    end
  end
end
