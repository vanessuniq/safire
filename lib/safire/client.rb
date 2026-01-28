module Safire
  # Unified client for SMART on FHIR authorization flows.
  #
  # This class is the main entry point for integrating SMART on FHIR authorization via Safire.
  # It supports discovery of SMART metadata and provides a unified interface for building
  # authorization URLs, exchanging authorization codes, and refreshing tokens.
  #
  # Configuration is provided via {Safire::ClientConfig} or a Hash. At minimum:
  #
  # * :base_url [String] FHIR base URL used for SMART discovery
  # * :client_id [String] OAuth2 client identifier
  # * :redirect_uri [String] redirect URI registered with the authorization server
  # * :scopes [Array<String>] default scopes requested during authorization
  # * :client_secret [String, optional] required for confidential symmetric clients if not managed externally
  #
  # The `auth_type` controls how the underlying SMART client authenticates:
  #
  # * :public                - Public client; `client_id` is sent in token and refresh requests.
  # * :confidential_symmetric - Confidential client using client_secret (e.g., HTTP Basic).
  # * :confidential_asymmetric - Reserved for future support (e.g., private_key_jwt).
  #
  # Token responses returned by {.request_access_token} and {.refresh_token} are parsed
  # JSON objects with **string keys** and are validated to include `"access_token"`.
  # On failure, a {Safire::Errors::AuthError} is raised.
  #
  # UDAP-based and additional asymmetric client flows are planned for a future iteration.
  #
  # @!attribute [r] config
  #   @return [Safire::ClientConfig] the resolved client configuration
  #
  # @!attribute [r] auth_type
  #   @return [Symbol] the configured auth type (:public, :confidential_symmetric, :confidential_asymmetric)
  # =>  Default to :public
  #
  # The client automatically discovers the SMART authorization and token endpoints
  # from the FHIR server's `.well-known/smart-configuration` metadata.
  # You won't need to provide the authorization and token endpoints in the config.
  #
  # @see Safire::ClientConfig
  # @see Safire::Protocols::Smart
  #
  # @example Step 0 – Initialize configuration
  #   config = Safire::ClientConfig.new(
  #     base_url: 'https://fhir.example.com',
  #     client_id: 'my_client_id',
  #     redirect_uri: 'https://myapp.example.com/callback',
  #     scopes: ['openid', 'profile', 'patient/*.read']
  #   )
  #
  # @example Step 1 – /launch route (authorization request)
  #   # Build authorization URL and redirect the user
  #   client = Safire::Client.new(config, auth_type: :public)
  #   auth_data = client.authorize_url
  #
  #   session[:state] = auth_data[:state]
  #   session[:code_verifier] = auth_data[:code_verifier]
  #
  #   redirect_to auth_data[:auth_url]
  #
  # @example Step 2 – /callback route (token exchange)
  #   # Verify state and exchange authorization code for an access token
  #   return head :unauthorized unless params[:state] == session[:state]
  #
  #   client = Safire::Client.new(config, auth_type: :public)
  #   token_data = client.request_access_token(
  #     code: params[:code],
  #     code_verifier: session[:code_verifier]
  #   )
  #
  #   access_token  = token_data["access_token"]
  #   refresh_token = token_data["refresh_token"]
  #
  # @example Step 3 – Refreshing an access token
  #   client = Safire::Client.new(config, auth_type: :public)
  #   new_tokens = client.refresh_token(
  #     refresh_token: stored_refresh_token
  #   )
  #   new_access_token = new_tokens["access_token"]
  class Client
    AUTH_TYPES = %i[public confidential_symmetric confidential_asymmetric].freeze

    attr_reader :config, :auth_type

    def initialize(config, auth_type: :public)
      @config = build_config(config)
      @auth_type = auth_type

      validate_auth_type
    end

    # Changes the authentication type for this client.
    #
    # @param new_auth_type [Symbol] the new auth type (:public, :confidential_symmetric, :confidential_asymmetric)
    # @return [Symbol] the new auth type
    # @raise [ArgumentError] if the auth type is not supported
    #
    # @example Discover then switch auth type
    #   client = Safire::Client.new(config)  # defaults to :public
    #   metadata = client.smart_metadata
    #
    #   if metadata.supports_confidential_symmetric_clients?
    #     client.auth_type = :confidential_symmetric
    #   end
    #
    #   # Now token requests will use Basic auth
    #   tokens = client.request_access_token(code: code, code_verifier: verifier)
    def auth_type=(new_auth_type)
      @auth_type = new_auth_type.to_sym
      validate_auth_type
      @smart_client = nil # Reset cached client to use new auth type
    end

    def smart_metadata
      @smart_metadata ||= smart_client.well_known_config
    end

    def authorize_url(launch: nil, custom_scopes: nil)
      smart_client.authorization_url(launch:, custom_scopes:)
    end

    def request_access_token(code:, code_verifier:, client_secret: config.client_secret)
      smart_client.request_access_token(code:, code_verifier:, client_secret:)
    end

    def refresh_token(refresh_token:, scopes: nil, client_secret: config.client_secret)
      smart_client.refresh_token(refresh_token:, scopes:, client_secret:)
    end

    private

    def smart_client
      @smart_client ||= Protocols::Smart.new(config.to_hash, auth_type:)
    end

    def build_config(config)
      return config if config.is_a?(Safire::ClientConfig)

      Safire::ClientConfig.new(config)
    end

    def validate_auth_type
      return if AUTH_TYPES.include?(auth_type)

      raise ArgumentError, "`#{auth_type}` is not supported. The supported auth types are #{AUTH_TYPES.to_sentence}"
    end
  end
end
