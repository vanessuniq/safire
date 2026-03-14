module Safire
  # Unified facade client for SMART on FHIR and (future) UDAP authorization flows.
  #
  # This class is the main entry point for integrating SMART on FHIR authorization via Safire.
  # It supports discovery of server metadata and provides a unified interface for building
  # authorization URLs, exchanging authorization codes, and refreshing tokens.
  #
  # Configuration is provided via {Safire::ClientConfig} or a Hash. At minimum:
  #
  # * :base_url [String] FHIR base URL used for SMART discovery
  # * :client_id [String] OAuth2 client identifier
  # * :redirect_uri [String] redirect URI registered with the authorization server
  # * :scopes [Array<String>] default scopes requested during authorization
  # * :client_secret [String, optional] required for confidential_symmetric clients
  # * :private_key [OpenSSL::PKey, String, optional] private key for confidential_asymmetric clients
  # * :kid [String, optional] key ID matching the registered public key for asymmetric clients
  # * :jwt_algorithm [String, optional] JWT signing algorithm (RS384 or ES384). Auto-detected if not provided
  # * :jwks_uri [String, optional] URL to client's JWKS for jku header in JWT assertions
  #
  # The +protocol:+ keyword selects the authorization protocol:
  #
  # * :smart (default) — SMART App Launch 2.2.0
  # * :udap             — UDAP Security (future; not yet implemented)
  #
  # The +client_type:+ keyword controls how the SMART client authenticates at the token endpoint:
  #
  # * :public (default)             — no client authentication; client_id sent in request body
  # * :confidential_symmetric       — HTTP Basic auth using client_secret
  # * :confidential_asymmetric      — private_key_jwt assertion (JWT signed with private key)
  #
  # client_type is validated for :smart and ignored for :udap (UDAP always uses private_key_jwt
  # via Dynamic Client Registration; client authentication is not user-configurable).
  #
  # @note Future kwargs (not yet implemented):
  #
  #   flow: [Symbol] the authorization flow for this client.
  #     SMART values:
  #       nil / absent  — :app_launch (default): SMART App Launch, authorization_code grant
  #       :backend_services — SMART Backend Services, client_credentials grant;
  #         private_key_jwt is implied; client_type validation is skipped
  #     UDAP values (protocol: :udap):
  #       :b2b          — client_credentials grant, server-to-server
  #       :b2c          — authorization_code grant, user-facing
  #       :tiered_oauth — authorization_code + IdP identity delegation
  #
  #   Contract methods will be extended per flow in a future PR.
  #   When protocol: :udap is fully implemented, client_type: will default to nil
  #   (not applicable) and the flow: kwarg will drive B2B vs B2C selection.
  #
  # @!attribute [r] config
  #   @return [Safire::ClientConfig] the resolved client configuration
  #
  # @!attribute [r] protocol
  #   @return [Symbol] the selected protocol (:smart or :udap)
  #
  # @!attribute [r] client_type
  #   @return [Symbol] the client authentication method
  #     (:public, :confidential_symmetric, or :confidential_asymmetric)
  #
  # @see Safire::ClientConfig
  # @see Safire::Protocols::Smart
  # @see Safire::Protocols::Behaviours
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
  #   client = Safire::Client.new(config)  # defaults to protocol: :smart, client_type: :public
  #   auth_data = client.authorization_url
  #
  #   session[:state] = auth_data[:state]
  #   session[:code_verifier] = auth_data[:code_verifier]
  #
  #   redirect_to auth_data[:auth_url]
  #
  # @example Step 2 – /callback route (token exchange)
  #   return head :unauthorized unless params[:state] == session[:state]
  #
  #   client = Safire::Client.new(config)
  #   token_data = client.request_access_token(
  #     code: params[:code],
  #     code_verifier: session[:code_verifier]
  #   )
  #
  # @example Step 3 – Refreshing an access token
  #   client = Safire::Client.new(config)
  #   new_tokens = client.refresh_token(refresh_token: stored_refresh_token)
  class Client
    extend Forwardable

    VALID_PROTOCOLS = %i[smart udap].freeze

    PROTOCOL_CLASSES = {
      smart: Protocols::Smart
      # udap: Protocols::Udap  # future
    }.freeze

    # Valid client_type values per protocol.
    # nil means the protocol does not use client_type (e.g. UDAP always uses private_key_jwt via DCR).
    PROTOCOL_CLIENT_TYPES = {
      smart: %i[public confidential_symmetric confidential_asymmetric],
      udap: nil # UDAP always uses private_key_jwt via Dynamic Client Registration
    }.freeze

    def_delegators :protocol_client,
                   :server_metadata, :authorization_url,
                   :request_access_token, :refresh_token,
                   :token_response_valid?, :register_client

    attr_reader :config, :protocol, :client_type

    def initialize(config, protocol: :smart, client_type: :public)
      @protocol    = protocol.to_sym
      @client_type = client_type.to_sym
      @config      = build_config(config)

      validate_protocol!
      validate_client_type!
    end

    # Changes the client type for this client.
    #
    # Updates the underlying protocol client in place — server metadata already
    # fetched is preserved and no re-discovery occurs.
    #
    # @param new_client_type [Symbol, String] the new client type
    # @return [Symbol] the new client type
    # @raise [Safire::Errors::ConfigurationError] if the client type is not valid for this protocol
    #
    # @example Discover then switch client type
    #   client = Safire::Client.new(config)  # defaults to :public
    #   metadata = client.server_metadata
    #
    #   if metadata.supports_symmetric_auth?
    #     client.client_type = :confidential_symmetric
    #   end
    def client_type=(new_client_type)
      @client_type = new_client_type.to_sym
      validate_client_type!
      @protocol_client&.client_type = @client_type
    end

    private

    def protocol_client
      @protocol_client ||= PROTOCOL_CLASSES.fetch(@protocol).new(config, client_type:)
    end

    def build_config(config)
      return config if config.is_a?(Safire::ClientConfig)

      Safire::ClientConfig.new(config)
    end

    def validate_protocol!
      return if VALID_PROTOCOLS.include?(@protocol)

      raise Errors::ConfigurationError.new(
        invalid_attribute: :protocol,
        invalid_value: @protocol,
        valid_values: VALID_PROTOCOLS
      )
    end

    def validate_client_type!
      valid_types = PROTOCOL_CLIENT_TYPES[@protocol]
      return if valid_types.nil? || valid_types.include?(@client_type)

      raise Errors::ConfigurationError.new(
        invalid_attribute: :client_type,
        invalid_value: @client_type,
        valid_values: valid_types
      )
    end
  end
end
