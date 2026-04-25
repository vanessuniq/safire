module Safire
  # Unified facade client for SMART and (future) UDAP authorization flows.
  #
  # This class is the main entry point for integrating SMART authorization via Safire.
  # It supports discovery of server metadata and provides a unified interface for building
  # authorization URLs, exchanging authorization codes, refreshing tokens, and requesting
  # backend services access tokens (client_credentials grant).
  #
  # Configuration is provided via {Safire::ClientConfig} or a Hash. Key attributes:
  #
  # * :base_url [String] FHIR base URL used for SMART discovery
  # * :client_id [String, nil] OAuth2 client identifier — optional at initialization;
  #     required by all authorization flows and validated at call time
  # * :redirect_uri [String] redirect URI registered with the authorization server;
  #     required for app launch, not required for backend services
  # * :scopes [Array<String>] default scopes; falls back to +["system/*.rs"]+ for
  #     backend services when not provided
  # * :client_secret [String, optional] required for confidential_symmetric clients
  # * :private_key [OpenSSL::PKey, String, optional] private key for asymmetric clients and backend services
  # * :kid [String, optional] key ID matching the registered public key for asymmetric clients and backend services
  # * :jwt_algorithm [String, optional] JWT signing algorithm (RS384 or ES384). Auto-detected if not provided
  # * :jwks_uri [String, optional] URL to client's JWKS for jku header in JWT assertions
  #
  # The +protocol:+ keyword selects the authorization protocol:
  #
  # * :smart (default) — SMART App Launch 2.2.0
  # * :udap             — UDAP Security (future; not yet implemented)
  #
  # The +client_type:+ keyword controls how the SMART client authenticates at the token endpoint.
  # Defaults to +nil+, which resolves to +:public+ for SMART. For UDAP, +client_type:+ is not
  # applicable — passing any explicit value raises +ConfigurationError+.
  #
  # * :public             — no client authentication; client_id sent in request body (SMART default)
  # * :confidential_symmetric       — HTTP Basic auth using client_secret
  # * :confidential_asymmetric      — private_key_jwt assertion (JWT signed with private key)
  #
  # UDAP clients authenticate via signed JWT assertions (Authentication Token / AnT) with an
  # X.509 certificate chain in the x5c JOSE header; the authentication method is not
  # user-configurable for UDAP. DCR is typically performed once to obtain a client_id, which is
  # then reused as iss/sub in every subsequent AnT. The unregistered client flow (§8.1) allows
  # client_credentials grant without prior DCR when identity can be fully determined from
  # certificate attributes alone.
  #
  # @note Future kwargs (not yet implemented):
  #
  #   flow: [Symbol] the authorization flow for UDAP clients (protocol: :udap):
  #     :b2b          — client_credentials grant, server-to-server
  #     :b2c          — authorization_code grant, user-facing
  #     :tiered_oauth — authorization_code + IdP identity delegation
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
  #
  # @example Backend Services – system-to-system access token (client_credentials grant)
  #   config = Safire::ClientConfig.new(
  #     base_url:   'https://fhir.example.com',
  #     client_id:  'my_client_id',
  #     private_key: OpenSSL::PKey::RSA.new(File.read('private_key.pem')),
  #     kid:        'my-key-id',
  #     scopes:     ['system/Patient.rs']
  #   )
  #   client = Safire::Client.new(config, client_type: :confidential_asymmetric)
  #   token_data = client.request_backend_token
  #
  # @example Dynamic Client Registration – obtain a client_id before authorization flows
  #   # Step 1 – create a temporary client (no client_id required)
  #   temp_client = Safire::Client.new({ base_url: 'https://fhir.example.com' })
  #
  #   # Step 2 – register and receive credentials
  #   registration = temp_client.register_client(
  #     {
  #       client_name:                'My FHIR App',
  #       redirect_uris:              ['https://myapp.example.com/callback'],
  #       grant_types:                ['authorization_code'],
  #       token_endpoint_auth_method: 'private_key_jwt',
  #       jwks_uri:                   'https://myapp.example.com/.well-known/jwks.json'
  #     }
  #   )
  #
  #   # Step 3 – persist credentials durably (database, secrets manager, etc.)
  #   client_id = registration['client_id']
  #
  #   # Step 4 – build a properly configured client for subsequent authorization flows
  #   client = Safire::Client.new(
  #     {
  #       base_url:     'https://fhir.example.com',
  #       client_id:    client_id,
  #       redirect_uri: 'https://myapp.example.com/callback',
  #       scopes:       ['openid', 'profile', 'patient/*.read']
  #     }
  #   )
  class Client
    extend Forwardable

    VALID_PROTOCOLS = %i[smart udap].freeze

    # Valid client_type values per protocol.
    # nil means client_type is not applicable for that protocol; any explicit value raises ConfigurationError.
    PROTOCOL_CLIENT_TYPES = {
      smart: %i[public confidential_symmetric confidential_asymmetric],
      udap: nil # UDAP authenticates via signed JWT assertions (AnT) with X.509 certificate chain
    }.freeze

    def_delegators :protocol_client,
                   :server_metadata, :authorization_url,
                   :request_access_token, :refresh_token,
                   :request_backend_token,
                   :token_response_valid?, :register_client

    attr_reader :config, :protocol, :client_type

    def initialize(config, protocol: :smart, client_type: nil)
      @protocol    = protocol.to_sym
      @client_type = client_type&.to_sym
      @config      = build_config(config)

      validate_protocol!
      resolve_client_type!
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
      raise_client_type_not_applicable!(new_client_type) if PROTOCOL_CLIENT_TYPES[@protocol].nil?

      @client_type = new_client_type.to_sym
      validate_client_type!
      @protocol_client&.client_type = @client_type
    end

    private

    def protocol_client
      @protocol_client ||= build_protocol_client
    end

    def build_protocol_client
      case @protocol
      when :smart then Protocols::Smart.new(config, client_type:)
      when :udap  then raise NotImplementedError, 'UDAP protocol client is not yet implemented'
      end
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

    def resolve_client_type!
      @client_type = :public if @protocol == :smart && @client_type.nil?
    end

    def validate_client_type!
      valid_types = PROTOCOL_CLIENT_TYPES[@protocol]
      if valid_types.nil?
        return if @client_type.nil?

        raise_client_type_not_applicable!(@client_type)
      end
      return if valid_types.include?(@client_type)

      raise Errors::ConfigurationError.new(
        invalid_attribute: :client_type,
        invalid_value: @client_type,
        valid_values: valid_types
      )
    end

    def raise_client_type_not_applicable!(value)
      raise Errors::ConfigurationError.new(
        invalid_attribute: :client_type,
        invalid_value: value,
        valid_values: ["N/A (client_type is not applicable for protocol :#{@protocol})"]
      )
    end
  end
end
