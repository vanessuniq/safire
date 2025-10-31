module Safire
  # Safire client providing unified interface to SMART on FHIR auth flows
  #
  # This class serves as the main entry point for interacting with the Safire library.
  # It handles discovery of SMART metadata and provides access to diffent auth flows
  # such as public clients, confidential symmetric & asymmetric clients, and backend services.
  #
  # @!attribute [r] config
  #   @return [Safire::ClientConfig] the client configuration instance
  #
  # @example Quick start with public client
  #   config = Safire::ClientConfig.new(
  #     base_url: 'https://fhir.example.com',
  #     client_id: 'my_client_id',
  #     redirect_uri: 'https://myapp.example.com/callback',
  #     scopes: ['openid', 'profile', 'patient/*.read']
  #   )
  #   public_client = Safire::Client.new(config).public_client
  #   # Build authorization URL
  #   auth_data = public_client.authorization_url
  #   puts auth_data[:auth_url]  # The authorization URL
  #   puts auth_data[:state]     # The state parameter (user should store to verify the state in the callback)
  #   # Your app should redirect the user to the auth_url (auth_data[:auth_url]) and handle the callback
  #   # to obtain the authorization code. After receiving the code:
  #   token_response = public_client.request_access_token(code_from_callback)
  #   puts token_response['access_token']  # The obtained access token
  # @see Safire::ClientConfig
  # @see Safire::Protocols::Smart::PublicClient
  class Client
    attr_reader :config

    # Initialie Safire client with a set of config
    #
    # @param config an instance of Safire::ClientConfig
    def initialize(config)
      @config = config
    end

    def smart_metadata
      @smart_metadata ||= Safire::Protocols::Smart::Discovery.new(config.base_url).discover
    end

    def public_client
      @public_client ||= Protocols::Smart::PublicClient.new(public_client_config)
    end

    private

    def public_client_config
      {
        client_id: config.client_id,
        issuer: config.issuer,
        redirect_uri: config.redirect_uri,
        scopes: config.scopes || [],
        authorization_endpoint: smart_metadata.authorization_endpoint,
        token_endpoint: smart_metadata.token_endpoint
      }
    end
  end
end
