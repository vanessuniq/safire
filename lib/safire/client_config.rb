module Safire
  # Client configuration entity providing necessary attributes to perform different
  # auth flows such as SMART on FHIR puclic, confidential symmetric, confidential asymmetric
  # clients, and backend services.
  # The ClientConfig instance is passed to Safire::Client upon initialization.
  #
  # @!attribute [r] base_url
  #   @return [String] the base URL of the FHIR service
  # @!attribute [r] issuer
  #   @return [String] the URL of the FHIR service from which the app wishes to retrieve FHIR data.
  #     Optionally provided. Will default to `base_url` if not provided.
  # @!attribute [r] client_id
  #   @return [String] the client identifier issued to the app by the authorization server
  # @!attribute [r] redirect_uri
  #   @return [String] the redirect URI registered by the app with the authorization server
  # @!attribute [r] scopes
  #   @return [Array<String>] list of OAuth2 scopes describing the app's desired access.
  #     Optionally provided.
  #
  # @example Initializing a ClientConfig
  #   config = Safire::ClientConfig.new(
  #     base_url: 'https://fhir.example.com',
  #     client_id: 'my_client_id',
  #     redirect_uri: 'https://myapp.example.com/callback',
  #     scopes: ['openid', 'profile', 'patient/*.read']
  #   )
  #  client = Safire::Client.new(config)
  #
  # @example Initializing a ClientConfig using the Builder
  #   config = Safire::ClientConfig.builder
  #     .base_url('https://fhir.example.com')
  #     .client_id('my_client_id')
  #     .redirect_uri('https://myapp.example.com/callback')
  #     .scopes(['openid', 'profile', 'patient/*.read'])
  #     .build
  #  client = Safire::Client.new(config)
  #
  # @see Safire::ClientConfigBuilder
  class ClientConfig < Entity
    ATTRIBUTES = %i[base_url issuer client_id redirect_uri scopes].freeze

    attr_reader(*ATTRIBUTES)

    def initialize(config)
      super(config, ATTRIBUTES)
      validate!
    end

    class << self
      def builder
        ClientConfigBuilder.new
      end
    end

    private

    def validate!
      required_attrs = %i[base_url client_id redirect_uri]
      nil_vars = required_attrs.select { |attr| send(attr).nil? }
      return if nil_vars.empty?

      raise Errors::ConfigurationError,
            "Client configuration missing required attributes: #{nil_vars.to_sentence}"
    end
  end
end
