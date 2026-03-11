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
  # @!attribute [r] authorization_endpoint
  #   @return [String] URL of the server’s OAuth2 Authorization Endpoint.
  # =>  Optional, will be retrieved from the well-known smart-configuration if not provided
  # @!attribute [r] token_endpoint
  #   @return [String] URL of the server's OAuth2 Token Endpoint.
  # =>  Optional, will be retrieved from the well-known smart-configuration if not provided
  # @!attribute [r] private_key
  #   @return [OpenSSL::PKey::RSA, OpenSSL::PKey::EC, String, nil] the private key for signing
  #     JWT assertions in confidential asymmetric auth. Can be an OpenSSL key object or PEM string.
  # @!attribute [r] kid
  #   @return [String, nil] the key ID matching the public key registered with the authorization server.
  #     Required for confidential asymmetric authentication.
  # @!attribute [r] jwt_algorithm
  #   @return [String, nil] the JWT signing algorithm (RS384 or ES384).
  #     Optional, auto-detected from key type if not provided.
  # @!attribute [r] jwks_uri
  #   @return [String, nil] URL to the client's JWKS containing the public key.
  #     Optional, included as jku header in JWT assertions when provided.
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
    ATTRIBUTES = %i[
      base_url issuer client_id client_secret redirect_uri
      scopes authorization_endpoint token_endpoint
      private_key kid jwt_algorithm jwks_uri
    ].freeze

    attr_reader(*ATTRIBUTES)

    def initialize(config)
      super(config, ATTRIBUTES)

      @issuer ||= base_url
      validate!
    end

    class << self
      def builder
        ClientConfigBuilder.new
      end
    end

    SENSITIVE_ATTRIBUTES = %i[client_secret private_key].freeze
    URI_ATTRS = %i[base_url redirect_uri issuer authorization_endpoint token_endpoint jwks_uri].freeze
    OPTIONAL_URI_ATTRS = %i[authorization_endpoint token_endpoint jwks_uri].freeze
    private_constant :SENSITIVE_ATTRIBUTES, :URI_ATTRS, :OPTIONAL_URI_ATTRS

    # @api private
    def inspect
      attrs = ATTRIBUTES.map do |attr|
        value = send(attr)
        next if value.nil?

        masked = SENSITIVE_ATTRIBUTES.include?(attr) ? '[FILTERED]' : value.inspect
        "#{attr}: #{masked}"
      end.compact.join(', ')
      "#<#{self.class} #{attrs}>"
    end

    protected

    # @return [Array<Symbol>] attributes masked as '[FILTERED]' in #to_hash
    def sensitive_attributes
      SENSITIVE_ATTRIBUTES
    end

    private

    # Validates all URI attributes for structure and HTTPS requirement.
    #
    # Per SMART App Launch 2.2.0 (§App Protection, §Confidential Asymmetric),
    # all exchanges involving sensitive data SHALL use TLS. All endpoint URIs
    # must therefore use the `https` scheme.
    #
    # Exception: `http` is permitted when the host is `localhost` or `127.0.0.1`
    # to support local development without a TLS termination proxy.
    #
    # @raise [Errors::ConfigurationError] if any URI is malformed or uses HTTP on a non-localhost host
    def validate_uris!
      invalid_uris, non_https_uris = collect_uri_violations
      return if invalid_uris.empty? && non_https_uris.empty?

      raise Errors::ConfigurationError.new(
        invalid_uri_attributes: invalid_uris,
        non_https_uri_attributes: non_https_uris
      )
    end

    def collect_uri_violations
      invalid_uris = []
      non_https_uris = []

      URI_ATTRS.each do |attr|
        value = send(attr)
        next if value.nil? && OPTIONAL_URI_ATTRS.include?(attr)

        case classify_uri(value)
        when :invalid   then invalid_uris << attr
        when :non_https then non_https_uris << attr
        end
      end

      [invalid_uris, non_https_uris]
    end

    def classify_uri(value)
      uri = Addressable::URI.parse(value)
      return :invalid unless uri.scheme && uri.host

      :non_https if uri.scheme != 'https' && !localhost_host?(uri.host)
    rescue Addressable::URI::InvalidURIError
      :invalid
    end

    # Returns true when the host is a local loopback address.
    # HTTP is permitted for localhost to support development environments.
    def localhost_host?(host)
      %w[localhost 127.0.0.1].include?(host)
    end

    def validate!
      required_attrs = %i[base_url client_id redirect_uri]
      nil_vars = required_attrs.select { |attr| send(attr).nil? }

      if nil_vars.empty?
        validate_uris!
        return
      end

      raise Errors::ConfigurationError.new(missing_attributes: nil_vars)
    end
  end
end
