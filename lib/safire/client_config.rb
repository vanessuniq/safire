module Safire
  # Client configuration entity providing attributes for SMART authorization flows,
  # backend services, UDAP discovery, and UDAP client signing credentials.
  # The ClientConfig instance is passed to Safire::Client upon initialization.
  #
  # @!attribute [r] base_url
  #   @return [String] the base URL of the FHIR service
  # @!attribute [r] issuer
  #   @return [String] the URL of the FHIR service from which the app wishes to retrieve FHIR data.
  #     Optionally provided. Will default to `base_url` if not provided.
  # @!attribute [r] client_id
  #   @return [String, nil] the client identifier issued to the app by the authorization server.
  #     Optional at initialization — required by all authorization flows. Omit only when
  #     performing Dynamic Client Registration (RFC 7591) to obtain a +client_id+ before
  #     any flow begins.
  # @!attribute [r] redirect_uri
  #   @return [String] the redirect URI registered by the app with the authorization server
  # @!attribute [r] scopes
  #   @return [Array<String>] list of OAuth2 scopes describing the app's desired access.
  #     Optionally provided.
  # @!attribute [r] authorization_endpoint
  #   @return [String] URL of the server’s OAuth2 Authorization Endpoint.
  #   =>  Optional, will be retrieved from the well-known smart-configuration if not provided
  # @!attribute [r] token_endpoint
  #   @return [String] URL of the server's OAuth2 Token Endpoint.
  #   =>  Optional, will be retrieved from the well-known smart-configuration if not provided
  # @!attribute [r] private_key
  #   @return [OpenSSL::PKey::RSA, OpenSSL::PKey::EC, String, nil] the private key for signing
  #     SMART JWT assertions or planned UDAP software statements. Can be an OpenSSL key object or PEM string.
  # @!attribute [r] certificate_chain
  #   @return [Array<String, OpenSSL::X509::Certificate>, nil] leaf-first X.509 certificate chain
  #     for planned UDAP software-statement signing. Entries may be PEM strings or certificate objects.
  #     Certificate objects are stored as DER snapshots and returned as fresh copies. Parsing PEM
  #     strings and identity validation occur when the software statement is built.
  # @!attribute [r] kid
  #   @return [String, nil] the key ID matching the public key registered with the authorization server.
  #     Required for confidential asymmetric authentication.
  # @!attribute [r] jwt_algorithm
  #   @return [String, nil] the JWT signing algorithm. SMART supports RS384 or ES384;
  #     planned UDAP registration supports RS256, RS384, ES256, or ES384 subject to key
  #     compatibility and server discovery. Optional; selected from the key and protocol
  #     requirements when omitted.
  # @!attribute [r] jwks_uri
  #   @return [String, nil] URL to the client's JWKS containing the public key.
  #     Optional, included as jku header in JWT assertions when provided.
  # @!attribute [r] allow_insecure_localhost
  #   @return [Boolean] whether HTTP loopback URIs are accepted for local development.
  #     Defaults to +false+. Set to +true+ only in development when a local FHIR
  #     server cannot terminate TLS.
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
    include URIValidation

    ATTRIBUTES = %i[
      base_url issuer client_id client_secret redirect_uri
      scopes authorization_endpoint token_endpoint
      private_key certificate_chain kid jwt_algorithm jwks_uri
      allow_insecure_localhost
    ].freeze

    CertificateSnapshot = Data.define(:der)
    private_constant :CertificateSnapshot

    attr_reader(*(ATTRIBUTES - [:certificate_chain]))

    def certificate_chain
      return if @certificate_chain.nil?

      @certificate_chain.map { |entry| materialize_certificate_entry(entry) }.freeze
    end

    def initialize(config)
      super(config, ATTRIBUTES)

      @allow_insecure_localhost = normalize_localhost_policy(config)
      @certificate_chain = normalize_certificate_chain(@certificate_chain)
      @issuer ||= base_url
      validate!
    end

    class << self
      def builder
        ClientConfigBuilder.new
      end
    end

    CERTIFICATE_CHAIN_ENTRY_TYPES = [String, OpenSSL::X509::Certificate].freeze
    SENSITIVE_ATTRIBUTES = %i[client_secret private_key certificate_chain].freeze
    URI_ATTRS = %i[base_url redirect_uri issuer authorization_endpoint token_endpoint jwks_uri].freeze
    OPTIONAL_URI_ATTRS = %i[redirect_uri authorization_endpoint token_endpoint jwks_uri].freeze
    private_constant :CERTIFICATE_CHAIN_ENTRY_TYPES, :SENSITIVE_ATTRIBUTES, :URI_ATTRS, :OPTIONAL_URI_ATTRS

    # @api private
    def inspect
      attrs = ATTRIBUTES.map do |attr|
        # Read stored values directly so masked compound types are not materialized before being discarded.
        value = instance_variable_get(:"@#{attr}")
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

    def normalize_certificate_chain(chain)
      return if chain.nil?

      validate_certificate_chain_type!(chain)
      chain.map { |entry| snapshot_certificate_entry(entry) }.freeze
    end

    def validate_certificate_chain_type!(chain)
      raise_invalid_certificate_chain!(chain.class, [Array]) unless chain.is_a?(Array)
      raise_invalid_certificate_chain!(chain.class, ['non-empty Array']) if chain.empty?

      chain.each do |entry|
        next if CERTIFICATE_CHAIN_ENTRY_TYPES.any? { |type| entry.is_a?(type) }

        raise_invalid_certificate_chain!(entry.class, CERTIFICATE_CHAIN_ENTRY_TYPES)
      end
    end

    def snapshot_certificate_entry(entry)
      return entry.dup.freeze if entry.is_a?(String)

      CertificateSnapshot.new(der: entry.to_der.freeze)
    rescue OpenSSL::X509::CertificateError
      raise_invalid_certificate_chain!(entry.class, ['serializable OpenSSL::X509::Certificate'])
    end

    def materialize_certificate_entry(entry)
      return entry unless entry.is_a?(CertificateSnapshot)

      OpenSSL::X509::Certificate.new(entry.der)
    end

    def raise_invalid_certificate_chain!(invalid_value, valid_values)
      raise Errors::ConfigurationError.new(
        invalid_attribute: :certificate_chain,
        invalid_value:,
        valid_values:
      )
    end

    def normalize_localhost_policy(config)
      value = if config.key?(:allow_insecure_localhost)
                config[:allow_insecure_localhost]
              elsif config.key?('allow_insecure_localhost')
                config['allow_insecure_localhost']
              else
                false
              end

      validate_localhost_policy(value)
    end

    # Validates all URI attributes for structure and HTTPS requirement.
    #
    # Per SMART App Launch 2.2.0 (§App Protection, §Confidential Asymmetric),
    # all exchanges involving sensitive data SHALL use TLS. All endpoint URIs
    # must therefore use the `https` scheme.
    #
    # Exception: `http` is permitted when `allow_insecure_localhost` is true
    # and the host is `localhost` or `127.0.0.1` to support local development
    # without a TLS termination proxy.
    #
    # @raise [Errors::ConfigurationError] if any URI is malformed or uses HTTP on a non-localhost host
    def validate_uris!
      invalid_uris, non_https_uris = collect_uri_violations
      if invalid_uris.empty? && non_https_uris.empty?
        warn_if_insecure_localhost_used
        return
      end

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

        case classify_uri(value, allow_insecure_localhost:)
        when :invalid   then invalid_uris << attr
        when :non_https then non_https_uris << attr
        end
      end

      [invalid_uris, non_https_uris]
    end

    def warn_if_insecure_localhost_used
      return unless allow_insecure_localhost

      local_http_attrs = URI_ATTRS.select do |attr|
        value = send(attr)
        value && localhost_http_uri?(value)
      end
      return if local_http_attrs.empty?

      Safire.logger.warn(
        '[Safire] allow_insecure_localhost permits development-only HTTP loopback URIs; ' \
        'SMART App Launch and UDAP require HTTPS in production'
      )
    end

    def validate!
      raise Errors::ConfigurationError.new(missing_attributes: [:base_url]) if base_url.nil?

      validate_uris!
    end
  end
end
