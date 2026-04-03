require 'jwt'
require 'openssl'
require 'securerandom'

module Safire
  # Generates JWT client assertions for SMART confidential asymmetric authentication.
  #
  # This class creates signed JWTs according to the SMART App Launch STU 2.2.0 specification
  # for private_key_jwt client authentication.
  #
  # @see https://hl7.org/fhir/smart-app-launch/client-confidential-asymmetric.html
  #
  # @example Creating a JWT assertion with RSA key
  #   assertion = Safire::JWTAssertion.new(
  #     client_id: 'my_app',
  #     token_endpoint: 'https://auth.example.com/token',
  #     private_key: OpenSSL::PKey::RSA.new(File.read('private.pem')),
  #     kid: 'key-id-123'
  #   )
  #   jwt = assertion.to_jwt  # => signed JWT string
  #
  # @example With explicit algorithm and jku header
  #   assertion = Safire::JWTAssertion.new(
  #     client_id: 'my_app',
  #     token_endpoint: 'https://auth.example.com/token',
  #     private_key: private_key,
  #     kid: 'key-id-123',
  #     algorithm: 'RS384',
  #     jku: 'https://app.example.com/.well-known/jwks.json'
  #   )
  #
  class JWTAssertion
    # Maximum expiration time allowed per SMART specification (5 minutes)
    MAX_EXPIRATION_SECONDS = 300

    # Default expiration time (5 minutes)
    DEFAULT_EXPIRATION_SECONDS = 300

    # Supported signing algorithms (required by SMART specification)
    SUPPORTED_ALGORITHMS = %w[RS384 ES384].freeze

    # Required parameters for JWT assertion
    REQUIRED_PARAMS = %i[client_id token_endpoint kid].freeze

    # EC curve names that support ES384 algorithm
    SUPPORTED_EC_CURVES = %w[secp384r1 P-384].freeze

    # Default algorithm for RSA keys (required by SMART spec)
    DEFAULT_RSA_ALGORITHM = 'RS384'.freeze

    # Default algorithm for EC keys (required by SMART spec)
    DEFAULT_EC_ALGORITHM = 'ES384'.freeze

    # @!attribute [r] client_id
    #   @return [String] the client_id used as iss and sub claims in the JWT
    # @!attribute [r] token_endpoint
    #   @return [String] the token endpoint URL used as aud claim in the JWT
    # @!attribute [r] private_key
    #   @return [OpenSSL::PKey::RSA, OpenSSL::PKey::EC] the private key for signing the JWT
    # @!attribute [r] kid
    #   @return [String] the key ID matching the public key registered with the authorization server
    # @!attribute [r] algorithm
    #   @return [String] the signing algorithm (RS384 or ES384)
    # @!attribute [r] jku
    #   @return [String, nil] the optional JWKS URL included in the JWT header
    # @!attribute [r] expiration_seconds
    #   @return [Integer] the JWT expiration time in seconds (max 300 per SMART spec)
    attr_reader :client_id, :token_endpoint, :private_key, :kid, :algorithm, :jku, :expiration_seconds

    # Creates a new JWT assertion generator.
    #
    # @param client_id [String] the client_id to use as iss and sub claims
    # @param token_endpoint [String] the token endpoint URL to use as aud claim
    # @param private_key [OpenSSL::PKey::RSA, OpenSSL::PKey::EC, String] the private key for signing
    #   (can be a PEM-encoded string)
    # @param kid [String] the key ID matching the registered public key
    # @param algorithm [String, nil] the signing algorithm (auto-detected from key type if nil)
    # @param jku [String, nil] optional JWKS URL for jku header (must be HTTPS)
    # @param expiration_seconds [Integer] expiration time in seconds (default: 300, max: 300)
    #
    # @raise [ArgumentError] if required parameters are missing or invalid
    def initialize(client_id:, token_endpoint:, private_key:, kid:, algorithm: nil, jku: nil,
                   expiration_seconds: DEFAULT_EXPIRATION_SECONDS)
      @client_id = client_id
      @token_endpoint = token_endpoint
      @private_key = parse_private_key(private_key)
      @kid = kid
      @algorithm = algorithm || detect_algorithm(@private_key)
      @jku = jku
      @expiration_seconds = [expiration_seconds, MAX_EXPIRATION_SECONDS].min

      validate!
    end

    # Generates a signed JWT assertion.
    #
    # @return [String] the signed JWT string
    def to_jwt
      JWT.encode(payload, private_key, algorithm, header)
    end

    # Returns the JWT header.
    #
    # @return [Hash] the JWT header with typ, kid, alg, and optional jku
    def header
      h = { typ: 'JWT', kid: kid, alg: algorithm }
      h[:jku] = jku if jku.present?
      h
    end

    # Returns the JWT payload.
    #
    # @return [Hash] the JWT payload with iss, sub, aud, exp, and jti claims
    def payload
      now = Time.now.to_i
      { iss: client_id, sub: client_id, aud: token_endpoint, exp: now + expiration_seconds, jti: generate_jti }
    end

    private

    # Parses the private key from various formats.
    #
    # @param key [OpenSSL::PKey::RSA, OpenSSL::PKey::EC, String, nil] the private key
    # @return [OpenSSL::PKey::RSA, OpenSSL::PKey::EC] the parsed private key
    # @raise [ArgumentError] if the key is invalid or unsupported
    def parse_private_key(key)
      case key
      when OpenSSL::PKey::RSA, OpenSSL::PKey::EC
        key
      when String
        parse_pem_key(key)
      else
        raise ArgumentError, 'private_key must be an OpenSSL::PKey::RSA, OpenSSL::PKey::EC, or PEM string'
      end
    end

    # Parses a PEM-encoded private key string.
    #
    # @param pem [String] the PEM-encoded private key
    # @return [OpenSSL::PKey::RSA, OpenSSL::PKey::EC] the parsed private key
    # @raise [ArgumentError] if the PEM string is invalid
    def parse_pem_key(pem)
      OpenSSL::PKey.read(pem)
    rescue OpenSSL::PKey::PKeyError => e
      raise ArgumentError, "Invalid private key: #{e.message}"
    end

    # Detects the appropriate signing algorithm based on the key type.
    # For RSA keys, uses RS384 (required by SMART spec).
    # For EC keys, uses ES384 (required by SMART spec) - requires P-384 curve.
    #
    # @param key [OpenSSL::PKey::RSA, OpenSSL::PKey::EC] the private key
    # @return [String] the detected algorithm
    # @raise [ArgumentError] if the key type or EC curve is unsupported
    def detect_algorithm(key)
      case key
      when OpenSSL::PKey::RSA
        DEFAULT_RSA_ALGORITHM
      when OpenSSL::PKey::EC
        validate_ec_curve!(key)
        DEFAULT_EC_ALGORITHM
      else
        raise ArgumentError, "Unsupported key type: #{key.class}"
      end
    end

    # Validates that the EC key uses a supported curve (P-384 for ES384).
    #
    # @param key [OpenSSL::PKey::EC] the EC private key
    # @raise [ArgumentError] if the curve is not supported
    def validate_ec_curve!(key)
      curve = key.group.curve_name
      return if SUPPORTED_EC_CURVES.include?(curve)

      raise ArgumentError, "Unsupported EC curve: #{curve}. ES384 requires P-384 (secp384r1) curve"
    end

    # Generates a unique JWT ID (jti) for replay protection.
    #
    # @return [String] a unique UUID identifier
    def generate_jti
      SecureRandom.uuid
    end

    # Validates the assertion configuration.
    #
    # @raise [ArgumentError] if validation fails
    def validate!
      validate_required_params!
      validate_algorithm!
      validate_key_algorithm_match!
      validate_jku! if jku.present?
    end

    # Validates that required parameters are present.
    #
    # @raise [ArgumentError] if required parameters are missing
    def validate_required_params!
      missing = REQUIRED_PARAMS.select { |param| send(param).blank? }
      return if missing.empty?

      raise ArgumentError, "Missing required parameters: #{missing.to_sentence}"
    end

    # Validates the algorithm is supported.
    #
    # @raise [ArgumentError] if the algorithm is not supported
    def validate_algorithm!
      return if SUPPORTED_ALGORITHMS.include?(algorithm)

      raise ArgumentError, "Unsupported algorithm: #{algorithm}. Supported: #{SUPPORTED_ALGORITHMS.to_sentence}"
    end

    # Validates the key type matches the algorithm.
    #
    # @raise [ArgumentError] if there is a mismatch
    def validate_key_algorithm_match!
      rsa_algorithm = algorithm.start_with?('RS')
      expected_key_class = rsa_algorithm ? OpenSSL::PKey::RSA : OpenSSL::PKey::EC
      return if private_key.is_a?(expected_key_class)

      raise ArgumentError, "Algorithm #{algorithm} requires an #{rsa_algorithm ? 'RSA' : 'EC'} key"
    end

    # Validates the jku URL format.
    #
    # @raise [ArgumentError] if the jku is not a valid HTTPS URL
    def validate_jku!
      uri = URI.parse(jku)
      return if uri.scheme == 'https'

      raise ArgumentError, 'jku must be an HTTPS URL'
    rescue URI::InvalidURIError
      raise ArgumentError, 'jku must be a valid URL'
    end
  end
end
