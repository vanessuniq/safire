require 'securerandom'

module Safire
  module Protocols
    # Builds the UDAP Authentication Token (AnT) sent as +client_assertion+ at
    # the token endpoint.
    #
    # HL7 UDAP Security STU2 (B2B and Consumer-Facing, "Constructing
    # Authentication Token") requires +iss+ and +sub+ to be the registered
    # +client_id+, +aud+ to be the token endpoint URL, integer +iat+ and +exp+,
    # and a +jti+ nonce. "The maximum lifetime for an Authentication Token
    # SHALL be 5 minutes"; Safire always signs +exp = iat + 300+. The JOSE
    # header carries only +alg+ and +x5c+ (General Guidance §7.1), produced by
    # {UdapSigningCredentials}.
    #
    # The conditional +extensions+ claim ("A JSON object containing one or more
    # extensions") is included only when the caller supplies a non-empty Hash
    # whose values are non-empty JSON objects. Extension contents (for example
    # +hl7-b2b+) are not interpreted here; callers pass already-built extension
    # objects.
    #
    # Unlike {UdapSoftwareStatement}, no leaf-certificate URI SAN check is
    # performed: +iss+ is the server-assigned +client_id+, not the client URI.
    #
    # The token endpoint is signed exactly as supplied (no normalization), per
    # the General Guidance note that clients "should include the URI exactly as
    # it was originally provided by that server".
    #
    # @see https://hl7.org/fhir/us/udap-security/STU2/b2b.html#constructing-authentication-token
    # @see https://hl7.org/fhir/us/udap-security/STU2/consumer.html#constructing-authentication-token
    # @see https://hl7.org/fhir/us/udap-security/STU2/general.html#jwt-claims
    # @api private
    class UdapAuthenticationToken
      include URIValidation

      LIFETIME_SECONDS = 300
      DEFAULT_JTI_GENERATOR = -> { SecureRandom.uuid }
      JSON_SCALAR_TYPES = [String, Integer, TrueClass, FalseClass, NilClass].freeze

      private_constant :LIFETIME_SECONDS, :DEFAULT_JTI_GENERATOR, :JSON_SCALAR_TYPES

      # @return [String] client_id used as +iss+ and +sub+
      attr_reader :client_id

      # @return [String] token endpoint used exactly as +aud+
      attr_reader :token_endpoint

      # @param client_id [String] client_id assigned by the authorization server at registration
      # @param token_endpoint [String] discovered token endpoint, signed exactly as +aud+
      # @param private_key [OpenSSL::PKey::RSA, OpenSSL::PKey::EC, String] signing private key or PEM
      # @param certificate_chain [Array<String, OpenSSL::X509::Certificate>] leaf-first,
      #   issuer-ordered client certificate chain
      # @param supported_algorithms [Array<String>] server's +token_endpoint_auth_signing_alg_values_supported+
      # @param algorithm [String, nil] optional explicit signing algorithm
      # @param extensions [Hash{String, Symbol => Hash}, nil] optional +extensions+ claim;
      #   +nil+ omits the claim, an empty Hash is rejected
      # @param clock [#now] time source returning +Time+
      # @param jti_generator [#call, nil] JTI source; defaults to +SecureRandom.uuid+
      # @param allow_insecure_localhost [Boolean] permit an HTTP localhost token endpoint for development
      # @raise [Safire::Errors::ConfigurationError] when caller-controlled signing configuration is invalid
      # @raise [Safire::Errors::ValidationError] when +extensions+ is not a valid extensions object
      # @raise [Safire::Errors::CertificateError] when the certificate chain cannot support signing
      def initialize(client_id:, token_endpoint:, private_key:, certificate_chain:, supported_algorithms:,
                     algorithm: nil, extensions: nil, clock: Time, jti_generator: nil,
                     allow_insecure_localhost: false)
        @client_id = validate_client_id(client_id)
        @token_endpoint = validate_token_endpoint(token_endpoint, allow_insecure_localhost)
        @extensions = normalize_extensions(extensions)
        @jti_generator = validate_jti_generator(jti_generator)
        @credentials = UdapSigningCredentials.new(
          private_key:, certificate_chain:, supported_algorithms:, algorithm:, clock:
        )
        freeze
      end

      # @return [String] selected JWS signing algorithm
      def algorithm
        @credentials.algorithm
      end

      # Returns a newly signed Authentication Token with a fresh +jti+.
      #
      # @return [String] compact JWS
      # @raise [Safire::Errors::ConfigurationError] when the clock or JTI generator returns an invalid value
      # @raise [Safire::Errors::CertificateError] when the certificate chain is not valid at signing time
      def to_jwt
        signing_time = @credentials.current_time
        @credentials.validate_certificate_times!(signing_time)

        @credentials.sign(payload(signing_time))
      end

      private

      def payload(signing_time)
        now = signing_time.to_i
        claims = {
          'iss' => @client_id,
          'sub' => @client_id,
          'aud' => @token_endpoint,
          'iat' => now,
          'exp' => now + LIFETIME_SECONDS,
          'jti' => generate_jti
        }
        claims['extensions'] = @extensions unless @extensions.nil?
        claims
      end

      def validate_client_id(value)
        configuration_error!(:client_id, value.class, ['non-blank String']) unless value.nil? || value.is_a?(String)
        raise Errors::ConfigurationError.new(missing_attributes: [:client_id]) if value.blank?

        immutable_string(value)
      end

      def validate_token_endpoint(value, allow_insecure_localhost)
        allow_insecure_localhost = validate_localhost_policy(allow_insecure_localhost)
        if classify_uri(value, allow_insecure_localhost:, allow_fragment: false).nil? && endpoint_host?(value)
          return immutable_string(value)
        end

        configuration_error!(:token_endpoint, value.class, [token_endpoint_requirement(allow_insecure_localhost)])
      end

      def endpoint_host?(value)
        Addressable::URI.parse(value).host.present?
      end

      def token_endpoint_requirement(allow_insecure_localhost)
        return 'absolute HTTPS URI without fragment' unless allow_insecure_localhost

        'absolute HTTPS URI (or HTTP localhost) without fragment'
      end

      def validate_jti_generator(generator)
        return DEFAULT_JTI_GENERATOR if generator.nil?
        return generator if generator.respond_to?(:call)

        configuration_error!(:jti_generator, generator.class, ['callable'])
      end

      def generate_jti
        jti = @jti_generator.call
        return immutable_string(jti) if jti.is_a?(String) && jti.present?

        configuration_error!(:jti_generator, jti.class, ['callable returning a non-blank String'])
      end

      # -- extensions ---------------------------------------------------------

      def normalize_extensions(extensions)
        return nil if extensions.nil?

        extensions_error!('must be a Hash or nil') unless extensions.is_a?(Hash)
        extensions_error!('must contain one or more extensions') if extensions.empty?

        normalize_object(extensions, Set.new) do |key, value, seen|
          extensions_error!('extension keys must be non-blank') if key.blank?
          extension_value(value, seen)
        end
      end

      def extension_value(value, seen)
        extensions_error!('each extension must be a JSON object') unless value.is_a?(Hash)
        extensions_error!('each extension must be a non-empty JSON object') if value.empty?

        normalize_json(value, seen)
      end

      # Copies a Hash with String keys, yielding each normalized key and value.
      def normalize_object(hash, seen)
        guard_cycle!(hash, seen) do
          hash.each_with_object({}) do |(key, value), copy|
            name = normalize_key(key)
            extensions_error!('duplicate key after normalization') if copy.key?(name)
            copy[name] = yield(name, value, seen)
          end.freeze
        end
      end

      def normalize_key(key)
        case key
        when String then immutable_string(key)
        when Symbol then key.to_s.freeze
        else extensions_error!('object keys must be Strings or Symbols')
        end
      end

      def normalize_json(value, seen)
        case value
        when Hash then normalize_object(value, seen) { |_key, nested, nested_seen| normalize_json(nested, nested_seen) }
        when Array then guard_cycle!(value, seen) { value.map { |item| normalize_json(item, seen) }.freeze }
        when Float then finite_float(value)
        when String then immutable_string(value)
        when *JSON_SCALAR_TYPES then value
        else extensions_error!('values must be JSON-compatible')
        end
      end

      def finite_float(value)
        return value if value.finite?

        extensions_error!('values must be JSON-compatible (finite numbers only)')
      end

      def guard_cycle!(container, seen)
        extensions_error!('must not contain cyclic references') if seen.include?(container.object_id)

        seen.add(container.object_id)
        result = yield
        seen.delete(container.object_id)
        result
      end

      def extensions_error!(reason)
        raise Errors::ValidationError.new(attribute: :extensions, reason:)
      end

      def configuration_error!(attribute, invalid_value, valid_values)
        raise Errors::ConfigurationError.new(
          invalid_attribute: attribute,
          invalid_value:,
          valid_values:
        )
      end

      def immutable_string(value)
        value.dup.freeze
      end
    end
  end
end
