require 'base64'
require 'jwt'
require 'openssl'
require 'securerandom'

module Safire
  module Protocols
    # Builds X.509-backed UDAP Dynamic Client Registration software statements.
    #
    # The resulting compact JWS follows the software-statement requirements in
    # HL7 UDAP Security STU2 and is intended for use by the UDAP registration
    # protocol flow. This class performs local signing-identity checks only; the
    # authorization server remains responsible for trusting the submitted client
    # certificate chain.
    #
    # @see https://hl7.org/fhir/us/udap-security/STU2/registration.html
    # @api private
    class UdapSoftwareStatement
      include URIValidation

      LIFETIME_SECONDS = 300
      SUPPORTED_ALGORITHMS = %w[RS256 RS384 ES256 ES384].freeze
      RSA_ALGORITHMS = %w[RS256 RS384].freeze
      EC_CURVE_ALGORITHMS = {
        'prime256v1' => ['ES256'],
        'secp256r1' => ['ES256'],
        'P-256' => ['ES256'],
        'secp384r1' => ['ES384'],
        'P-384' => ['ES384']
      }.freeze
      CERTIFICATE_ENTRY_TYPES = [String, OpenSSL::X509::Certificate].freeze
      PRIVATE_KEY_TYPES = [String, OpenSSL::PKey::RSA, OpenSSL::PKey::EC].freeze
      DEFAULT_JTI_GENERATOR = -> { SecureRandom.uuid }

      private_constant :LIFETIME_SECONDS, :SUPPORTED_ALGORITHMS, :RSA_ALGORITHMS, :EC_CURVE_ALGORITHMS,
                       :CERTIFICATE_ENTRY_TYPES, :PRIVATE_KEY_TYPES, :DEFAULT_JTI_GENERATOR

      # @param metadata [Safire::Protocols::UdapRegistrationMetadata] validated registration metadata
      # @param client_uri [String] absolute client URI used as +iss+ and +sub+
      # @param registration_endpoint [String] discovered registration endpoint used exactly as +aud+
      # @param private_key [OpenSSL::PKey::RSA, OpenSSL::PKey::EC, String] signing private key or PEM
      # @param certificate_chain [Array<String, OpenSSL::X509::Certificate>] leaf-first client certificate chain
      # @param supported_algorithms [Array<String>] algorithms advertised by UDAP discovery
      # @param algorithm [String, nil] optional explicit signing algorithm
      # @param clock [#now] time source for deterministic NumericDate claims
      # @param jti_generator [#call, nil] JTI source; defaults to +SecureRandom.uuid+
      # @param allow_insecure_localhost [Boolean] permit HTTP localhost registration endpoint for development
      # @raise [Safire::Errors::ValidationError] when +metadata+ is not validated registration metadata
      # @raise [Safire::Errors::ConfigurationError] when caller-controlled signing configuration is invalid
      # @raise [Safire::Errors::CertificateError] when the certificate chain cannot support signing
      def initialize(metadata:, client_uri:, registration_endpoint:, private_key:, certificate_chain:,
                     supported_algorithms:, algorithm: nil, clock: Time, jti_generator: nil,
                     allow_insecure_localhost: false)
        @metadata = validate_metadata(metadata)
        @client_uri = validate_client_uri(client_uri)
        @registration_endpoint = validate_registration_endpoint(registration_endpoint, allow_insecure_localhost)
        @clock = validate_clock(clock)
        @jti_generator = validate_jti_generator(jti_generator)
        @private_key = parse_private_key(private_key)
        @certificate_chain = parse_certificate_chain(certificate_chain)
        @supported_algorithms = validate_supported_algorithms(supported_algorithms)
        @algorithm = select_algorithm(algorithm)

        validate_certificate_chain!
        freeze
      end

      # Returns the signed software statement as a compact JWS string.
      #
      # @return [String]
      # @raise [Safire::Errors::ConfigurationError] when the clock or JTI generator returns an invalid value
      def to_jwt
        JWT.encode(payload, @private_key, @algorithm, header)
      end

      private

      def payload
        now = current_timestamp
        @metadata.to_h.merge(
          'iss' => @client_uri,
          'sub' => @client_uri,
          'aud' => @registration_endpoint,
          'iat' => now,
          'exp' => now + LIFETIME_SECONDS,
          'jti' => generate_jti
        )
      end

      def header
        {
          'alg' => @algorithm,
          'x5c' => @certificate_chain.map { |cert| Base64.strict_encode64(cert.to_der) }
        }
      end

      def validate_metadata(metadata)
        return metadata if metadata.is_a?(UdapRegistrationMetadata)

        raise Errors::ValidationError.new(
          attribute: :metadata,
          reason: 'must be a Safire::Protocols::UdapRegistrationMetadata'
        )
      end

      def validate_client_uri(value)
        return value if absolute_client_uri?(value)

        configuration_error!(:client_uri, value.class, ['absolute URI string'])
      end

      def absolute_client_uri?(value)
        return false unless value.is_a?(String) && value.present?

        uri = Addressable::URI.parse(value)
        return false unless uri.scheme.present?
        return uri.host.present? if %w[http https].include?(uri.scheme)

        true
      rescue Addressable::URI::InvalidURIError
        false
      end

      def validate_registration_endpoint(value, allow_insecure_localhost)
        allow_insecure_localhost = validate_localhost_policy(allow_insecure_localhost)
        return value if strict_https_uri?(value)
        return value if allow_insecure_localhost && localhost_http_uri?(value)

        configuration_error!(:registration_endpoint, value.class, ['absolute HTTPS URI'])
      end

      def validate_clock(clock)
        return clock if clock.respond_to?(:now)

        configuration_error!(:clock, clock.class, ['object responding to #now'])
      end

      def validate_jti_generator(generator)
        return DEFAULT_JTI_GENERATOR if generator.nil?
        return generator if generator.respond_to?(:call)

        configuration_error!(:jti_generator, generator.class, ['callable'])
      end

      def parse_private_key(key)
        parsed = case key
                 when OpenSSL::PKey::RSA, OpenSSL::PKey::EC
                   key
                 when String
                   OpenSSL::PKey.read(key)
                 else
                   configuration_error!(:private_key, key.class, PRIVATE_KEY_TYPES)
                 end

        validate_private_key!(parsed)
      rescue OpenSSL::PKey::PKeyError
        configuration_error!(:private_key, key.class, PRIVATE_KEY_TYPES)
      end

      def validate_private_key!(key)
        return key if supported_private_key?(key) && key.private?

        configuration_error!(:private_key, key.class, PRIVATE_KEY_TYPES)
      end

      def supported_private_key?(key)
        key.is_a?(OpenSSL::PKey::RSA) || key.is_a?(OpenSSL::PKey::EC)
      end

      def parse_certificate_chain(chain)
        configuration_error!(:certificate_chain, chain.class, ['non-empty Array']) unless chain.is_a?(Array)
        configuration_error!(:certificate_chain, chain.class, ['non-empty Array']) if chain.empty?

        chain.map { |entry| parse_certificate_entry(entry) }.freeze
      end

      def parse_certificate_entry(entry)
        unless CERTIFICATE_ENTRY_TYPES.any? { |type| entry.is_a?(type) }
          configuration_error!(:certificate_chain, entry.class, CERTIFICATE_ENTRY_TYPES)
        end

        cert = entry.is_a?(String) ? OpenSSL::X509::Certificate.new(entry) : OpenSSL::X509::Certificate.new(entry.to_der)
        cert.freeze
      rescue OpenSSL::X509::CertificateError
        raise Errors::CertificateError.new(reason: 'malformed certificate in certificate_chain')
      end

      def validate_supported_algorithms(values)
        unless values.is_a?(Array) && values.all?(String)
          configuration_error!(:supported_algorithms, values.class, ['Array<String>'])
        end

        values.dup.freeze
      end

      def select_algorithm(explicit_algorithm)
        compatible = compatible_algorithms
        return select_explicit_algorithm(explicit_algorithm, compatible) unless explicit_algorithm.nil?

        compatible.find { |candidate| @supported_algorithms.include?(candidate) } ||
          configuration_error!(:supported_algorithms, @supported_algorithms, compatible)
      end

      def select_explicit_algorithm(algorithm, compatible)
        return algorithm if SUPPORTED_ALGORITHMS.include?(algorithm) &&
                            compatible.include?(algorithm) &&
                            @supported_algorithms.include?(algorithm)

        configuration_error!(:algorithm, algorithm, compatible & @supported_algorithms)
      end

      def compatible_algorithms
        case @private_key
        when OpenSSL::PKey::RSA
          RSA_ALGORITHMS
        when OpenSSL::PKey::EC
          EC_CURVE_ALGORITHMS.fetch(@private_key.group.curve_name) do
            configuration_error!(:algorithm, @private_key.group.curve_name, EC_CURVE_ALGORITHMS.keys)
          end
        end
      end

      def validate_certificate_chain!
        time = current_time
        @certificate_chain.each { |cert| validate_certificate_time!(cert, time) }
        validate_key_matches_leaf!
        validate_leaf_uri_san!
      end

      def validate_certificate_time!(cert, time)
        if cert.not_before > time
          raise Errors::CertificateError.new(reason: 'certificate is not yet valid', subject: cert.subject.to_s)
        end
        return unless cert.not_after <= time

        raise Errors::CertificateError.new(reason: 'certificate is expired', subject: cert.subject.to_s)
      end

      def validate_key_matches_leaf!
        return if private_key_matches_leaf?

        raise Errors::CertificateError.new(
          reason: 'private key does not match the leaf certificate public key',
          subject: leaf_certificate.subject.to_s
        )
      end

      def private_key_matches_leaf?
        data = 'safire-udap-key-check'
        digest = OpenSSL::Digest.new('SHA256')
        signature = @private_key.sign(digest, data)
        leaf_certificate.public_key.verify(digest, signature, data)
      rescue OpenSSL::PKey::PKeyError
        false
      end

      def validate_leaf_uri_san!
        return if uri_sans(leaf_certificate).include?(@client_uri)

        raise Errors::CertificateError.new(
          reason: 'client_uri does not match any URI SAN in the leaf certificate',
          subject: leaf_certificate.subject.to_s
        )
      end

      def uri_sans(cert)
        san_ext = cert.extensions.find { |extension| extension.oid == 'subjectAltName' }
        return [] unless san_ext

        # OpenSSL renders SAN values as comma-separated text. That covers the
        # simple UDAP client URI identifiers this builder supports without
        # introducing ASN.1 parsing solely for uncommon literal comma cases.
        san_ext.value.split(',').filter_map do |entry|
          san = entry.strip
          san.delete_prefix('URI:') if san.start_with?('URI:')
        end
      end

      def leaf_certificate
        @certificate_chain.first
      end

      def current_timestamp
        current_time.to_i
      end

      def current_time
        time = @clock.now
        return time if time.respond_to?(:to_i)

        configuration_error!(:clock, time.class, ['object whose #now result responds to #to_i'])
      end

      def generate_jti
        jti = @jti_generator.call
        return jti if jti.is_a?(String) && jti.present?

        configuration_error!(:jti_generator, jti.class, ['callable returning a non-blank String'])
      end

      def configuration_error!(attribute, invalid_value, valid_values)
        raise Errors::ConfigurationError.new(
          invalid_attribute: attribute,
          invalid_value:,
          valid_values:
        )
      end
    end
  end
end
