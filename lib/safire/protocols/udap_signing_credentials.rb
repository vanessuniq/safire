require 'base64'
require 'jwt'
require 'openssl'

module Safire
  module Protocols
    # X.509-backed signing identity shared by UDAP signed JWTs.
    #
    # Parses and snapshots a private key and leaf-first certificate chain,
    # negotiates a key-compatible signing algorithm from the server-advertised
    # list, and produces compact JWS values with the UDAP JOSE header
    # (+alg+ and a leaf-first +x5c+ chain only).
    #
    # UDAP Security STU2 General Guidance §7.1 requires signed JWTs to carry
    # +alg+ and +x5c+ headers, with the signer's certificate first in +x5c+.
    # Safire supports RS256 and RS384 for RSA keys, ES256 for EC P-256 keys, and
    # ES384 for EC P-384 keys.
    #
    # This class performs local signing-identity checks only: chain order,
    # private key to leaf certificate match, and certificate validity dates.
    # It does not check trust anchors or revocation and it does not check URI
    # SANs; claim-specific checks belong to the caller (for example,
    # {UdapSoftwareStatement} requires +client_uri+ to match a leaf URI SAN).
    #
    # @see https://hl7.org/fhir/us/udap-security/STU2/general.html#jwt-headers
    # @api private
    class UdapSigningCredentials
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
      URI_SAN_TAG = 6

      private_constant :SUPPORTED_ALGORITHMS, :RSA_ALGORITHMS, :EC_CURVE_ALGORITHMS,
                       :CERTIFICATE_ENTRY_TYPES, :PRIVATE_KEY_TYPES, :URI_SAN_TAG

      # @return [String] selected JWS signing algorithm
      attr_reader :algorithm

      # @return [Array<String>] Base64 (strict, non-URL-safe) DER certificates, leaf first
      attr_reader :x5c

      # @param private_key [OpenSSL::PKey::RSA, OpenSSL::PKey::EC, String] signing private key or PEM
      # @param certificate_chain [Array<String, OpenSSL::X509::Certificate>] leaf-first,
      #   issuer-ordered certificate chain
      # @param supported_algorithms [Array<String>] algorithms advertised by UDAP discovery
      # @param algorithm [String, nil] optional explicit signing algorithm
      # @param clock [#now] time source returning +Time+
      # @raise [Safire::Errors::ConfigurationError] when caller-controlled signing configuration is invalid
      # @raise [Safire::Errors::CertificateError] when the certificate chain cannot support signing
      def initialize(private_key:, certificate_chain:, supported_algorithms:, algorithm: nil, clock: Time)
        @clock = validate_clock(clock)
        @private_key = parse_private_key(private_key)
        @certificate_chain = parse_certificate_chain(certificate_chain)
        @supported_algorithms = validate_supported_algorithms(supported_algorithms)
        @algorithm = select_algorithm(algorithm)

        validate_certificate_chain!
        @x5c = @certificate_chain.map { |cert| Base64.strict_encode64(cert.to_der).freeze }.freeze
        freeze
      end

      # @return [OpenSSL::X509::Certificate] frozen leaf (signer) certificate
      def leaf_certificate
        @certificate_chain.first
      end

      # @return [Hash{String => Object}] JOSE header containing only +alg+ and +x5c+
      def jose_header
        { 'alg' => @algorithm, 'x5c' => @x5c }
      end

      # Reads the configured clock.
      #
      # @return [Time]
      # @raise [Safire::Errors::ConfigurationError] when the clock does not return a +Time+
      def current_time
        time = @clock.now
        return time if time.is_a?(Time)

        configuration_error!(:clock, time.class, ['object whose #now result is a Time'])
      end

      # Checks every certificate in the chain is within its validity period at +time+.
      #
      # @param time [Time]
      # @return [void]
      # @raise [Safire::Errors::CertificateError] when a certificate is expired or not yet valid
      def validate_certificate_times!(time)
        @certificate_chain.each { |cert| validate_certificate_time!(cert, time) }
      end

      # @param uri [String]
      # @return [Boolean] whether +uri+ exactly matches a URI SAN in the leaf certificate
      def leaf_uri_san?(uri)
        uri_sans(leaf_certificate).include?(uri)
      end

      # Signs +payload+ with the private key and selected algorithm.
      #
      # Callers are responsible for checking certificate validity at the signing
      # time (see {#validate_certificate_times!}).
      #
      # @param payload [Hash] JWT claims
      # @return [String] compact JWS
      def sign(payload)
        JWT.encode(payload, @private_key, @algorithm, jose_header)
      end

      private

      def validate_clock(clock)
        return clock if clock.respond_to?(:now)

        configuration_error!(:clock, clock.class, ['object responding to #now'])
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

        cert = if entry.is_a?(String)
                 OpenSSL::X509::Certificate.new(entry)
               else
                 OpenSSL::X509::Certificate.new(entry.to_der)
               end
        cert.freeze
      rescue OpenSSL::X509::CertificateError
        raise Errors::CertificateError.new(reason: 'malformed certificate in certificate_chain')
      end

      def validate_supported_algorithms(values)
        unless values.is_a?(Array) && values.all?(String)
          configuration_error!(:supported_algorithms, values.class, ['Array<String>'])
        end

        values.map { |value| immutable_string(value) }.freeze
      end

      def select_algorithm(explicit_algorithm)
        compatible = compatible_algorithms
        return select_explicit_algorithm(explicit_algorithm, compatible) unless explicit_algorithm.nil?

        selected = compatible.find { |candidate| @supported_algorithms.include?(candidate) }
        return immutable_string(selected) if selected

        configuration_error!(:supported_algorithms, @supported_algorithms, compatible)
      end

      def select_explicit_algorithm(algorithm, compatible)
        if SUPPORTED_ALGORITHMS.include?(algorithm) &&
           compatible.include?(algorithm) &&
           @supported_algorithms.include?(algorithm)
          return immutable_string(algorithm)
        end

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
        validate_certificate_times!(current_time)
        validate_chain_order!
        validate_key_matches_leaf!
      end

      def validate_certificate_time!(cert, time)
        if cert.not_before > time
          raise Errors::CertificateError.new(reason: 'certificate is not yet valid', subject: cert.subject.to_s)
        end
        return unless cert.not_after < time

        raise Errors::CertificateError.new(reason: 'certificate is expired', subject: cert.subject.to_s)
      end

      def validate_chain_order!
        @certificate_chain.each_cons(2) do |child, issuer|
          next if child.issuer == issuer.subject && child.verify(issuer.public_key)

          raise Errors::CertificateError.new(
            reason: 'certificate_chain must be leaf-first and issuer-ordered',
            subject: child.subject.to_s
          )
        end
      rescue OpenSSL::X509::CertificateError, OpenSSL::PKey::PKeyError
        raise Errors::CertificateError.new(reason: 'certificate_chain must be leaf-first and issuer-ordered')
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

      def uri_sans(cert)
        san_ext = cert.extensions.find { |extension| extension.oid == 'subjectAltName' }
        return [] unless san_ext

        subject_alt_name_entries(san_ext).filter_map do |entry|
          entry.value if entry.tag_class == :CONTEXT_SPECIFIC && entry.tag == URI_SAN_TAG
        end
      end

      def subject_alt_name_entries(extension)
        extension_asn1 = OpenSSL::ASN1.decode(extension.to_der)
        extn_value = extension_asn1.value.find { |entry| entry.is_a?(OpenSSL::ASN1::OctetString) }
        return [] unless extn_value

        general_names = OpenSSL::ASN1.decode(extn_value.value)
        return [] unless general_names.value.is_a?(Array)

        general_names.value
      rescue OpenSSL::ASN1::ASN1Error
        []
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
