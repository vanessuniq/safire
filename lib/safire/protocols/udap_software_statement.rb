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
      DEFAULT_JTI_GENERATOR = -> { SecureRandom.uuid }

      private_constant :LIFETIME_SECONDS, :DEFAULT_JTI_GENERATOR

      # @param metadata [Safire::Protocols::UdapRegistrationMetadata] validated registration metadata
      # @param client_uri [String] absolute client URI used as +iss+ and +sub+
      # @param registration_endpoint [String] discovered registration endpoint used exactly as +aud+
      # @param private_key [OpenSSL::PKey::RSA, OpenSSL::PKey::EC, String] signing private key or PEM
      # @param certificate_chain [Array<String, OpenSSL::X509::Certificate>] leaf-first,
      #   issuer-ordered client certificate chain
      # @param supported_algorithms [Array<String>] algorithms advertised by UDAP discovery
      # @param algorithm [String, nil] optional explicit signing algorithm
      # @param clock [#now] time source returning +Time+ for deterministic NumericDate claims
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
        @credentials = UdapSigningCredentials.new(
          private_key:, certificate_chain:, supported_algorithms:, algorithm:, clock: @clock
        )

        validate_leaf_uri_san!
        freeze
      end

      # Returns the signed software statement as a compact JWS string.
      #
      # @return [String]
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
        @metadata.to_h.merge(
          'iss' => @client_uri,
          'sub' => @client_uri,
          'aud' => @registration_endpoint,
          'iat' => now,
          'exp' => now + LIFETIME_SECONDS,
          'jti' => generate_jti
        )
      end

      def validate_metadata(metadata)
        return metadata if metadata.is_a?(UdapRegistrationMetadata)

        raise Errors::ValidationError.new(
          attribute: :metadata,
          reason: 'must be a Safire::Protocols::UdapRegistrationMetadata'
        )
      end

      def validate_client_uri(value)
        return immutable_string(value) if absolute_client_uri?(value)

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
        return immutable_string(value) if strict_https_uri?(value)
        return immutable_string(value) if allow_insecure_localhost && localhost_http_uri?(value)

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

      def validate_leaf_uri_san!
        return if @credentials.leaf_uri_san?(@client_uri)

        raise Errors::CertificateError.new(
          reason: 'client_uri does not match any URI SAN in the leaf certificate',
          subject: @credentials.leaf_certificate.subject.to_s
        )
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

      def immutable_string(value)
        value.dup.freeze
      end
    end
  end
end
