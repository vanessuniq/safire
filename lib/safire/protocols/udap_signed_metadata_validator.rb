require 'jwt'
require 'openssl'
require 'base64'

module Safire
  module Protocols
    # Validates the +signed_metadata+ JWT included in a UDAP server discovery response
    # per {https://hl7.org/fhir/us/udap-security/discovery.html#signed-metadata-elements
    # UDAP Security STU2 §Signed Metadata Elements}.
    #
    # This is an internal class used by {Safire::Protocols::Udap} and
    # {Safire::Protocols::UdapMetadata}. Do not instantiate it directly.
    #
    # @api private
    class UdapSignedMetadataValidator
      ALLOWED_ALGORITHMS    = %w[RS256].freeze
      MAX_VALIDITY_SECONDS  = 365 * 24 * 3600
      REQUIRED_ENDPOINT_CLAIMS = %w[token_endpoint registration_endpoint].freeze

      # @param signed_metadata_jwt [String] the compact-JWS value from the discovery response
      # @param unsigned_metadata [Hash] the raw (unsigned) discovery response body
      def initialize(signed_metadata_jwt, unsigned_metadata)
        @jwt      = signed_metadata_jwt
        @unsigned = unsigned_metadata
      end

      # Validates the signed metadata JWT and returns the signed endpoint claims to merge
      # over the unsigned discovery values.
      #
      # Each validation failure is logged as a warning without raising, except for
      # malformed certificate DER in +x5c+, which raises {Safire::Errors::CertificateError}
      # because the input is unparseable rather than merely non-conformant.
      #
      # @param base_url [String] the server's base URL; must equal the +iss+ claim
      # @param trusted_anchors [Array<OpenSSL::X509::Certificate>] trust anchors for chain verification
      # @param verify_chain [Boolean] when +false+, skips X.509 chain validation (dev/test only)
      # @return [Hash, nil] signed endpoint claims to merge, or +nil+ if validation fails
      # @raise [Safire::Errors::CertificateError] if an +x5c+ certificate cannot be parsed
      def signed_endpoint_claims(base_url:, trusted_anchors: [], verify_chain: true)
        decoded = decode_jwt
        return unless decoded

        payload, header = decoded
        return unless alg_valid?(header)
        return unless x5c_present?(header)

        leaf_cert = parse_leaf_cert(header['x5c'].first)
        return unless signature_valid?(leaf_cert)
        return unless cert_trusted?(header['x5c'].drop(1), leaf_cert, trusted_anchors, verify_chain)
        return unless claims_valid?(payload, base_url, leaf_cert)

        extract_endpoint_claims(payload)
      end

      # Returns +true+ when {#signed_endpoint_claims} succeeds.
      #
      # @param base_url [String] the server's base URL
      # @param trusted_anchors [Array<OpenSSL::X509::Certificate>] trust anchors for chain verification
      # @param verify_chain [Boolean] when +false+, skips X.509 chain validation
      # @return [Boolean]
      def valid?(base_url:, trusted_anchors: [], verify_chain: true)
        signed_endpoint_claims(base_url:, trusted_anchors:, verify_chain:).present?
      end

      private

      def decode_jwt
        JWT.decode(@jwt, nil, false)
      rescue JWT::DecodeError => e
        log_failure("could not decode signed_metadata JWT: #{e.message}")
        nil
      end

      def alg_valid?(header)
        return true if ALLOWED_ALGORITHMS.include?(header['alg'])

        log_failure("alg '#{header['alg']}' is not permitted; expected RS256 (UDAP Security STU2)")
        false
      end

      def x5c_present?(header)
        return true if header['x5c'].is_a?(Array) && header['x5c'].any?

        log_failure('x5c header is required and must be a non-empty array of base64-encoded certificates')
        false
      end

      def parse_leaf_cert(x5c_value)
        parse_x5c_cert(x5c_value, 'leaf')
      end

      def signature_valid?(leaf_cert)
        JWT.decode(@jwt, leaf_cert.public_key, true, algorithms: ALLOWED_ALGORITHMS, verify_expiration: false)
        true
      rescue JWT::DecodeError => e
        log_failure("signature verification failed: #{e.message}")
        false
      end

      def cert_trusted?(intermediate_ders, leaf_cert, trusted_anchors, verify_chain)
        return true unless verify_chain

        chain_valid?(intermediate_ders, leaf_cert, trusted_anchors)
      end

      def chain_valid?(intermediate_ders, leaf_cert, trusted_anchors)
        intermediates = parse_intermediate_certs(intermediate_ders)
        store = OpenSSL::X509::Store.new
        trusted_anchors.each { |anchor| store.add_cert(anchor) }
        ctx = OpenSSL::X509::StoreContext.new(store, leaf_cert, intermediates)
        return true if ctx.verify

        log_failure("certificate chain validation failed: #{ctx.error_string}")
        false
      rescue OpenSSL::X509::StoreError => e
        log_failure("certificate chain error: #{e.message}")
        false
      end

      def parse_intermediate_certs(ders)
        ders.map { |der_b64| parse_x5c_cert(der_b64, 'intermediate') }
      end

      def parse_x5c_cert(der_b64, label)
        OpenSSL::X509::Certificate.new(Base64.strict_decode64(der_b64))
      rescue ArgumentError, OpenSSL::X509::CertificateError => e
        raise Errors::CertificateError.new(reason: "malformed x5c #{label} certificate: #{e.message}")
      end

      def claims_valid?(payload, base_url, leaf_cert)
        # Intentionally runs all checks to surface every validation failure at once
        [
          iss_san_valid?(payload['iss'], leaf_cert),
          iss_base_url_valid?(payload['iss'], base_url),
          sub_equals_iss?(payload['sub'], payload['iss']),
          exp_valid?(payload['exp'], payload['iat']),
          jti_present?(payload['jti']),
          endpoint_claims_present?(payload)
        ].all?
      end

      def iss_san_valid?(iss, cert)
        if iss.blank?
          log_failure('iss claim is missing')
          return false
        end

        sans = uri_sans(cert)
        return true if sans.include?(iss)

        log_failure("iss '#{iss}' does not match any uriName SAN in the leaf certificate")
        false
      end

      def uri_sans(cert)
        san_ext = cert.extensions.find { |e| e.oid == 'subjectAltName' }
        return [] unless san_ext

        san_ext.value.split(',').map { |san| san.strip.delete_prefix('URI:') }
      end

      def iss_base_url_valid?(iss, base_url)
        return true if iss == base_url

        log_failure("iss '#{iss}' does not match the server base URL '#{base_url}'")
        false
      end

      def sub_equals_iss?(sub, iss)
        return true if sub == iss

        log_failure("sub must equal iss (sub='#{sub}', iss='#{iss}')")
        false
      end

      def exp_valid?(exp, iat)
        if exp.nil?
          log_failure('exp claim is missing')
          return false
        end

        now = Time.now.to_i
        if exp <= now
          log_failure("JWT has expired (exp=#{exp})")
          return false
        end

        if iat && exp > iat + MAX_VALIDITY_SECONDS
          log_failure('exp exceeds maximum validity of 1 year from iat')
          return false
        end

        true
      end

      def jti_present?(jti)
        return true if jti.present?

        log_failure('jti claim is missing or blank')
        false
      end

      def endpoint_claims_present?(payload)
        valid = REQUIRED_ENDPOINT_CLAIMS.map do |claim|
          next true if payload[claim].present?

          log_failure("required signed endpoint claim '#{claim}' is missing")
          false
        end.all?

        if @unsigned['authorization_endpoint'].present? && payload['authorization_endpoint'].blank?
          log_failure(
            "'authorization_endpoint' must be present in signed_metadata when it appears in unsigned metadata"
          )
          valid = false
        end

        valid
      end

      def extract_endpoint_claims(payload)
        payload.slice('token_endpoint', 'registration_endpoint', 'authorization_endpoint').compact
      end

      def log_failure(message)
        Safire.logger.warn("[UDAP] signed_metadata validation: #{message}")
      end
    end
  end
end
