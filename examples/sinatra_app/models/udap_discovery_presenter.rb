# frozen_string_literal: true

require 'openssl'

# Presentation model for the UDAP discovery demo view.
class UdapDiscoveryPresenter
  PROFILE_CHECKS = [
    ['Dynamic Client Registration profile', :dynamic_registration_profile?],
    ['JWT Client Authentication profile', :jwt_client_auth_profile?],
    ['Client Authorization profile', :client_authorization_profile?],
    ['Tiered OAuth profile', :tiered_oauth_profile?]
  ].freeze

  CAPABILITY_CHECKS = [
    ['Dynamic Client Registration capability', :supports_dynamic_registration?],
    ['JWT Client Authentication capability', :supports_jwt_client_auth?],
    ['Client Credentials capability', :supports_client_authorization?],
    ['Authorization Code grant', :supports_authorization_code?],
    ['Refresh Token grant', :supports_refresh_token?],
    ['Tiered OAuth capability', :supports_tiered_oauth?],
    ['Signed Metadata', :supports_signed_metadata?]
  ].freeze

  FIELD_LABELS = {
    udap_versions_supported: 'UDAP Versions Supported',
    udap_profiles_supported: 'UDAP Profiles Supported',
    udap_authorization_extensions_supported: 'Authorization Extensions Supported',
    udap_authorization_extensions_required: 'Authorization Extensions Required',
    udap_certifications_supported: 'Certifications Supported',
    udap_certifications_required: 'Certifications Required',
    grant_types_supported: 'Grant Types Supported',
    scopes_supported: 'Scopes Supported',
    token_endpoint: 'Token Endpoint',
    token_endpoint_auth_methods_supported: 'Token Endpoint Auth Methods',
    token_endpoint_auth_signing_alg_values_supported: 'Token Endpoint Auth Signing Algorithms',
    registration_endpoint: 'Registration Endpoint',
    registration_endpoint_jwt_signing_alg_values_supported: 'Registration JWT Signing Algorithms',
    authorization_endpoint: 'Authorization Endpoint',
    signed_metadata: 'Signed Metadata'
  }.freeze

  attr_reader :community, :metadata, :metadata_valid, :trust_policy

  def initialize(metadata, metadata_valid:, trust_policy:, community: nil)
    @metadata = metadata
    @metadata_valid = metadata_valid
    @trust_policy = trust_policy
    @community = community
  end

  def metadata_fields
    Safire::Protocols::UdapMetadata::ATTRIBUTES.map do |key|
      { key: key, label: FIELD_LABELS.fetch(key, key.to_s.humanize), value: metadata.public_send(key) }
    end
  end

  def profile_checks
    PROFILE_CHECKS.map { |label, method_name| check_row(label, method_name) }
  end

  def capability_checks
    CAPABILITY_CHECKS.map { |label, method_name| check_row(label, method_name) }
  end

  def trust_warning?
    trust_policy.development_mode?
  end

  def trust_warning_reason
    case trust_policy.chain_verification_disabled_reason
    when :explicit_override
      'because UDAP_VERIFY_CHAIN explicitly disables them for this demo environment'
    else
      'because complete UDAP trust anchors and CRLs are not configured for this demo environment'
    end
  end

  def structural_status
    metadata_valid ? 'Conformant' : 'Non-conformant'
  end

  def signed_metadata_status
    return 'Validated with chain and revocation checks' if trust_policy.verify_chain?

    'Validated without chain verification'
  end

  def status_text(value)
    value ? 'Yes' : 'No'
  end

  def badge_class(value)
    value ? 'badge-added' : 'badge-info'
  end

  # Trust policy for the UDAP discovery demo.
  class TrustPolicy
    CERTIFICATE_PATTERN = /-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/m
    CRL_PATTERN = /-----BEGIN X509 CRL-----.*?-----END X509 CRL-----/m
    TRUTHY_VALUES = %w[1 true yes on].freeze
    FALSEY_VALUES = %w[0 false no off].freeze
    BOOLEAN_VALUES = (TRUTHY_VALUES + FALSEY_VALUES).freeze

    def initialize(env = ENV)
      @env = env
    end

    def server_metadata_kwargs
      {
        trusted_anchors: trusted_anchors,
        crls: crls,
        verify_chain: verify_chain?
      }
    end

    def development_mode?
      !verify_chain?
    end

    def chain_verification_disabled_reason
      return nil if verify_chain?

      explicit_verify_chain == false ? :explicit_override : :missing_trust_material
    end

    def verify_chain?
      explicit = explicit_verify_chain
      return explicit unless explicit.nil?

      trust_material_configured?
    end

    def trust_material_configured?
      trusted_anchors.any? && crls.any?
    end

    private

    attr_reader :env

    def trusted_anchors
      @trusted_anchors ||= parse_pem_collection(
        'UDAP_TRUST_ANCHORS_PEM',
        CERTIFICATE_PATTERN,
        OpenSSL::X509::Certificate
      )
    end

    def crls
      @crls ||= parse_pem_collection('UDAP_CRLS_PEM', CRL_PATTERN, OpenSSL::X509::CRL)
    end

    def explicit_verify_chain
      return @explicit_verify_chain if defined?(@explicit_verify_chain)

      value = env.fetch('UDAP_VERIFY_CHAIN', nil).to_s.strip
      return @explicit_verify_chain = nil if value.empty?

      normalized_value = value.downcase
      return @explicit_verify_chain = true if TRUTHY_VALUES.include?(normalized_value)
      return @explicit_verify_chain = false if FALSEY_VALUES.include?(normalized_value)

      raise Safire::Errors::ConfigurationError.new(
        invalid_attribute: :UDAP_VERIFY_CHAIN,
        invalid_value: value,
        valid_values: BOOLEAN_VALUES
      )
    end

    def parse_pem_collection(env_key, pattern, parser)
      raw = env.fetch(env_key, nil).to_s.strip
      return [] if raw.empty?

      pem_blocks = raw.scan(pattern)
      raise_certificate_error(env_key, 'no PEM blocks found') if pem_blocks.empty?

      pem_blocks.map { |pem| parser.new(pem) }
    rescue OpenSSL::X509::CertificateError, OpenSSL::X509::CRLError => e
      raise_certificate_error(env_key, e.message)
    end

    def raise_certificate_error(env_key, reason)
      raise Safire::Errors::CertificateError.new(reason: "#{env_key} is invalid: #{reason}")
    end
  end

  private

  def check_row(label, method_name)
    { label: label, result: metadata.public_send(method_name) }
  end
end
