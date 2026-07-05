# frozen_string_literal: true

require_relative 'udap_pem_parsing'

# Server trust policy for UDAP signed_metadata validation in the demo app.
class UdapTrustPolicy
  include UdapPemParsing

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
    return if verify_chain?

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
      env,
      env_key: 'UDAP_TRUST_ANCHORS_PEM',
      pattern: UdapPemParsing::CERTIFICATE_PATTERN,
      parser: OpenSSL::X509::Certificate
    )
  end

  def crls
    @crls ||= parse_pem_collection(
      env,
      env_key: 'UDAP_CRLS_PEM',
      pattern: UdapPemParsing::CRL_PATTERN,
      parser: OpenSSL::X509::CRL
    )
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
end
