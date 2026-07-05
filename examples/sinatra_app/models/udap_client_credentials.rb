# frozen_string_literal: true

require 'openssl'
require_relative 'udap_pem_parsing'

# Client signing credentials for UDAP Dynamic Client Registration in the demo app.
class UdapClientCredentials
  include UdapPemParsing

  PRIVATE_KEY_ENV = 'UDAP_CLIENT_PRIVATE_KEY_PEM'
  CERTIFICATE_CHAIN_ENV = 'UDAP_CLIENT_CERTIFICATE_CHAIN_PEM'
  SIGNING_ALGORITHM_ENV = 'UDAP_REGISTRATION_SIGNING_ALGORITHM'
  SUPPORTED_ALGORITHMS = %w[RS256 RS384 ES256 ES384].freeze
  private_constant :PRIVATE_KEY_ENV, :CERTIFICATE_CHAIN_ENV, :SIGNING_ALGORITHM_ENV, :SUPPORTED_ALGORITHMS

  def initialize(env = ENV)
    @env = env
  end

  def configured?
    env_value?(PRIVATE_KEY_ENV) && env_value?(CERTIFICATE_CHAIN_ENV)
  end

  def client_config_kwargs
    @client_config_kwargs ||= begin
      validate_required_credentials!
      {
        private_key: private_key,
        certificate_chain: certificate_chain
      }.tap do |kwargs|
        kwargs[:jwt_algorithm] = signing_algorithm if signing_algorithm
      end.freeze
    end
  end

  private

  attr_reader :env

  def validate_required_credentials!
    missing = []
    missing << PRIVATE_KEY_ENV.to_sym unless env_value?(PRIVATE_KEY_ENV)
    missing << CERTIFICATE_CHAIN_ENV.to_sym unless env_value?(CERTIFICATE_CHAIN_ENV)
    return if missing.empty?

    raise Safire::Errors::ConfigurationError.new(missing_attributes: missing)
  end

  def private_key
    @private_key ||= begin
      key = OpenSSL::PKey.read(env.fetch(PRIVATE_KEY_ENV).to_s)
      raise_invalid_private_key! unless key.private?

      key
    end
  rescue OpenSSL::PKey::PKeyError
    raise_invalid_private_key!
  end

  def raise_invalid_private_key!
    raise Safire::Errors::ConfigurationError.new(
      invalid_attribute: PRIVATE_KEY_ENV.to_sym,
      invalid_value: 'configured value',
      valid_values: ['PEM private key']
    )
  end

  def certificate_chain
    @certificate_chain ||= parse_pem_collection(
      env,
      env_key: CERTIFICATE_CHAIN_ENV,
      pattern: UdapPemParsing::CERTIFICATE_PATTERN,
      parser: OpenSSL::X509::Certificate
    )
  end

  def signing_algorithm
    return @signing_algorithm if defined?(@signing_algorithm)

    value = env.fetch(SIGNING_ALGORITHM_ENV, nil).to_s.strip
    return @signing_algorithm = nil if value.empty?
    return @signing_algorithm = value.freeze if SUPPORTED_ALGORITHMS.include?(value)

    raise Safire::Errors::ConfigurationError.new(
      invalid_attribute: SIGNING_ALGORITHM_ENV.to_sym,
      invalid_value: value,
      valid_values: SUPPORTED_ALGORITHMS
    )
  end

  def env_value?(key)
    env.fetch(key, nil).to_s.strip.present?
  end
end
