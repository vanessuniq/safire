# frozen_string_literal: true

require 'openssl'
require 'safire'

# Shared PEM collection parsing for UDAP demo configuration models.
module UdapPemParsing
  CERTIFICATE_PATTERN = /-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/m
  CRL_PATTERN = /-----BEGIN X509 CRL-----.*?-----END X509 CRL-----/m

  private

  def parse_pem_collection(env, env_key:, pattern:, parser:)
    raw = env.fetch(env_key, nil).to_s.strip
    return [].freeze if raw.empty?

    pem_blocks = raw.scan(pattern)
    raise_certificate_error(env_key, 'no PEM blocks found') if pem_blocks.empty?

    pem_blocks.map { |pem| parser.new(pem) }.freeze
  rescue OpenSSL::X509::CertificateError, OpenSSL::X509::CRLError => e
    raise_certificate_error(env_key, e.message)
  end

  def raise_certificate_error(env_key, reason)
    raise Safire::Errors::CertificateError.new(reason: "#{env_key} is invalid: #{reason}")
  end
end
