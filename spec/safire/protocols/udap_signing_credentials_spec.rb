require 'spec_helper'
require_relative '../../support/udap_certificate_helpers'

RSpec.describe Safire::Protocols::UdapSigningCredentials do
  include UdapCertificateHelpers

  let(:now) { Time.at(1_700_000_000) }
  let(:clock) { class_double(Time, now:) }
  let(:uri_san) { 'https://client.example.com/app' }
  let(:rsa_key) { OpenSSL::PKey::RSA.generate(2048) }
  let(:leaf_cert) { build_valid_certificate(key: rsa_key) }
  let(:base_params) do
    {
      private_key: rsa_key,
      certificate_chain: [leaf_cert],
      supported_algorithms: %w[RS256 RS384 ES256 ES384],
      clock:
    }
  end

  def build_credentials(overrides = {})
    described_class.new(**base_params, **overrides)
  end

  def build_valid_certificate(key:, uri_san: self.uri_san, **kwargs)
    build_udap_certificate(key:, uri_san:, not_before: now - 60, not_after: now + 3600, **kwargs)
  end

  def build_issued_chain
    issuer_key = OpenSSL::PKey::RSA.generate(2048)
    issuer = build_valid_certificate(key: issuer_key, uri_san: 'https://issuer.example.com',
                                     subject: '/CN=UDAP Issuer', serial: 2)
    leaf = build_valid_certificate(key: rsa_key, issuer_cert: issuer, issuer_key:, serial: 3)
    [leaf, issuer]
  end

  def config_error_attribute(**overrides)
    capture_error(Safire::Errors::ConfigurationError) { build_credentials(overrides) }&.invalid_attribute
  end

  describe 'algorithm selection' do
    it 'prefers RS256 for RSA keys when advertised' do
      expect(build_credentials.algorithm).to eq('RS256')
    end

    it 'selects RS384 for RSA keys when RS256 is not advertised' do
      expect(build_credentials(supported_algorithms: %w[ES256 RS384]).algorithm).to eq('RS384')
    end

    it 'selects ES256 for EC P-256 keys' do
      ec_key = OpenSSL::PKey::EC.generate('prime256v1')
      credentials = build_credentials(private_key: ec_key, certificate_chain: [build_valid_certificate(key: ec_key)])

      expect(credentials.algorithm).to eq('ES256')
    end

    it 'selects ES384 for EC P-384 keys' do
      ec_key = OpenSSL::PKey::EC.generate('secp384r1')
      credentials = build_credentials(private_key: ec_key, certificate_chain: [build_valid_certificate(key: ec_key)])

      expect(credentials.algorithm).to eq('ES384')
    end

    it 'rejects EC curves without a supported algorithm' do
      ec_key = OpenSSL::PKey::EC.generate('secp521r1')

      expect(config_error_attribute(private_key: ec_key, certificate_chain: [build_valid_certificate(key: ec_key)]))
        .to eq(:algorithm)
    end

    it 'accepts an explicit compatible advertised algorithm' do
      expect(build_credentials(algorithm: 'RS384').algorithm).to eq('RS384')
    end

    it 'rejects an explicit algorithm incompatible with the key' do
      expect(config_error_attribute(algorithm: 'ES256')).to eq(:algorithm)
    end

    it 'rejects an explicit compatible algorithm the server did not advertise' do
      expect(config_error_attribute(algorithm: 'RS384', supported_algorithms: ['RS256'])).to eq(:algorithm)
    end

    it 'rejects an explicit algorithm Safire does not support' do
      expect(config_error_attribute(algorithm: 'RS512', supported_algorithms: %w[RS256 RS512])).to eq(:algorithm)
    end

    it 'rejects an advertised list with no key-compatible algorithm' do
      expect(config_error_attribute(supported_algorithms: %w[ES256 ES384])).to eq(:supported_algorithms)
    end

    it 'rejects an empty advertised list' do
      expect(config_error_attribute(supported_algorithms: [])).to eq(:supported_algorithms)
    end

    it 'rejects non-string advertised entries' do
      expect(config_error_attribute(supported_algorithms: [:RS256])).to eq(:supported_algorithms)
    end
  end

  describe 'private key parsing' do
    it 'accepts a PEM private key string' do
      expect(build_credentials(private_key: rsa_key.to_pem).algorithm).to eq('RS256')
    end

    it 'rejects malformed PEM' do
      expect(config_error_attribute(private_key: 'not a pem')).to eq(:private_key)
    end

    it 'rejects a public-only key' do
      expect(config_error_attribute(private_key: rsa_key.public_to_pem)).to eq(:private_key)
    end

    it 'rejects unsupported key objects' do
      expect(config_error_attribute(private_key: 123)).to eq(:private_key)
    end

    it 'does not include key material in the error message' do
      error = capture_error(Safire::Errors::ConfigurationError) do
        build_credentials(private_key: rsa_key.public_to_pem)
      end

      expect(error.message).not_to include('BEGIN')
    end
  end

  describe 'certificate chain parsing' do
    it 'accepts PEM certificate strings' do
      expect(build_credentials(certificate_chain: [leaf_cert.to_pem]).leaf_certificate.to_der).to eq(leaf_cert.to_der)
    end

    it 'rejects an empty chain' do
      expect(config_error_attribute(certificate_chain: [])).to eq(:certificate_chain)
    end

    it 'rejects a non-array chain' do
      expect(config_error_attribute(certificate_chain: leaf_cert)).to eq(:certificate_chain)
    end

    it 'rejects unsupported chain entry types' do
      expect(config_error_attribute(certificate_chain: [leaf_cert.to_der.bytes])).to eq(:certificate_chain)
    end

    it 'rejects malformed certificate PEM' do
      expect { build_credentials(certificate_chain: ['not a cert']) }
        .to raise_error(Safire::Errors::CertificateError, /malformed/)
    end

    it 'rejects a chain that is not leaf-first and issuer-ordered' do
      expect { build_credentials(certificate_chain: build_issued_chain.reverse) }
        .to raise_error(Safire::Errors::CertificateError, /issuer-ordered/)
    end

    it 'rejects a private key that does not match the leaf certificate' do
      expect { build_credentials(private_key: OpenSSL::PKey::RSA.generate(2048)) }
        .to raise_error(Safire::Errors::CertificateError, /private key/)
    end

    it 'does not require a URI SAN on the leaf certificate' do
      expect(build_credentials(certificate_chain: [build_valid_certificate(key: rsa_key, uri_san: nil)]).algorithm)
        .to eq('RS256')
    end
  end

  describe 'certificate validity at construction' do
    it 'rejects an expired certificate' do
      expired = build_udap_certificate(key: rsa_key, uri_san:, not_before: now - 3600, not_after: now - 1)

      expect { build_credentials(certificate_chain: [expired]) }
        .to raise_error(Safire::Errors::CertificateError, /expired/)
    end

    it 'rejects a certificate that is not yet valid' do
      future = build_udap_certificate(key: rsa_key, uri_san:, not_before: now + 1, not_after: now + 3600)

      expect { build_credentials(certificate_chain: [future]) }
        .to raise_error(Safire::Errors::CertificateError, /not yet valid/)
    end

    it 'rejects a clock that does not respond to #now' do
      expect(config_error_attribute(clock: Object.new)).to eq(:clock)
    end

    it 'rejects a clock whose #now is not a Time' do
      expect(config_error_attribute(clock: class_double(Time, now: 1_700_000_000))).to eq(:clock)
    end
  end

  describe '#validate_certificate_times!' do
    let(:credentials) { build_credentials }

    it 'accepts times inside the validity period, including the boundaries' do
      expect do
        credentials.validate_certificate_times!(leaf_cert.not_before)
        credentials.validate_certificate_times!(leaf_cert.not_after)
      end.not_to raise_error
    end

    it 'rejects a time after not_after' do
      expect { credentials.validate_certificate_times!(leaf_cert.not_after + 1) }
        .to raise_error(Safire::Errors::CertificateError, /expired/)
    end

    it 'rejects a time before not_before' do
      expect { credentials.validate_certificate_times!(leaf_cert.not_before - 1) }
        .to raise_error(Safire::Errors::CertificateError, /not yet valid/)
    end
  end

  describe '#x5c and #jose_header' do
    it 'encodes the chain leaf first as strict Base64 DER' do
      chain = build_issued_chain
      credentials = build_credentials(certificate_chain: chain)

      expect(credentials.x5c).to eq(chain.map { |cert| Base64.strict_encode64(cert.to_der) })
      expect(credentials.x5c).to all(satisfy { |entry| !entry.include?("\n") && !entry.include?('BEGIN') })
    end

    it 'contains only alg and x5c' do
      credentials = build_credentials

      expect(credentials.jose_header).to eq('alg' => 'RS256', 'x5c' => credentials.x5c)
    end
  end

  describe '#leaf_uri_san?' do
    it 'matches a URI SAN exactly' do
      credentials = build_credentials

      expect(credentials.leaf_uri_san?(uri_san)).to be(true)
      expect(credentials.leaf_uri_san?("#{uri_san}/")).to be(false)
    end
  end

  describe '#sign' do
    it 'produces a compact JWS verifiable with the leaf public key and carrying the UDAP header' do
      credentials = build_credentials(algorithm: 'RS384')
      token = credentials.sign('iss' => uri_san)

      payload, header = JWT.decode(token, leaf_cert.public_key, true, algorithms: ['RS384'])

      expect(payload).to eq('iss' => uri_san)
      expect(header).to eq('alg' => 'RS384', 'x5c' => credentials.x5c)
    end

    it 'signs with EC keys' do
      ec_key = OpenSSL::PKey::EC.generate('prime256v1')
      cert = build_valid_certificate(key: ec_key)
      token = build_credentials(private_key: ec_key, certificate_chain: [cert]).sign('sub' => 'x')

      expect(JWT.decode(token, cert.public_key, true, algorithms: ['ES256']).first).to eq('sub' => 'x')
    end
  end

  describe 'immutability' do
    it 'is frozen with frozen chain data' do
      credentials = build_credentials

      expect(credentials).to be_frozen
      expect(credentials.x5c).to be_frozen.and(all(be_frozen))
      expect(credentials.leaf_certificate).to be_frozen
    end

    it 'snapshots the supplied certificate chain' do
      chain = [leaf_cert]
      credentials = build_credentials(certificate_chain: chain)
      chain.clear

      expect(credentials.x5c.size).to eq(1)
    end
  end
end
