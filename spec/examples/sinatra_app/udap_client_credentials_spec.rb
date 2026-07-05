require 'spec_helper'
require 'openssl'

require_relative '../../support/udap_certificate_helpers'
require_relative '../../../examples/sinatra_app/models/udap_client_credentials'

RSpec.describe UdapClientCredentials do
  include UdapCertificateHelpers

  let(:private_key) { OpenSSL::PKey::RSA.generate(2048) }
  let(:issuer_key) { OpenSSL::PKey::RSA.generate(2048) }
  let(:issuer_cert) do
    build_udap_certificate(
      key: issuer_key.public_key,
      uri_san: 'https://issuer.example.com',
      subject: '/CN=UDAP Issuer',
      issuer_key: issuer_key
    )
  end
  let(:leaf_cert) do
    build_udap_certificate(
      key: private_key.public_key,
      uri_san: 'https://client.example.com',
      issuer_cert:,
      issuer_key:,
      serial: 2
    )
  end
  let(:chain_pem) { "#{leaf_cert.to_pem}\n#{issuer_cert.to_pem}" }
  let(:env) do
    {
      'UDAP_CLIENT_PRIVATE_KEY_PEM' => private_key.to_pem,
      'UDAP_CLIENT_CERTIFICATE_CHAIN_PEM' => chain_pem
    }
  end

  it 'is configured only when both signing key and certificate chain are present' do
    expect(described_class.new({})).not_to be_configured
    expect(described_class.new('UDAP_CLIENT_PRIVATE_KEY_PEM' => private_key.to_pem)).not_to be_configured
    expect(described_class.new(env)).to be_configured
  end

  it 'returns Safire client configuration kwargs with parsed signing material' do
    kwargs = described_class.new(env).client_config_kwargs

    expect(kwargs[:private_key]).to be_a(OpenSSL::PKey::RSA)
    expect(kwargs[:certificate_chain].map(&:subject)).to eq([leaf_cert.subject, issuer_cert.subject])
    expect(kwargs[:certificate_chain]).to be_frozen
    expect(kwargs).not_to have_key(:jwt_algorithm)
  end

  it 'includes an explicit registration signing algorithm when configured' do
    credentials = described_class.new(env.merge('UDAP_REGISTRATION_SIGNING_ALGORITHM' => 'RS384'))

    expect(credentials.client_config_kwargs[:jwt_algorithm]).to eq('RS384')
  end

  it 'raises ConfigurationError when usable credentials are requested but key material is missing' do
    credentials = described_class.new('UDAP_CLIENT_CERTIFICATE_CHAIN_PEM' => leaf_cert.to_pem)

    expect { credentials.client_config_kwargs }
      .to raise_error(Safire::Errors::ConfigurationError, /UDAP_CLIENT_PRIVATE_KEY_PEM/)
  end

  it 'raises ConfigurationError when usable credentials are requested but the chain is missing' do
    credentials = described_class.new('UDAP_CLIENT_PRIVATE_KEY_PEM' => private_key.to_pem)

    expect { credentials.client_config_kwargs }
      .to raise_error(Safire::Errors::ConfigurationError, /UDAP_CLIENT_CERTIFICATE_CHAIN_PEM/)
  end

  it 'raises ConfigurationError for malformed private key PEM without leaking the configured value' do
    credentials = described_class.new(env.merge('UDAP_CLIENT_PRIVATE_KEY_PEM' => 'not a key'))

    expect { credentials.client_config_kwargs }
      .to raise_error(Safire::Errors::ConfigurationError) { |error|
        expect(error.message).to include('UDAP_CLIENT_PRIVATE_KEY_PEM')
        expect(error.message).not_to include('not a key')
      }
  end

  it 'raises ConfigurationError when the configured key is not a private key' do
    credentials = described_class.new(env.merge('UDAP_CLIENT_PRIVATE_KEY_PEM' => private_key.public_key.to_pem))

    expect { credentials.client_config_kwargs }
      .to raise_error(Safire::Errors::ConfigurationError, /PEM private key/)
  end

  it 'raises CertificateError for malformed certificate PEM without leaking the configured value' do
    credentials = described_class.new(env.merge('UDAP_CLIENT_CERTIFICATE_CHAIN_PEM' => <<~PEM))
      -----BEGIN CERTIFICATE-----
      not a certificate
      -----END CERTIFICATE-----
    PEM

    expect { credentials.client_config_kwargs }
      .to raise_error(Safire::Errors::CertificateError) { |error|
        expect(error.message).to include('UDAP_CLIENT_CERTIFICATE_CHAIN_PEM')
        expect(error.message).not_to include('not a certificate')
      }
  end

  it 'raises ConfigurationError for unknown signing algorithms' do
    credentials = described_class.new(env.merge('UDAP_REGISTRATION_SIGNING_ALGORITHM' => 'HS256'))

    expect { credentials.client_config_kwargs }
      .to raise_error(Safire::Errors::ConfigurationError, /UDAP_REGISTRATION_SIGNING_ALGORITHM/)
  end

  it 'memoizes parsed credentials' do
    credentials = described_class.new(env)

    expect(credentials.client_config_kwargs[:private_key]).to equal(credentials.client_config_kwargs[:private_key])
  end
end
