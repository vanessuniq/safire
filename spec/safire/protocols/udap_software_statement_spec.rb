require 'spec_helper'
require_relative '../../support/udap_certificate_helpers'

RSpec.describe Safire::Protocols::UdapSoftwareStatement do
  include UdapCertificateHelpers

  let(:now) { Time.at(1_700_000_000) }
  let(:clock) { class_double(Time, now:) }
  let(:jti_generator) { -> { 'jti-123' } }
  let(:client_uri) { 'https://client.example.com/app' }
  let(:registration_endpoint) { 'https://as.example.com/register' }
  let(:rsa_key) { OpenSSL::PKey::RSA.generate(2048) }
  let(:leaf_cert) { build_valid_certificate(key: rsa_key, uri_san: client_uri) }
  let(:metadata_input) do
    {
      client_name: 'Example Backend Service',
      contacts: ['mailto:security@example.com'],
      grant_types: ['client_credentials'],
      scope: 'system/Patient.rs'
    }
  end
  let(:metadata) { Safire::Protocols::UdapRegistrationMetadata.new(metadata_input) }
  let(:base_params) do
    {
      metadata:,
      client_uri:,
      registration_endpoint:,
      private_key: rsa_key,
      certificate_chain: [leaf_cert],
      supported_algorithms: %w[RS256 RS384 ES256],
      clock:,
      jti_generator:
    }
  end

  def build_statement(overrides = {})
    described_class.new(**base_params, **overrides)
  end

  def build_valid_certificate(**kwargs)
    build_udap_certificate(not_before: now - 60, not_after: now + 3600, **kwargs)
  end

  def decode_statement(statement = build_statement, cert: leaf_cert, algorithm: 'RS256')
    JWT.decode(statement.to_jwt, cert.public_key, true, algorithms: [algorithm], verify_expiration: false)
  end

  describe '#to_jwt' do
    it 'builds the minimal JOSE header with a leaf-first x5c chain' do
      intermediate = build_valid_certificate(key: rsa_key, uri_san: 'https://issuer.example.com', serial: 2)
      statement = build_statement(certificate_chain: [leaf_cert, intermediate])
      _payload, header = decode_statement(statement)

      expect(header).to eq(
        'alg' => 'RS256',
        'x5c' => [leaf_cert, intermediate].map { |cert| Base64.strict_encode64(cert.to_der) }
      )
    end

    it 'builds a complete client-credentials software statement payload' do
      payload, = decode_statement

      expect(payload).to include(
        'iss' => client_uri,
        'sub' => client_uri,
        'aud' => registration_endpoint,
        'iat' => now.to_i,
        'exp' => now.to_i + 300,
        'jti' => 'jti-123',
        'client_name' => 'Example Backend Service',
        'grant_types' => ['client_credentials'],
        'token_endpoint_auth_method' => 'private_key_jwt',
        'scope' => 'system/Patient.rs'
      )
    end

    it 'builds a complete authorization-code software statement payload' do
      metadata = Safire::Protocols::UdapRegistrationMetadata.new(
        metadata_input.merge(
          grant_types: %w[authorization_code refresh_token],
          redirect_uris: ['https://client.example.com/callback'],
          logo_uri: 'https://client.example.com/logo.png'
        )
      )
      payload, = decode_statement(build_statement(metadata:))

      expect(payload).to include(
        'grant_types' => %w[authorization_code refresh_token],
        'redirect_uris' => ['https://client.example.com/callback'],
        'logo_uri' => 'https://client.example.com/logo.png',
        'response_types' => ['code']
      )
    end

    it 'uses the client URI and registration endpoint exactly as supplied' do
      exact_client_uri = 'https://Client.example.com:443/app/'
      exact_endpoint = 'https://as.example.com/register/'
      cert = build_valid_certificate(key: rsa_key, uri_san: exact_client_uri)
      payload, = decode_statement(
        build_statement(client_uri: exact_client_uri, registration_endpoint: exact_endpoint, certificate_chain: [cert]),
        cert:
      )

      expect(payload).to include('iss' => exact_client_uri, 'sub' => exact_client_uri, 'aud' => exact_endpoint)
    end

    it 'allows non-HTTPS absolute client URIs when the exact URI appears in the certificate SAN' do
      did_uri = 'did:web:client.example.com:app'
      cert = build_valid_certificate(key: rsa_key, uri_san: did_uri)
      payload, = decode_statement(build_statement(client_uri: did_uri, certificate_chain: [cert]), cert:)

      expect(payload['iss']).to eq(did_uri)
    end

    it 'allows HTTP localhost registration endpoints only with an explicit development opt-in' do
      endpoint = 'http://localhost:4567/register'
      statement = build_statement(registration_endpoint: endpoint, allow_insecure_localhost: true)
      payload, = decode_statement(statement)

      expect(payload['aud']).to eq(endpoint)
    end

    it 'generates a fresh random jti when no generator is injected' do
      first_payload, = decode_statement(build_statement(jti_generator: nil))
      second_payload, = decode_statement(build_statement(jti_generator: nil))

      expect(first_payload['jti']).not_to eq(second_payload['jti'])
    end
  end

  describe 'algorithm selection' do
    it 'prefers RS256 for RSA keys when advertised' do
      _payload, header = decode_statement(build_statement(supported_algorithms: %w[RS384 RS256]))

      expect(header['alg']).to eq('RS256')
    end

    it 'selects RS384 for RSA keys when RS256 is not advertised' do
      statement = build_statement(supported_algorithms: ['RS384'])
      _payload, header = decode_statement(statement, algorithm: 'RS384')

      expect(header['alg']).to eq('RS384')
    end

    it 'supports ES256 with EC P-256 keys' do
      ec_key = OpenSSL::PKey::EC.generate('prime256v1')
      cert = build_valid_certificate(key: ec_key, uri_san: client_uri)
      statement = build_statement(private_key: ec_key, certificate_chain: [cert], supported_algorithms: ['ES256'])
      _payload, header = decode_statement(statement, cert:, algorithm: 'ES256')

      expect(header['alg']).to eq('ES256')
    end

    it 'supports ES384 with EC P-384 keys' do
      ec_key = OpenSSL::PKey::EC.generate('secp384r1')
      cert = build_valid_certificate(key: ec_key, uri_san: client_uri)
      statement = build_statement(private_key: ec_key, certificate_chain: [cert], supported_algorithms: ['ES384'])
      _payload, header = decode_statement(statement, cert:, algorithm: 'ES384')

      expect(header['alg']).to eq('ES384')
    end

    it 'honors an explicit compatible algorithm when advertised' do
      statement = build_statement(algorithm: 'RS384', supported_algorithms: %w[RS256 RS384])
      _payload, header = decode_statement(statement, algorithm: 'RS384')

      expect(header['alg']).to eq('RS384')
    end

    it 'rejects an explicit algorithm that is not advertised' do
      expect { build_statement(algorithm: 'RS384', supported_algorithms: ['RS256']) }
        .to raise_error(Safire::Errors::ConfigurationError, /algorithm/)
    end

    it 'rejects a blank explicit algorithm' do
      expect { build_statement(algorithm: ' ') }
        .to raise_error(Safire::Errors::ConfigurationError, /algorithm/)
    end

    it 'rejects an algorithm that is incompatible with the private key' do
      expect { build_statement(algorithm: 'ES256', supported_algorithms: ['ES256']) }
        .to raise_error(Safire::Errors::ConfigurationError, /algorithm/)
    end

    it 'rejects unsupported advertised algorithms when no compatible supported algorithm remains' do
      expect { build_statement(supported_algorithms: %w[HS256 ES256]) }
        .to raise_error(Safire::Errors::ConfigurationError, /supported_algorithms/)
    end

    it 'requires supported_algorithms to be an array of strings' do
      expect { build_statement(supported_algorithms: ['RS256', nil]) }
        .to raise_error(Safire::Errors::ConfigurationError, /supported_algorithms/)
    end
  end

  describe 'configuration and certificate validation' do
    it 'accepts PEM strings for private key and certificate chain entries' do
      statement = build_statement(private_key: rsa_key.to_pem, certificate_chain: [leaf_cert.to_pem])
      payload, = decode_statement(statement)

      expect(payload['iss']).to eq(client_uri)
    end

    it 'requires a validated UdapRegistrationMetadata object' do
      expect { build_statement(metadata: metadata.to_h) }
        .to raise_error(Safire::Errors::ValidationError, /metadata/)
    end

    it 'rejects a malformed private key without leaking the value' do
      error = capture_error(Safire::Errors::ConfigurationError) do
        build_statement(private_key: 'not a private key')
      end

      expect(error.message).to include('private_key')
      expect(error.message).not_to include('not a private key')
    end

    it 'rejects a public-key-only signing key' do
      expect { build_statement(private_key: rsa_key.public_key) }
        .to raise_error(Safire::Errors::ConfigurationError, /private_key/)
    end

    it 'rejects an empty certificate chain' do
      expect { build_statement(certificate_chain: []) }
        .to raise_error(Safire::Errors::ConfigurationError, /certificate_chain/)
    end

    it 'rejects malformed certificate PEM as a certificate error' do
      expect { build_statement(certificate_chain: ['not a certificate']) }
        .to raise_error(Safire::Errors::CertificateError, /malformed/)
    end

    it 'rejects an expired leaf certificate' do
      expired = build_udap_certificate(key: rsa_key, uri_san: client_uri, not_before: now - 3600, not_after: now - 1)

      expect { build_statement(certificate_chain: [expired]) }
        .to raise_error(Safire::Errors::CertificateError, /expired/)
    end

    it 'rejects a not-yet-valid chain certificate' do
      future = build_udap_certificate(key: rsa_key, uri_san: 'https://issuer.example.com', not_before: now + 60)

      expect { build_statement(certificate_chain: [leaf_cert, future]) }
        .to raise_error(Safire::Errors::CertificateError, /not yet valid/)
    end

    it 'rejects a leaf certificate whose public key does not match the private key' do
      other_key = OpenSSL::PKey::RSA.generate(2048)
      mismatched = build_valid_certificate(key: other_key, uri_san: client_uri)

      expect { build_statement(certificate_chain: [mismatched]) }
        .to raise_error(Safire::Errors::CertificateError, /private key/)
    end

    it 'rejects a leaf certificate without a URI SAN' do
      cert = build_valid_certificate(key: rsa_key, uri_san: nil)

      expect { build_statement(certificate_chain: [cert]) }
        .to raise_error(Safire::Errors::CertificateError, /URI SAN/)
    end

    it 'rejects a leaf certificate whose URI SAN does not exactly match client_uri' do
      cert = build_valid_certificate(key: rsa_key, uri_san: "#{client_uri}/")

      expect { build_statement(certificate_chain: [cert]) }
        .to raise_error(Safire::Errors::CertificateError, /URI SAN/)
    end

    it 'rejects HTTP registration endpoints by default' do
      expect { build_statement(registration_endpoint: 'http://localhost:4567/register') }
        .to raise_error(Safire::Errors::ConfigurationError, /registration_endpoint/)
    end

    it 'rejects a non-boolean localhost HTTP opt-in' do
      expect { build_statement(allow_insecure_localhost: 'true') }
        .to raise_error(Safire::Errors::ConfigurationError, /allow_insecure_localhost/)
    end

    it 'rejects remote HTTP registration endpoints even with the localhost opt-in' do
      expect do
        build_statement(registration_endpoint: 'http://as.example.com/register', allow_insecure_localhost: true)
      end.to raise_error(Safire::Errors::ConfigurationError, /registration_endpoint/)
    end

    it 'rejects invalid client URIs' do
      expect { build_statement(client_uri: '/relative-client') }
        .to raise_error(Safire::Errors::ConfigurationError, /client_uri/)
    end

    it 'requires the JTI generator to be callable when provided' do
      expect { build_statement(jti_generator: 'jti') }
        .to raise_error(Safire::Errors::ConfigurationError, /jti_generator/)
    end

    it 'requires the JTI generator to return a non-blank string' do
      statement = build_statement(jti_generator: -> { ' ' })

      expect { statement.to_jwt }
        .to raise_error(Safire::Errors::ConfigurationError, /jti_generator/)
    end

    it 'requires the clock to return a time-like object' do
      bad_clock = class_double(Time, now: Object.new)

      expect { build_statement(clock: bad_clock) }
        .to raise_error(Safire::Errors::ConfigurationError, /clock/)
    end
  end
end
