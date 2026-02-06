require 'spec_helper'

RSpec.describe Safire::JWTAssertion do
  let(:rsa_key) { OpenSSL::PKey::RSA.generate(2048) }
  let(:ec_key) { OpenSSL::PKey::EC.generate('secp384r1') }
  let(:client_id) { 'test_client' }
  let(:token_endpoint) { 'https://auth.example.com/token' }
  let(:kid) { 'test-key-id' }

  describe '#initialize' do
    context 'with valid RSA key' do
      it 'creates an assertion with auto-detected RS384 algorithm' do
        assertion = described_class.new(
          client_id: client_id,
          token_endpoint: token_endpoint,
          private_key: rsa_key,
          kid: kid
        )

        expect(assertion.algorithm).to eq('RS384')
        expect(assertion.client_id).to eq(client_id)
        expect(assertion.token_endpoint).to eq(token_endpoint)
        expect(assertion.kid).to eq(kid)
      end
    end

    context 'with valid EC key' do
      it 'creates an assertion with auto-detected ES384 algorithm' do
        assertion = described_class.new(
          client_id: client_id,
          token_endpoint: token_endpoint,
          private_key: ec_key,
          kid: kid
        )

        expect(assertion.algorithm).to eq('ES384')
      end
    end

    context 'with PEM string key' do
      it 'parses and uses the key' do
        pem = rsa_key.to_pem
        assertion = described_class.new(
          client_id: client_id,
          token_endpoint: token_endpoint,
          private_key: pem,
          kid: kid
        )

        expect(assertion.private_key).to be_a(OpenSSL::PKey::RSA)
      end
    end

    context 'with explicit algorithm' do
      it 'uses the provided algorithm' do
        assertion = described_class.new(
          client_id: client_id,
          token_endpoint: token_endpoint,
          private_key: rsa_key,
          kid: kid,
          algorithm: 'RS384'
        )

        expect(assertion.algorithm).to eq('RS384')
      end
    end

    context 'with jku' do
      it 'stores the jku URL' do
        jku = 'https://app.example.com/.well-known/jwks.json'
        assertion = described_class.new(
          client_id: client_id,
          token_endpoint: token_endpoint,
          private_key: rsa_key,
          kid: kid,
          jku: jku
        )

        expect(assertion.jku).to eq(jku)
      end
    end

    context 'with expiration_seconds' do
      it 'caps expiration at MAX_EXPIRATION_SECONDS' do
        assertion = described_class.new(
          client_id: client_id,
          token_endpoint: token_endpoint,
          private_key: rsa_key,
          kid: kid,
          expiration_seconds: 600
        )

        expect(assertion.expiration_seconds).to eq(300)
      end

      it 'allows values under the maximum' do
        assertion = described_class.new(
          client_id: client_id,
          token_endpoint: token_endpoint,
          private_key: rsa_key,
          kid: kid,
          expiration_seconds: 120
        )

        expect(assertion.expiration_seconds).to eq(120)
      end
    end
  end

  describe 'validation errors' do
    it 'raises ArgumentError for missing client_id' do
      expect do
        described_class.new(
          client_id: nil,
          token_endpoint: token_endpoint,
          private_key: rsa_key,
          kid: kid
        )
      end.to raise_error(ArgumentError, /Missing required parameters.*client_id/)
    end

    it 'raises ArgumentError for missing token_endpoint' do
      expect do
        described_class.new(
          client_id: client_id,
          token_endpoint: nil,
          private_key: rsa_key,
          kid: kid
        )
      end.to raise_error(ArgumentError, /Missing required parameters.*token_endpoint/)
    end

    it 'raises ArgumentError for missing kid' do
      expect do
        described_class.new(
          client_id: client_id,
          token_endpoint: token_endpoint,
          private_key: rsa_key,
          kid: nil
        )
      end.to raise_error(ArgumentError, /Missing required parameters.*kid/)
    end

    it 'raises ArgumentError for unsupported algorithm' do
      expect do
        described_class.new(
          client_id: client_id,
          token_endpoint: token_endpoint,
          private_key: rsa_key,
          kid: kid,
          algorithm: 'RS256'
        )
      end.to raise_error(ArgumentError, /Unsupported algorithm/)
    end

    it 'raises ArgumentError for key/algorithm mismatch' do
      expect do
        described_class.new(
          client_id: client_id,
          token_endpoint: token_endpoint,
          private_key: rsa_key,
          kid: kid,
          algorithm: 'ES384'
        )
      end.to raise_error(ArgumentError, /requires an EC key/)
    end

    it 'raises ArgumentError for non-HTTPS jku' do
      expect do
        described_class.new(
          client_id: client_id,
          token_endpoint: token_endpoint,
          private_key: rsa_key,
          kid: kid,
          jku: 'http://insecure.example.com/jwks'
        )
      end.to raise_error(ArgumentError, /jku must be an HTTPS URL/)
    end

    it 'raises ArgumentError for invalid jku URL' do
      expect do
        described_class.new(
          client_id: client_id,
          token_endpoint: token_endpoint,
          private_key: rsa_key,
          kid: kid,
          jku: 'not a url'
        )
      end.to raise_error(ArgumentError, /jku must be/)
    end

    it 'raises ArgumentError for unsupported EC curve' do
      ec_p256 = OpenSSL::PKey::EC.generate('prime256v1')
      expect do
        described_class.new(
          client_id: client_id,
          token_endpoint: token_endpoint,
          private_key: ec_p256,
          kid: kid
        )
      end.to raise_error(ArgumentError, /Unsupported EC curve.*ES384 requires P-384/)
    end

    it 'raises ArgumentError for invalid PEM string' do
      expect do
        described_class.new(
          client_id: client_id,
          token_endpoint: token_endpoint,
          private_key: 'not a valid pem',
          kid: kid
        )
      end.to raise_error(ArgumentError, /Invalid private key/)
    end

    it 'raises ArgumentError for unsupported key type' do
      expect do
        described_class.new(
          client_id: client_id,
          token_endpoint: token_endpoint,
          private_key: 12_345,
          kid: kid
        )
      end.to raise_error(ArgumentError, /private_key must be/)
    end
  end

  describe '#header' do
    it 'returns header with typ, kid, and alg' do
      assertion = described_class.new(
        client_id: client_id,
        token_endpoint: token_endpoint,
        private_key: rsa_key,
        kid: kid
      )

      expect(assertion.header).to eq({ typ: 'JWT', kid: kid, alg: 'RS384' })
    end

    it 'includes jku when provided' do
      jku = 'https://app.example.com/.well-known/jwks.json'
      assertion = described_class.new(
        client_id: client_id,
        token_endpoint: token_endpoint,
        private_key: rsa_key,
        kid: kid,
        jku: jku
      )

      expect(assertion.header).to eq({ typ: 'JWT', kid: kid, alg: 'RS384', jku: jku })
    end
  end

  describe '#payload' do
    it 'returns payload with required claims' do
      freeze_time = Time.now
      allow(Time).to receive(:now).and_return(freeze_time)

      assertion = described_class.new(
        client_id: client_id,
        token_endpoint: token_endpoint,
        private_key: rsa_key,
        kid: kid
      )

      payload = assertion.payload

      expect(payload[:iss]).to eq(client_id)
      expect(payload[:sub]).to eq(client_id)
      expect(payload[:aud]).to eq(token_endpoint)
      expect(payload[:exp]).to eq(freeze_time.to_i + 300)
      expect(payload[:jti]).to be_a(String)
      expect(payload[:jti]).not_to be_empty
    end

    it 'generates unique jti on each call' do
      assertion = described_class.new(
        client_id: client_id,
        token_endpoint: token_endpoint,
        private_key: rsa_key,
        kid: kid
      )

      jti1 = assertion.payload[:jti]
      jti2 = assertion.payload[:jti]

      expect(jti1).not_to eq(jti2)
    end
  end

  describe '#to_jwt' do
    it 'returns a valid JWT string with RSA key' do
      assertion = described_class.new(
        client_id: client_id,
        token_endpoint: token_endpoint,
        private_key: rsa_key,
        kid: kid
      )

      jwt = assertion.to_jwt

      expect(jwt).to be_a(String)
      expect(jwt.split('.').length).to eq(3)

      decoded = JWT.decode(jwt, rsa_key.public_key, true, algorithm: 'RS384')
      expect(decoded[0]['iss']).to eq(client_id)
      expect(decoded[0]['sub']).to eq(client_id)
      expect(decoded[0]['aud']).to eq(token_endpoint)
      expect(decoded[1]['kid']).to eq(kid)
      expect(decoded[1]['alg']).to eq('RS384')
    end

    it 'returns a valid JWT string with EC key' do
      assertion = described_class.new(
        client_id: client_id,
        token_endpoint: token_endpoint,
        private_key: ec_key,
        kid: kid
      )

      jwt = assertion.to_jwt

      expect(jwt).to be_a(String)
      expect(jwt.split('.').length).to eq(3)

      decoded = JWT.decode(jwt, ec_key, true, algorithm: 'ES384')
      expect(decoded[0]['iss']).to eq(client_id)
      expect(decoded[1]['alg']).to eq('ES384')
    end
  end
end
