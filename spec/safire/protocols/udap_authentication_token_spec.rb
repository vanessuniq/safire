require 'spec_helper'
require_relative '../../support/udap_certificate_helpers'

RSpec.describe Safire::Protocols::UdapAuthenticationToken do
  include UdapCertificateHelpers

  let(:now) { Time.at(1_700_000_000) }
  let(:clock) { class_double(Time, now:) }
  let(:jti_generator) { -> { 'jti-123' } }
  let(:client_id) { 'client-abc' }
  let(:token_endpoint) { 'https://as.example.com/token' }
  let(:rsa_key) { OpenSSL::PKey::RSA.generate(2048) }
  let(:leaf_cert) { build_valid_certificate(key: rsa_key) }
  let(:base_params) do
    {
      client_id:,
      token_endpoint:,
      private_key: rsa_key,
      certificate_chain: [leaf_cert],
      supported_algorithms: %w[RS256 RS384 ES256],
      clock:,
      jti_generator:
    }
  end
  let(:b2b_extension) do
    {
      'hl7-b2b' => {
        'version' => '1',
        'organization_id' => 'https://org.example.com',
        'purpose_of_use' => ['urn:oid:2.16.840.1.113883.5.8#TREAT']
      }
    }
  end

  def build_token(overrides = {})
    described_class.new(**base_params, **overrides)
  end

  def build_valid_certificate(key:, **kwargs)
    build_udap_certificate(key:, uri_san: nil, not_before: now - 60, not_after: now + 3600, **kwargs)
  end

  def decode(jwt, cert: leaf_cert, algorithm: 'RS256')
    JWT.decode(jwt, cert.public_key, true, algorithms: [algorithm], verify_expiration: false, verify_iat: false)
  end

  describe '#to_jwt' do
    it 'emits a header containing exactly alg and a leaf-first x5c' do
      _payload, header = decode(build_token.to_jwt)

      expect(header.keys).to contain_exactly('alg', 'x5c')
      expect(header['alg']).to eq('RS256')
      expect(header['x5c']).to eq([Base64.strict_encode64(leaf_cert.to_der)])
    end

    it 'emits exactly the required claims when no extensions are supplied' do
      payload, = decode(build_token.to_jwt)

      expect(payload).to eq(
        'iss' => client_id,
        'sub' => client_id,
        'aud' => token_endpoint,
        'iat' => now.to_i,
        'exp' => now.to_i + 300,
        'jti' => 'jti-123'
      )
    end

    it 'uses a lifetime of exactly 300 seconds with integer NumericDates' do
      payload, = decode(build_token(clock: class_double(Time, now: Time.at(1_700_000_000.9))).to_jwt)

      expect(payload['iat']).to be_a(Integer)
      expect(payload['exp']).to be_a(Integer)
      expect(payload['exp'] - payload['iat']).to eq(300)
    end

    it 'generates a distinct default jti for each call' do
      token = build_token(jti_generator: nil)
      first, = decode(token.to_jwt)
      second, = decode(token.to_jwt)

      expect(first['jti']).to match(/\A\h{8}-\h{4}-\h{4}-\h{4}-\h{12}\z/)
      expect(first['jti']).not_to eq(second['jti'])
    end

    it 'calls the injected jti generator once per token' do
      values = %w[first second].each
      token = build_token(jti_generator: -> { values.next })

      expect([decode(token.to_jwt).first['jti'], decode(token.to_jwt).first['jti']]).to eq(%w[first second])
    end

    it 'rejects a blank jti from the generator' do
      expect { build_token(jti_generator: -> { ' ' }).to_jwt }
        .to raise_error(Safire::Errors::ConfigurationError, /jti_generator/)
    end

    it 'rejects a non-String jti from the generator' do
      expect { build_token(jti_generator: -> { 42 }).to_jwt }
        .to raise_error(Safire::Errors::ConfigurationError, /jti_generator/)
    end

    %w[
      https://AS.Example.com:443/token/
      https://as.example.com:8443/Token
      https://as.example.com/token?tenant=a
    ].each do |endpoint|
      it "signs aud byte-identical to the supplied endpoint #{endpoint}" do
        payload, = decode(build_token(token_endpoint: endpoint).to_jwt)

        expect(payload['aud']).to eq(endpoint)
      end
    end

    it 'includes extensions only when supplied' do
      payload, = decode(build_token(extensions: b2b_extension).to_jwt)

      expect(payload.keys).to contain_exactly('iss', 'sub', 'aud', 'iat', 'exp', 'jti', 'extensions')
      expect(payload['extensions']).to eq(b2b_extension)
    end

    it 'raises CertificateError when the certificate expires before signing' do
      signing_clock = Struct.new(:now).new(now)
      expiring_cert = build_udap_certificate(key: rsa_key, uri_san: nil, not_before: now - 60, not_after: now + 60)
      token = build_token(clock: signing_clock, certificate_chain: [expiring_cert])

      signing_clock.now = now + 61

      expect { token.to_jwt }.to raise_error(Safire::Errors::CertificateError, /expired/)
    end

    it 'raises ConfigurationError when the clock stops returning a Time' do
      signing_clock = Struct.new(:now).new(now)
      token = build_token(clock: signing_clock)
      signing_clock.now = now.to_i

      expect { token.to_jwt }.to raise_error(Safire::Errors::ConfigurationError, /clock/)
    end

    it 'does not include claim values or key material in errors' do
      token = build_token(jti_generator: -> { 42 })

      expect { token.to_jwt }.to raise_error(Safire::Errors::ConfigurationError) { |error|
        expect(error.message).not_to include(client_id, token_endpoint)
        expect(error.message).not_to include('PRIVATE KEY')
      }
    end
  end

  describe 'construction' do
    it 'is frozen' do
      expect(build_token).to be_frozen
    end

    it 'does not require a URI SAN in the leaf certificate' do
      expect(build_token.algorithm).to eq('RS256')
    end
  end

  describe 'algorithm negotiation' do
    it 'selects RS256 for RSA keys when advertised' do
      expect(build_token(supported_algorithms: %w[RS384 RS256]).algorithm).to eq('RS256')
    end

    it 'falls back to RS384 for RSA keys when RS256 is not advertised' do
      token = build_token(supported_algorithms: %w[RS384 ES256])

      expect(decode(token.to_jwt, algorithm: 'RS384').last['alg']).to eq('RS384')
    end

    it 'selects ES256 for an EC P-256 key' do
      ec_key = OpenSSL::PKey::EC.generate('prime256v1')
      cert = build_valid_certificate(key: ec_key)
      token = build_token(private_key: ec_key, certificate_chain: [cert], supported_algorithms: %w[RS256 ES256])

      expect(decode(token.to_jwt, cert:, algorithm: 'ES256').last['alg']).to eq('ES256')
    end

    it 'selects ES384 for an EC P-384 key' do
      ec_key = OpenSSL::PKey::EC.generate('secp384r1')
      cert = build_valid_certificate(key: ec_key)
      token = build_token(private_key: ec_key, certificate_chain: [cert], supported_algorithms: %w[ES256 ES384])

      expect(decode(token.to_jwt, cert:, algorithm: 'ES384').last['alg']).to eq('ES384')
    end

    it 'honors an explicit advertised algorithm' do
      expect(build_token(algorithm: 'RS384').algorithm).to eq('RS384')
    end

    it 'raises ConfigurationError when no advertised algorithm is compatible with the key' do
      expect { build_token(supported_algorithms: %w[ES256 ES384]) }
        .to raise_error(Safire::Errors::ConfigurationError, /supported_algorithms/)
    end

    it 'raises ConfigurationError when an explicit algorithm is not advertised' do
      expect { build_token(supported_algorithms: %w[RS256], algorithm: 'RS384') }
        .to raise_error(Safire::Errors::ConfigurationError, /algorithm/)
    end
  end

  describe 'certificate checks' do
    it 'raises CertificateError when the private key does not match the leaf certificate' do
      mismatched = build_valid_certificate(key: OpenSSL::PKey::RSA.generate(2048))

      expect { build_token(certificate_chain: [mismatched]) }
        .to raise_error(Safire::Errors::CertificateError, /does not match/)
    end

    it 'raises CertificateError for an already expired certificate' do
      expired = build_udap_certificate(key: rsa_key, uri_san: nil, not_before: now - 3600, not_after: now - 1)

      expect { build_token(certificate_chain: [expired]) }
        .to raise_error(Safire::Errors::CertificateError, /expired/)
    end
  end

  describe 'client_id validation' do
    [nil, '', '   '].each do |value|
      it "reports client_id as missing for #{value.inspect}" do
        expect { build_token(client_id: value) }.to raise_error(Safire::Errors::ConfigurationError) { |error|
          expect(error.missing_attributes).to eq([:client_id])
        }
      end
    end

    [42, :client, ['client']].each do |value|
      it "rejects non-String client_id #{value.class}" do
        expect { build_token(client_id: value) }.to raise_error(Safire::Errors::ConfigurationError) { |error|
          expect(error.invalid_attribute).to eq(:client_id)
          expect(error.invalid_value).to eq(value.class)
        }
      end
    end

    it 'snapshots the client_id against caller mutation' do
      value = +'client-abc'
      token = build_token(client_id: value)
      value << '-changed'

      expect(decode(token.to_jwt).first.values_at('iss', 'sub')).to eq(%w[client-abc client-abc])
    end
  end

  describe 'token_endpoint validation' do
    {
      'plain HTTP' => 'http://as.example.com/token',
      'HTTP localhost without opt-in' => 'http://localhost:8080/token',
      'fragment' => 'https://as.example.com/token#frag',
      'empty fragment' => 'https://as.example.com/token#',
      'relative' => '/token',
      'missing host' => 'https:///token',
      'non-HTTP scheme' => 'urn:example:token',
      'nil' => nil,
      'non-String' => URI('https://as.example.com/token')
    }.each do |label, value|
      it "rejects a #{label} token endpoint" do
        expect { build_token(token_endpoint: value) }.to raise_error(Safire::Errors::ConfigurationError) { |error|
          expect(error.invalid_attribute).to eq(:token_endpoint)
          expect(error.message).not_to include('as.example.com')
        }
      end
    end

    it 'allows an HTTP localhost token endpoint with allow_insecure_localhost' do
      token = build_token(token_endpoint: 'http://localhost:8080/token', allow_insecure_localhost: true)

      expect(decode(token.to_jwt).first['aud']).to eq('http://localhost:8080/token')
    end

    it 'allows an HTTP 127.0.0.1 token endpoint with allow_insecure_localhost' do
      expect(build_token(token_endpoint: 'http://127.0.0.1/token', allow_insecure_localhost: true).token_endpoint)
        .to eq('http://127.0.0.1/token')
    end

    it 'still rejects a non-loopback HTTP endpoint with allow_insecure_localhost' do
      expect { build_token(token_endpoint: 'http://as.example.com/token', allow_insecure_localhost: true) }
        .to raise_error(Safire::Errors::ConfigurationError, /token_endpoint/)
    end

    it 'still rejects a localhost fragment with allow_insecure_localhost' do
      expect { build_token(token_endpoint: 'http://localhost/token#x', allow_insecure_localhost: true) }
        .to raise_error(Safire::Errors::ConfigurationError, /token_endpoint/)
    end

    it 'rejects a non-boolean allow_insecure_localhost' do
      expect { build_token(allow_insecure_localhost: 'true') }
        .to raise_error(Safire::Errors::ConfigurationError, /allow_insecure_localhost/)
    end
  end

  describe 'extensions validation' do
    def extensions_error(extensions)
      build_token(extensions:)
    rescue Safire::Errors::ValidationError => e
      e
    end

    it 'omits the extensions claim when nil' do
      expect(decode(build_token(extensions: nil).to_jwt).first).not_to have_key('extensions')
    end

    it 'rejects an empty Hash' do
      expect(extensions_error({})).to have_attributes(attribute: :extensions, reason: /one or more/)
    end

    it 'rejects a non-Hash extensions value' do
      expect(extensions_error([b2b_extension])).to have_attributes(attribute: :extensions, reason: /Hash/)
    end

    it 'stringifies Symbol keys at every level' do
      token = build_token(extensions: { 'hl7-b2b': { version: '1', nested: { flag: true } } })

      expect(decode(token.to_jwt).first['extensions'])
        .to eq('hl7-b2b' => { 'version' => '1', 'nested' => { 'flag' => true } })
    end

    it 'rejects duplicate top-level keys after normalization' do
      expect(extensions_error({ 'ext' => { 'a' => 1 }, ext: { 'b' => 2 } }))
        .to have_attributes(reason: /duplicate/)
    end

    it 'rejects duplicate nested keys after normalization' do
      expect(extensions_error({ 'ext' => { 'a' => 1, a: 2 } })).to have_attributes(reason: /duplicate/)
    end

    it 'rejects a blank extension key' do
      expect(extensions_error({ ' ' => { 'a' => 1 } })).to have_attributes(reason: /non-blank/)
    end

    it 'rejects a non-String, non-Symbol key' do
      expect(extensions_error({ 1 => { 'a' => 1 } })).to have_attributes(reason: /keys/)
    end

    it 'rejects a non-Hash extension value' do
      expect(extensions_error({ 'ext' => 'value' })).to have_attributes(reason: /JSON object/)
    end

    it 'rejects an empty extension object' do
      expect(extensions_error({ 'ext' => {} })).to have_attributes(reason: /non-empty/)
    end

    {
      'Time' => Time.at(0),
      'Object' => Object.new,
      'Symbol' => :value,
      'NaN' => Float::NAN,
      'Infinity' => Float::INFINITY
    }.each do |label, value|
      it "rejects a non-JSON #{label} value" do
        expect(extensions_error({ 'ext' => { 'list' => [value] } })).to have_attributes(reason: /JSON-compatible/)
      end
    end

    it 'accepts every JSON value type' do
      value = { 's' => 'x', 'i' => 1, 'f' => 1.5, 't' => true, 'f2' => false, 'n' => nil, 'a' => [1, { 'k' => 'v' }] }
      token = build_token(extensions: { 'ext' => value })

      expect(decode(token.to_jwt).first['extensions']).to eq('ext' => value)
    end

    it 'rejects cyclic structures' do
      cyclic = { 'a' => 1 }
      cyclic['self'] = cyclic

      expect(extensions_error({ 'ext' => cyclic })).to have_attributes(reason: /cyclic/)
    end

    it 'accepts the same object referenced twice without a cycle' do
      shared = { 'k' => 'v' }
      token = build_token(extensions: { 'ext' => { 'a' => shared, 'b' => shared } })

      expect(decode(token.to_jwt).first['extensions']).to eq('ext' => { 'a' => shared, 'b' => shared })
    end

    it 'is not affected by caller mutation after construction' do
      source = { 'hl7-b2b' => { 'version' => +'1', 'purpose_of_use' => ['TREAT'] } }
      token = build_token(extensions: source)

      source['hl7-b2b']['version'] << '0'
      source['hl7-b2b']['purpose_of_use'] << 'ETREAT'
      source['other'] = { 'x' => 1 }

      expect(decode(token.to_jwt).first['extensions'])
        .to eq('hl7-b2b' => { 'version' => '1', 'purpose_of_use' => ['TREAT'] })
    end

    it 'does not include extension values in error messages' do
      error = extensions_error({ 'ext' => { 'secret' => Time.at(0) } })

      expect(error.message).not_to include('secret')
    end
  end
end
