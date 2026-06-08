require 'spec_helper'
require 'openssl'
require 'base64'

RSpec.describe Safire::Protocols::UdapSignedMetadataValidator do
  # RSA key generation is slow; generate once for the whole suite.
  # rubocop:disable RSpec/BeforeAfterAll, RSpec/InstanceVariable
  before(:context) do
    @shared_key = OpenSSL::PKey::RSA.generate(2048)
  end

  let(:base_url)    { 'https://fhir.example.com' }
  let(:private_key) { @shared_key }
  # rubocop:enable RSpec/BeforeAfterAll, RSpec/InstanceVariable
  let(:cert)         { build_udap_cert(private_key, uri_san: base_url) }

  let(:now)          { Time.now.to_i }
  let(:valid_payload) do
    {
      'iss' => base_url,
      'sub' => base_url,
      'iat' => now,
      'exp' => now + 3600,
      'jti' => 'unique-nonce-abc123',
      'token_endpoint' => "#{base_url}/token",
      'registration_endpoint' => "#{base_url}/register"
    }
  end

  let(:unsigned_metadata) do
    {
      'token_endpoint' => "#{base_url}/token_unsigned",
      'registration_endpoint' => "#{base_url}/register_unsigned"
    }
  end

  let(:jwt)       { build_udap_jwt(valid_payload, key: private_key, cert: cert) }
  let(:validator) { described_class.new(jwt, unsigned_metadata) }

  # ---------- helpers ----------

  def build_udap_cert(key, uri_san:)
    c = OpenSSL::X509::Certificate.new
    c.version    = 2
    c.serial     = 1
    c.subject    = OpenSSL::X509::Name.parse('/CN=Test UDAP Server')
    c.issuer     = c.subject
    c.public_key = key
    c.not_before = Time.now - 60
    c.not_after  = Time.now + 86_400
    ef = OpenSSL::X509::ExtensionFactory.new(c, c)
    c.add_extension(ef.create_extension('subjectAltName', "URI:#{uri_san}", false))
    c.sign(key, OpenSSL::Digest.new('SHA256'))
    c
  end

  def build_udap_jwt(payload, key: private_key, cert: self.cert, alg: 'RS256', omit_x5c: false)
    header = omit_x5c ? {} : { 'x5c' => [Base64.strict_encode64(cert.to_der)] }
    JWT.encode(payload, key, alg, header)
  end

  def build_crl(issuer_cert, issuer_key, revoked_serials: [])
    crl = OpenSSL::X509::CRL.new
    crl.version = 1
    crl.issuer = issuer_cert.subject
    crl.last_update = Time.now - 60
    crl.next_update = Time.now + 86_400

    revoked_serials.each do |serial|
      revoked = OpenSSL::X509::Revoked.new
      revoked.serial = serial
      revoked.time = Time.now - 30
      crl.add_revoked(revoked)
    end

    crl.sign(issuer_key, OpenSSL::Digest.new('SHA256'))
    crl
  end

  def build_malformed_claim_jwt(payload, key: private_key, cert: self.cert, header: nil)
    header ||= { 'alg' => 'RS256', 'x5c' => [Base64.strict_encode64(cert.to_der)] }
    signing_input = [header, payload].map { |part| Base64.urlsafe_encode64(part.to_json, padding: false) }.join('.')
    signature = key.sign(OpenSSL::Digest.new('SHA256'), signing_input)

    "#{signing_input}.#{Base64.urlsafe_encode64(signature, padding: false)}"
  end

  # ---------- #signed_endpoint_claims ----------

  describe '#signed_endpoint_claims' do
    before { allow(Safire.logger).to receive(:warn) }

    context 'with a valid JWT' do
      it 'returns the signed endpoint claims' do
        result = validator.signed_endpoint_claims(base_url:, verify_chain: false)

        expect(result).to eq(
          'token_endpoint' => "#{base_url}/token",
          'registration_endpoint' => "#{base_url}/register"
        )
      end

      it 'includes authorization_endpoint when present in the signed payload' do
        payload = valid_payload.merge('authorization_endpoint' => "#{base_url}/authorize")
        v = described_class.new(
          build_udap_jwt(payload),
          unsigned_metadata.merge('authorization_endpoint' => "#{base_url}/authorize_unsigned")
        )

        expect(v.signed_endpoint_claims(base_url:, verify_chain: false)).to include(
          'authorization_endpoint' => "#{base_url}/authorize"
        )
      end

      it 'does not log any warnings' do
        validator.signed_endpoint_claims(base_url:, verify_chain: false)

        expect(Safire.logger).not_to have_received(:warn)
      end
    end

    # ---------- alg validation ----------

    context 'when alg is not RS256' do
      let(:other_key) { OpenSSL::PKey::EC.generate('prime256v1') }
      let(:ec_cert)   { build_udap_cert(other_key, uri_san: base_url) }
      let(:jwt)       { build_udap_jwt(valid_payload, key: other_key, cert: ec_cert, alg: 'ES256') }

      it 'returns nil' do
        expect(validator.signed_endpoint_claims(base_url:)).to be_nil
      end

      it 'logs a warning about the disallowed algorithm' do
        validator.signed_endpoint_claims(base_url:)

        expect(Safire.logger).to have_received(:warn).with(/ES256.*not permitted|not permitted.*ES256/)
      end
    end

    context 'when the decoded header is not a JSON object' do
      let(:jwt) { build_malformed_claim_jwt(valid_payload, header: 'not an object') }

      it 'returns nil and logs a warning without raising' do
        result = validator.signed_endpoint_claims(base_url:, verify_chain: false)

        expect(result).to be_nil
        expect(Safire.logger).to have_received(:warn).with(/header.*object/)
      end
    end

    context 'when the decoded payload is not a JSON object' do
      let(:jwt) { build_malformed_claim_jwt('not an object') }

      it 'returns nil and logs a warning without raising' do
        result = validator.signed_endpoint_claims(base_url:, verify_chain: false)

        expect(result).to be_nil
        expect(Safire.logger).to have_received(:warn).with(/payload.*object/)
      end
    end

    # ---------- x5c validation ----------

    context 'when x5c header is absent' do
      let(:jwt) { build_udap_jwt(valid_payload, omit_x5c: true) }

      it 'returns nil' do
        expect(validator.signed_endpoint_claims(base_url:)).to be_nil
      end

      it 'logs a warning' do
        validator.signed_endpoint_claims(base_url:)

        expect(Safire.logger).to have_received(:warn).with(/x5c/)
      end
    end

    context 'when x5c header contains a non-string value' do
      let(:jwt) { build_malformed_claim_jwt(valid_payload, header: { 'alg' => 'RS256', 'x5c' => [nil] }) }

      it 'returns nil and logs a warning without raising' do
        result = validator.signed_endpoint_claims(base_url:)

        expect(result).to be_nil
        expect(Safire.logger).to have_received(:warn).with(/x5c.*certificate strings/)
      end
    end

    # ---------- certificate parsing ----------

    context 'when x5c[0] is malformed DER' do
      let(:jwt) do
        header = { 'x5c' => [Base64.strict_encode64('not-valid-der')] }
        JWT.encode(valid_payload, private_key, 'RS256', header)
      end

      it 'raises CertificateError' do
        expect { validator.signed_endpoint_claims(base_url:) }
          .to raise_error(Safire::Errors::CertificateError, /malformed/)
      end
    end

    # ---------- signature verification ----------

    context 'when the JWT is signed with a different key' do
      let(:other_key) { OpenSSL::PKey::RSA.generate(2048) }
      let(:jwt)       { build_udap_jwt(valid_payload, key: other_key, cert: cert) }

      it 'returns nil' do
        expect(validator.signed_endpoint_claims(base_url:)).to be_nil
      end

      it 'logs a warning about signature failure' do
        validator.signed_endpoint_claims(base_url:)

        expect(Safire.logger).to have_received(:warn).with(/signature/)
      end
    end

    # ---------- chain verification ----------

    context 'with verify_chain: true' do
      context 'when the cert is provided as a trusted anchor with revocation material' do
        it 'returns the signed endpoint claims' do
          result = validator.signed_endpoint_claims(
            base_url:,
            trusted_anchors: [cert],
            crls: [build_crl(cert, private_key)],
            verify_chain: true
          )

          expect(result).to include('token_endpoint', 'registration_endpoint')
        end
      end

      context 'when no revocation policy is configured' do
        it 'returns nil and logs a revocation warning' do
          result = validator.signed_endpoint_claims(base_url:, trusted_anchors: [cert], verify_chain: true)

          expect(result).to be_nil
          expect(Safire.logger).to have_received(:warn).with(/revocation/)
        end
      end

      context 'when a CRL revokes the leaf certificate' do
        it 'returns nil and logs a chain warning' do
          result = validator.signed_endpoint_claims(
            base_url:,
            trusted_anchors: [cert],
            crls: [build_crl(cert, private_key, revoked_serials: [cert.serial])],
            verify_chain: true
          )

          expect(result).to be_nil
          expect(Safire.logger).to have_received(:warn).with(/chain|revoked/i)
        end
      end

      context 'when a custom revocation checker approves the certificate' do
        it 'returns the signed endpoint claims' do
          checker = lambda do |leaf_cert:, intermediates:, trusted_anchors:|
            expect(leaf_cert).to eq(cert)
            expect(intermediates).to eq([])
            expect(trusted_anchors).to eq([cert])
            true
          end

          result = validator.signed_endpoint_claims(
            base_url:,
            trusted_anchors: [cert],
            revocation_checker: checker,
            verify_chain: true
          )

          expect(result).to include('token_endpoint', 'registration_endpoint')
        end
      end

      context 'when a custom revocation checker rejects the certificate' do
        it 'returns nil and logs a revocation warning' do
          checker = ->(**_kwargs) { false }

          result = validator.signed_endpoint_claims(
            base_url:,
            trusted_anchors: [cert],
            revocation_checker: checker,
            verify_chain: true
          )

          expect(result).to be_nil
          expect(Safire.logger).to have_received(:warn).with(/revocation/)
        end
      end

      context 'when no trusted anchors are provided for a self-signed cert' do
        it 'returns nil' do
          expect(
            validator.signed_endpoint_claims(
              base_url:,
              trusted_anchors: [],
              crls: [build_crl(cert, private_key)],
              verify_chain: true
            )
          )
            .to be_nil
        end

        it 'logs a warning about chain failure' do
          validator.signed_endpoint_claims(
            base_url:,
            trusted_anchors: [],
            crls: [build_crl(cert, private_key)],
            verify_chain: true
          )

          expect(Safire.logger).to have_received(:warn).with(/chain/)
        end
      end

      context 'when the X.509 store raises a StoreError' do
        before do
          allow(OpenSSL::X509::StoreContext).to receive(:new).and_raise(OpenSSL::X509::StoreError, 'store error')
        end

        it 'returns nil and logs a chain error warning' do
          result = validator.signed_endpoint_claims(
            base_url:,
            trusted_anchors: [cert],
            crls: [build_crl(cert, private_key)],
            verify_chain: true
          )

          expect(result).to be_nil
          expect(Safire.logger).to have_received(:warn).with(/chain/)
        end
      end
    end

    context 'with verify_chain: false' do
      it 'skips chain verification and returns claims' do
        result = validator.signed_endpoint_claims(base_url:, verify_chain: false)

        expect(result).to include('token_endpoint', 'registration_endpoint')
      end
    end

    # ---------- iss / SAN validation ----------

    context 'when iss claim is missing from the payload' do
      let(:jwt) { build_udap_jwt(valid_payload.except('iss')) }

      it 'returns nil and logs a warning' do
        result = validator.signed_endpoint_claims(base_url:, verify_chain: false)

        expect(result).to be_nil
        expect(Safire.logger).to have_received(:warn).with(/iss.*missing/)
      end
    end

    context 'when iss does not match the certificate SAN' do
      let(:jwt) { build_udap_jwt(valid_payload.merge('iss' => 'https://other.example.com')) }

      it 'returns nil' do
        expect(validator.signed_endpoint_claims(base_url: 'https://other.example.com', verify_chain: false))
          .to be_nil
      end

      it 'logs a warning about the SAN mismatch' do
        validator.signed_endpoint_claims(base_url: 'https://other.example.com', verify_chain: false)

        expect(Safire.logger).to have_received(:warn).with(/SAN|uriName/)
      end
    end

    context 'when iss does not match the server base URL' do
      let(:jwt)       { build_udap_jwt(valid_payload) }

      it 'returns nil' do
        expect(validator.signed_endpoint_claims(base_url: 'https://other.example.com', verify_chain: false))
          .to be_nil
      end

      it 'logs a warning about the base URL mismatch' do
        validator.signed_endpoint_claims(base_url: 'https://other.example.com', verify_chain: false)

        expect(Safire.logger).to have_received(:warn)
      end

      it 'normalizes a trailing slash on the configured base URL' do
        expect(validator.signed_endpoint_claims(base_url: "#{base_url}/", verify_chain: false))
          .to include('token_endpoint', 'registration_endpoint')
      end
    end

    # ---------- sub == iss ----------

    context 'when sub does not equal iss' do
      let(:jwt) { build_udap_jwt(valid_payload.merge('sub' => 'https://other.example.com')) }

      it 'returns nil' do
        expect(validator.signed_endpoint_claims(base_url:, verify_chain: false)).to be_nil
      end

      it 'logs a warning' do
        validator.signed_endpoint_claims(base_url:, verify_chain: false)

        expect(Safire.logger).to have_received(:warn).with(/sub.*iss|sub must equal/)
      end
    end

    # ---------- iat validation ----------

    context 'when iat is missing from the payload' do
      let(:jwt) { build_udap_jwt(valid_payload.except('iat')) }

      it 'returns nil and logs a warning' do
        result = validator.signed_endpoint_claims(base_url:, verify_chain: false)

        expect(result).to be_nil
        expect(Safire.logger).to have_received(:warn).with(/iat/)
      end
    end

    context 'when iat is not an integer' do
      let(:jwt) { build_malformed_claim_jwt(valid_payload.merge('iat' => 'now')) }

      it 'returns nil and logs a warning without raising' do
        result = validator.signed_endpoint_claims(base_url:, verify_chain: false)

        expect(result).to be_nil
        expect(Safire.logger).to have_received(:warn).with(/iat.*integer/)
      end
    end

    # ---------- exp validation ----------

    context 'when exp is missing' do
      let(:jwt) { build_udap_jwt(valid_payload.except('exp'), key: private_key, cert: cert) }

      it 'returns nil and logs a warning' do
        result = validator.signed_endpoint_claims(base_url:, verify_chain: false)

        expect(result).to be_nil
        expect(Safire.logger).to have_received(:warn).with(/exp/)
      end
    end

    context 'when exp is not an integer' do
      let(:jwt) { build_malformed_claim_jwt(valid_payload.merge('exp' => 'tomorrow')) }

      it 'returns nil and logs a warning without raising' do
        result = validator.signed_endpoint_claims(base_url:, verify_chain: false)

        expect(result).to be_nil
        expect(Safire.logger).to have_received(:warn).with(/exp.*integer/)
      end
    end

    context 'when the JWT has expired' do
      let(:jwt) { build_udap_jwt(valid_payload.merge('exp' => now - 1)) }

      it 'returns nil and logs a warning' do
        result = validator.signed_endpoint_claims(base_url:, verify_chain: false)

        expect(result).to be_nil
        expect(Safire.logger).to have_received(:warn).with(/expired/)
      end
    end

    context 'when exp exceeds iat by more than 1 year' do
      let(:jwt) { build_udap_jwt(valid_payload.merge('exp' => now + (366 * 24 * 3600))) }

      it 'returns nil and logs a warning' do
        result = validator.signed_endpoint_claims(base_url:, verify_chain: false)

        expect(result).to be_nil
        expect(Safire.logger).to have_received(:warn).with(/1 year|maximum validity/)
      end
    end

    # ---------- jti ----------

    context 'when jti is missing' do
      let(:jwt) { build_udap_jwt(valid_payload.except('jti')) }

      it 'returns nil and logs a warning' do
        result = validator.signed_endpoint_claims(base_url:, verify_chain: false)

        expect(result).to be_nil
        expect(Safire.logger).to have_received(:warn).with(/jti/)
      end
    end

    # ---------- required endpoint claims ----------

    context 'when token_endpoint is missing from the signed payload' do
      let(:jwt) { build_udap_jwt(valid_payload.except('token_endpoint')) }

      it 'returns nil and logs a warning' do
        result = validator.signed_endpoint_claims(base_url:, verify_chain: false)

        expect(result).to be_nil
        expect(Safire.logger).to have_received(:warn).with(/token_endpoint/)
      end
    end

    context 'when token_endpoint is not an absolute URL' do
      let(:jwt) { build_udap_jwt(valid_payload.merge('token_endpoint' => 'not a url')) }

      it 'returns nil and logs a warning' do
        result = validator.signed_endpoint_claims(base_url:, verify_chain: false)

        expect(result).to be_nil
        expect(Safire.logger).to have_received(:warn).with(/token_endpoint.*HTTPS URL/)
      end
    end

    context 'when registration_endpoint is not HTTPS' do
      let(:jwt) { build_udap_jwt(valid_payload.merge('registration_endpoint' => 'http://remote.example.com/register')) }

      it 'returns nil and logs a warning' do
        result = validator.signed_endpoint_claims(base_url:, verify_chain: false)

        expect(result).to be_nil
        expect(Safire.logger).to have_received(:warn).with(/registration_endpoint.*HTTPS URL/)
      end
    end

    context 'when registration_endpoint is missing from the signed payload' do
      let(:jwt) { build_udap_jwt(valid_payload.except('registration_endpoint')) }

      it 'returns nil and logs a warning' do
        result = validator.signed_endpoint_claims(base_url:, verify_chain: false)

        expect(result).to be_nil
        expect(Safire.logger).to have_received(:warn).with(/registration_endpoint/)
      end
    end

    context 'when authorization_endpoint is present but not HTTPS' do
      let(:jwt) do
        build_udap_jwt(valid_payload.merge('authorization_endpoint' => 'http://remote.example.com/authorize'))
      end

      it 'returns nil and logs a warning' do
        result = validator.signed_endpoint_claims(base_url:, verify_chain: false)

        expect(result).to be_nil
        expect(Safire.logger).to have_received(:warn).with(/authorization_endpoint.*HTTPS URL/)
      end
    end

    context 'when authorization_endpoint is present but blank' do
      let(:jwt) { build_udap_jwt(valid_payload.merge('authorization_endpoint' => '   ')) }

      it 'returns nil and logs a warning' do
        result = validator.signed_endpoint_claims(base_url:, verify_chain: false)

        expect(result).to be_nil
        expect(Safire.logger).to have_received(:warn).with(/authorization_endpoint.*HTTPS URL/)
      end
    end

    context 'when authorization_endpoint is in unsigned metadata but missing from signed payload' do
      let(:unsigned_metadata) { super().merge('authorization_endpoint' => "#{base_url}/authorize") }

      it 'returns nil and logs a warning' do
        result = validator.signed_endpoint_claims(base_url:, verify_chain: false)

        expect(result).to be_nil
        expect(Safire.logger).to have_received(:warn).with(/authorization_endpoint/)
      end
    end

    context 'when authorization_endpoint is absent from both unsigned metadata and signed payload' do
      it 'returns claims without authorization_endpoint' do
        result = validator.signed_endpoint_claims(base_url:, verify_chain: false)

        expect(result).not_to have_key('authorization_endpoint')
        expect(result).to include('token_endpoint', 'registration_endpoint')
      end
    end

    # ---------- malformed JWT ----------

    context 'when the JWT string is malformed' do
      let(:jwt) { 'not.a.valid.jwt.at.all' }

      it 'returns nil' do
        expect(validator.signed_endpoint_claims(base_url:)).to be_nil
      end

      it 'logs a warning' do
        validator.signed_endpoint_claims(base_url:)

        expect(Safire.logger).to have_received(:warn).with(/decode|invalid|malformed/i)
      end
    end

    context 'when signed_metadata is not a string' do
      let(:jwt) { 123 }

      it 'returns nil and logs a warning without raising' do
        result = validator.signed_endpoint_claims(base_url:)

        expect(result).to be_nil
        expect(Safire.logger).to have_received(:warn).with(/compact-JWS string/)
      end
    end
  end

  # ---------- #valid? ----------

  describe '#valid?' do
    before { allow(Safire.logger).to receive(:warn) }

    it 'returns true when signed_endpoint_claims succeeds' do
      expect(validator.valid?(base_url:, verify_chain: false)).to be(true)
    end

    it 'returns false when signed_endpoint_claims returns nil' do
      broken = described_class.new('not.a.jwt', unsigned_metadata)

      expect(broken.valid?(base_url:)).to be(false)
    end
  end
end
