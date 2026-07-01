require 'spec_helper'

RSpec.describe Safire::ClientConfig do
  let(:certificate) do
    key = OpenSSL::PKey::RSA.generate(2048)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 1
    cert.subject = OpenSSL::X509::Name.parse('/CN=client.example.com')
    cert.issuer = cert.subject
    cert.public_key = key.public_key
    cert.not_before = Time.now
    cert.not_after = Time.now + 3600
    cert.sign(key, OpenSSL::Digest.new('SHA256'))
    cert
  end
  let(:certificate_pem) do
    <<~PEM
      -----BEGIN CERTIFICATE-----
      certificate-data
      -----END CERTIFICATE-----
    PEM
  end
  let(:valid_attrs) do
    {
      base_url: 'https://fhir.example.com',
      client_id: 'my_client',
      redirect_uri: 'https://myapp.example.com/callback'
    }
  end

  # ---------- Required attribute validation ----------

  describe 'required attribute validation' do
    it 'initializes successfully with all required attributes' do
      expect { described_class.new(valid_attrs) }.not_to raise_error
    end

    it 'initializes successfully without redirect_uri' do
      expect { described_class.new(valid_attrs.except(:redirect_uri)) }.not_to raise_error
    end

    it 'initializes successfully without client_id' do
      expect { described_class.new(valid_attrs.except(:client_id)) }.not_to raise_error
    end

    it 'raises ConfigurationError when base_url is missing' do
      expect { described_class.new(valid_attrs.except(:base_url)) }
        .to raise_error(Safire::Errors::ConfigurationError, /base_url/)
    end
  end

  # ---------- URI format validation ----------

  describe 'URI format validation' do
    it 'raises ConfigurationError when base_url is not a valid URI' do
      expect { described_class.new(valid_attrs.merge(base_url: 'not a url')) }
        .to raise_error(Safire::Errors::ConfigurationError, /invalid URIs/)
    end

    it 'raises ConfigurationError when redirect_uri has no host' do
      expect { described_class.new(valid_attrs.merge(redirect_uri: 'justpath')) }
        .to raise_error(Safire::Errors::ConfigurationError, /invalid URIs/)
    end
  end

  # ---------- HTTPS enforcement ----------

  describe 'HTTPS enforcement' do
    context 'when base_url uses HTTP on a non-localhost host' do
      it 'raises ConfigurationError' do
        expect { described_class.new(valid_attrs.merge(base_url: 'http://fhir.example.com')) }
          .to raise_error(Safire::Errors::ConfigurationError,
                          /requires HTTPS.*base_url.*SMART App Launch 2\.2\.0 requires TLS/)
      end
    end

    context 'when redirect_uri uses HTTP on a non-localhost host' do
      it 'raises ConfigurationError' do
        expect { described_class.new(valid_attrs.merge(redirect_uri: 'http://myapp.example.com/callback')) }
          .to raise_error(Safire::Errors::ConfigurationError, /requires HTTPS.*redirect_uri/)
      end
    end

    context 'when optional token_endpoint uses HTTP on a non-localhost host' do
      it 'raises ConfigurationError' do
        expect do
          described_class.new(valid_attrs.merge(token_endpoint: 'http://fhir.example.com/token'))
        end.to raise_error(Safire::Errors::ConfigurationError, /requires HTTPS.*token_endpoint/)
      end
    end

    context 'when optional authorization_endpoint uses HTTP on a non-localhost host' do
      it 'raises ConfigurationError' do
        expect do
          described_class.new(valid_attrs.merge(authorization_endpoint: 'http://fhir.example.com/auth'))
        end.to raise_error(Safire::Errors::ConfigurationError, /requires HTTPS.*authorization_endpoint/)
      end
    end

    context 'when optional jwks_uri uses HTTP on a non-localhost host' do
      it 'raises ConfigurationError' do
        expect do
          described_class.new(valid_attrs.merge(jwks_uri: 'http://myapp.example.com/jwks.json'))
        end.to raise_error(Safire::Errors::ConfigurationError, /requires HTTPS.*jwks_uri/)
      end
    end

    context 'when multiple URIs use HTTP on non-localhost hosts' do
      it 'reports all non-HTTPS attributes in a single error' do
        expect do
          described_class.new(
            valid_attrs.merge(
              base_url: 'http://fhir.example.com',
              redirect_uri: 'http://myapp.example.com/callback'
            )
          )
        end.to raise_error(Safire::Errors::ConfigurationError, /base_url.*redirect_uri|redirect_uri.*base_url/)
      end
    end

    context 'when allow_insecure_localhost is not enabled' do
      it 'rejects HTTP for localhost base_url' do
        expect do
          described_class.new(valid_attrs.merge(base_url: 'http://localhost:3000/fhir'))
        end.to raise_error(Safire::Errors::ConfigurationError, /requires HTTPS.*base_url/)
      end

      it 'rejects HTTP for localhost redirect_uri' do
        expect do
          described_class.new(valid_attrs.merge(redirect_uri: 'http://localhost:3000/callback'))
        end.to raise_error(Safire::Errors::ConfigurationError, /requires HTTPS.*redirect_uri/)
      end
    end

    context 'when allow_insecure_localhost is enabled' do
      before { allow(Safire.logger).to receive(:warn) }

      it 'allows HTTP for localhost base_url' do
        expect do
          described_class.new(valid_attrs.merge(base_url: 'http://localhost:3000/fhir', allow_insecure_localhost: true))
        end.not_to raise_error
      end

      it 'reads allow_insecure_localhost from a string key' do
        config = described_class.new(
          valid_attrs.merge(
            base_url: 'http://localhost:3000/fhir',
            'allow_insecure_localhost' => true
          )
        )

        expect(config.allow_insecure_localhost).to be(true)
      end

      it 'allows HTTP for 127.0.0.1 base_url' do
        expect do
          described_class.new(valid_attrs.merge(base_url: 'http://127.0.0.1:8080/fhir', allow_insecure_localhost: true))
        end.not_to raise_error
      end

      it 'allows HTTP for localhost redirect_uri' do
        expect do
          described_class.new(valid_attrs.merge(redirect_uri: 'http://localhost:3000/callback',
                                                allow_insecure_localhost: true))
        end.not_to raise_error
      end

      it 'allows HTTP for localhost token_endpoint' do
        expect do
          described_class.new(valid_attrs.merge(token_endpoint: 'http://localhost:9000/token',
                                                allow_insecure_localhost: true))
        end.not_to raise_error
      end

      it 'allows HTTP for 127.0.0.1 redirect_uri' do
        expect do
          described_class.new(valid_attrs.merge(redirect_uri: 'http://127.0.0.1:4000/callback',
                                                allow_insecure_localhost: true))
        end.not_to raise_error
      end

      it 'still rejects HTTP for remote hosts' do
        expect do
          described_class.new(valid_attrs.merge(base_url: 'http://fhir.example.com',
                                                allow_insecure_localhost: true))
        end.to raise_error(Safire::Errors::ConfigurationError, /requires HTTPS.*base_url/)
      end

      it 'logs a warning when the exception is used' do
        described_class.new(valid_attrs.merge(redirect_uri: 'http://localhost:3000/callback',
                                              allow_insecure_localhost: true))

        expect(Safire.logger).to have_received(:warn)
          .with(/allow_insecure_localhost.*development.*HTTPS/i)
      end

      it 'does not log when the flag is enabled but no HTTP loopback URI is configured' do
        described_class.new(valid_attrs.merge(allow_insecure_localhost: true))

        expect(Safire.logger).not_to have_received(:warn)
      end
    end

    context 'when allow_insecure_localhost is not boolean' do
      it 'raises ConfigurationError' do
        expect do
          described_class.new(valid_attrs.merge(allow_insecure_localhost: 'true'))
        end.to raise_error(Safire::Errors::ConfigurationError, /allow_insecure_localhost/)
      end
    end

    context 'with HTTPS URIs' do
      it 'accepts all HTTPS endpoints' do
        expect do
          described_class.new(
            valid_attrs.merge(
              token_endpoint: 'https://fhir.example.com/token',
              authorization_endpoint: 'https://fhir.example.com/auth',
              jwks_uri: 'https://myapp.example.com/.well-known/jwks.json'
            )
          )
        end.not_to raise_error
      end
    end
  end

  # ---------- Issuer defaults to base_url ----------

  describe 'issuer defaulting' do
    it 'defaults issuer to base_url when not provided' do
      config = described_class.new(valid_attrs)
      expect(config.issuer).to eq(valid_attrs[:base_url])
    end

    it 'uses provided issuer when given' do
      config = described_class.new(valid_attrs.merge(issuer: 'https://issuer.example.com'))
      expect(config.issuer).to eq('https://issuer.example.com')
    end
  end

  # ---------- Certificate chain configuration ----------

  describe 'certificate chain configuration' do
    it 'defaults certificate_chain to nil' do
      expect(described_class.new(valid_attrs).certificate_chain).to be_nil
    end

    it 'accepts PEM strings and OpenSSL certificates while preserving order' do
      config = described_class.new(valid_attrs.merge(certificate_chain: [certificate_pem, certificate]))

      expect(config.certificate_chain).to eq([certificate_pem, certificate])
    end

    it 'rejects an empty certificate_chain' do
      expect { described_class.new(valid_attrs.merge(certificate_chain: [])) }
        .to raise_error(Safire::Errors::ConfigurationError, /certificate_chain.*non-empty Array/)
    end

    it 'rejects a non-array certificate_chain without exposing its value' do
      expect { described_class.new(valid_attrs.merge(certificate_chain: certificate_pem)) }
        .to raise_error(Safire::Errors::ConfigurationError) { |error|
          expect(error.message).to include('certificate_chain', 'Array')
          expect(error.message).not_to include('certificate-data')
        }
    end

    it 'rejects unsupported certificate entry types without exposing their values' do
      expect { described_class.new(valid_attrs.merge(certificate_chain: [Object.new])) }
        .to raise_error(Safire::Errors::ConfigurationError) { |error|
          expect(error.message).to include('certificate_chain', 'String', 'OpenSSL::X509::Certificate')
          expect(error.message).not_to match(/#<Object/)
        }
    end

    it 'rejects nil entries within the certificate_chain' do
      expect { described_class.new(valid_attrs.merge(certificate_chain: [certificate_pem, nil])) }
        .to raise_error(Safire::Errors::ConfigurationError, /certificate_chain.*NilClass/)
    end

    it 'rejects certificate objects that cannot be snapshotted' do
      incomplete_certificate = OpenSSL::X509::Certificate.new

      expect { described_class.new(valid_attrs.merge(certificate_chain: [incomplete_certificate])) }
        .to raise_error(Safire::Errors::ConfigurationError, /certificate_chain.*serializable/)
    end

    it 'defensively copies and freezes the chain and PEM strings' do
      source_pem = certificate_pem.dup
      source_chain = [source_pem]
      config = described_class.new(valid_attrs.merge(certificate_chain: source_chain))

      source_pem << 'mutated'
      source_chain << certificate

      expect(config.certificate_chain).to eq([certificate_pem])
      expect(config.certificate_chain).to be_frozen
      expect(config.certificate_chain.first).to be_frozen
    end

    it 'snapshots certificate objects independently of the caller-owned instance' do
      original_der = certificate.to_der
      config = described_class.new(valid_attrs.merge(certificate_chain: [certificate]))

      certificate.serial = 99

      expect(config.certificate_chain.first.to_der).to eq(original_der)
    end

    it 'returns fresh certificate objects so accessor mutations do not alter the stored chain' do
      config = described_class.new(valid_attrs.merge(certificate_chain: [certificate]))
      returned_certificate = config.certificate_chain.first

      returned_certificate.serial = 99

      expect(config.certificate_chain.first.serial.to_i).to eq(1)
      expect(config.certificate_chain.first).not_to equal(returned_certificate)
    end

    it 'does not expose a certificate_chain writer' do
      expect(described_class.new(valid_attrs)).not_to respond_to(:certificate_chain=)
    end
  end

  # ---------- to_hash ----------

  describe '#to_hash' do
    it 'returns a hash with symbolized keys' do
      config = described_class.new(valid_attrs)
      hash = config.to_hash
      expect(hash).to be_a(Hash)
      expect(hash[:base_url]).to eq(valid_attrs[:base_url])
      expect(hash[:client_id]).to eq(valid_attrs[:client_id])
    end

    it 'masks client_secret with [FILTERED]' do
      config = described_class.new(valid_attrs.merge(client_secret: 'super_secret'))
      expect(config.to_hash[:client_secret]).to eq('[FILTERED]')
    end

    it 'masks private_key with [FILTERED]' do
      config = described_class.new(valid_attrs.merge(private_key: 'pem_key_data'))
      expect(config.to_hash[:private_key]).to eq('[FILTERED]')
    end

    it 'masks certificate_chain with [FILTERED]' do
      config = described_class.new(valid_attrs.merge(certificate_chain: [certificate_pem]))
      expect(config.to_hash[:certificate_chain]).to eq('[FILTERED]')
    end

    it 'leaves nil client_secret as nil' do
      config = described_class.new(valid_attrs)
      expect(config.to_hash[:client_secret]).to be_nil
    end

    it 'does not mask non-sensitive attributes' do
      config = described_class.new(valid_attrs)
      expect(config.to_hash[:base_url]).to eq(valid_attrs[:base_url])
    end
  end

  # ---------- inspect ----------

  describe '#inspect' do
    it 'does not expose client_secret in output' do
      config = described_class.new(valid_attrs.merge(client_secret: 'super_secret'))
      expect(config.inspect).not_to include('super_secret')
    end

    it 'shows [FILTERED] in place of client_secret' do
      config = described_class.new(valid_attrs.merge(client_secret: 'super_secret'))
      expect(config.inspect).to include('[FILTERED]')
    end

    it 'does not expose private_key in output' do
      config = described_class.new(valid_attrs.merge(private_key: 'pem_key_data'))
      expect(config.inspect).not_to include('pem_key_data')
    end

    it 'shows [FILTERED] in place of private_key' do
      config = described_class.new(valid_attrs.merge(private_key: 'pem_key_data'))
      expect(config.inspect).to include('[FILTERED]')
    end

    it 'does not expose certificate_chain in output' do
      config = described_class.new(valid_attrs.merge(certificate_chain: [certificate_pem]))
      expect(config.inspect).not_to include('certificate-data')
    end

    it 'shows [FILTERED] in place of certificate_chain' do
      config = described_class.new(valid_attrs.merge(certificate_chain: [certificate_pem]))
      expect(config.inspect).to include('certificate_chain: [FILTERED]')
    end

    it 'includes non-sensitive attributes in output' do
      config = described_class.new(valid_attrs)
      expect(config.inspect).to include('base_url')
      expect(config.inspect).to include('client_id')
    end

    it 'omits nil attributes' do
      config = described_class.new(valid_attrs)
      expect(config.inspect).not_to include('client_secret')
      expect(config.inspect).not_to include('private_key')
      expect(config.inspect).not_to include('certificate_chain')
    end
  end
end
