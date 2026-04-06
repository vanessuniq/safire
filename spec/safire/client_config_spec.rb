require 'spec_helper'

RSpec.describe Safire::ClientConfig do
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

    context 'with localhost exception' do
      it 'allows HTTP for localhost base_url' do
        expect do
          described_class.new(valid_attrs.merge(base_url: 'http://localhost:3000/fhir'))
        end.not_to raise_error
      end

      it 'allows HTTP for 127.0.0.1 base_url' do
        expect do
          described_class.new(valid_attrs.merge(base_url: 'http://127.0.0.1:8080/fhir'))
        end.not_to raise_error
      end

      it 'allows HTTP for localhost redirect_uri' do
        expect do
          described_class.new(valid_attrs.merge(redirect_uri: 'http://localhost:3000/callback'))
        end.not_to raise_error
      end

      it 'allows HTTP for localhost token_endpoint' do
        expect do
          described_class.new(valid_attrs.merge(token_endpoint: 'http://localhost:9000/token'))
        end.not_to raise_error
      end

      it 'allows HTTP for 127.0.0.1 redirect_uri' do
        expect do
          described_class.new(valid_attrs.merge(redirect_uri: 'http://127.0.0.1:4000/callback'))
        end.not_to raise_error
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

    it 'includes non-sensitive attributes in output' do
      config = described_class.new(valid_attrs)
      expect(config.inspect).to include('base_url')
      expect(config.inspect).to include('client_id')
    end

    it 'omits nil attributes' do
      config = described_class.new(valid_attrs)
      expect(config.inspect).not_to include('client_secret')
      expect(config.inspect).not_to include('private_key')
    end
  end
end
