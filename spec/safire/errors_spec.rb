require 'spec_helper'

RSpec.describe Safire::Errors do
  describe Safire::Errors::Error do
    it 'is a StandardError' do
      expect(described_class.superclass).to eq(StandardError)
    end

    it 'can be raised and rescued as StandardError' do
      expect { raise described_class }.to raise_error(StandardError)
    end
  end

  describe Safire::Errors::ConfigurationError do
    it 'is a Safire::Errors::Error' do
      expect(described_class.superclass).to eq(Safire::Errors::Error)
    end

    context 'with missing_attributes' do
      subject(:error) { described_class.new(missing_attributes: %i[base_url client_id]) }

      it 'exposes missing_attributes' do
        expect(error.missing_attributes).to eq(%i[base_url client_id])
      end

      it 'builds a message from missing_attributes' do
        expect(error.message).to match(/base_url/)
        expect(error.message).to match(/client_id/)
      end

      it 'does not require a message argument' do
        expect { described_class.new(missing_attributes: [:base_url]) }.not_to raise_error
      end
    end

    context 'with invalid_attribute' do
      subject(:error) do
        described_class.new(
          invalid_attribute: :method,
          invalid_value: :ftp,
          valid_values: %i[get post]
        )
      end

      it 'exposes invalid_attribute, invalid_value, and valid_values' do
        expect(error.invalid_attribute).to eq(:method)
        expect(error.invalid_value).to eq(:ftp)
        expect(error.valid_values).to eq(%i[get post])
      end

      it 'builds a message from the invalid attribute context' do
        expect(error.message).to match(/method/)
        expect(error.message).to match(/ftp/)
        expect(error.message).to match(/get/)
        expect(error.message).to match(/post/)
      end
    end

    context 'with no arguments' do
      it 'has a generic fallback message' do
        expect(described_class.new.message).to eq('Configuration error')
      end
    end
  end

  describe Safire::Errors::DiscoveryError do
    it 'is a Safire::Errors::Error' do
      expect(described_class.superclass).to eq(Safire::Errors::Error)
    end

    context 'with endpoint only' do
      subject(:error) { described_class.new(endpoint: 'https://fhir.example.com/.well-known/smart-configuration') }

      it 'exposes endpoint' do
        expect(error.endpoint).to eq('https://fhir.example.com/.well-known/smart-configuration')
      end

      it 'builds a message including the endpoint' do
        expect(error.message).to match(/fhir\.example\.com/)
      end

      it 'has nil status' do
        expect(error.status).to be_nil
      end
    end

    context 'with endpoint and status' do
      subject(:error) { described_class.new(endpoint: 'https://fhir.example.com/.well-known/smart-configuration', status: 404) }

      it 'exposes status' do
        expect(error.status).to eq(404)
      end

      it 'includes status in the message' do
        expect(error.message).to match(/404/)
      end
    end
  end

  describe Safire::Errors::TokenError do
    it 'is a Safire::Errors::Error' do
      expect(described_class.superclass).to eq(Safire::Errors::Error)
    end

    context 'when HTTP failure (status + OAuth2 fields)' do
      subject(:error) do
        described_class.new(status: 401, error_code: 'invalid_grant', error_description: 'Code expired')
      end

      it 'exposes status, error_code, and error_description' do
        expect(error.status).to eq(401)
        expect(error.error_code).to eq('invalid_grant')
        expect(error.error_description).to eq('Code expired')
      end

      it 'builds a message from typed attributes' do
        expect(error.message).to match(/401/)
        expect(error.message).to match(/invalid_grant/)
        expect(error.message).to match(/Code expired/)
      end
    end

    context 'when structural failure (missing access_token)' do
      subject(:error) { described_class.new(received_fields: %w[token_type expires_in]) }

      it 'exposes received_fields' do
        expect(error.received_fields).to eq(%w[token_type expires_in])
      end

      it 'builds a message with field names but no values' do
        expect(error.message).to match(/token_type/)
        expect(error.message).to match(/expires_in/)
      end

      it 'does not include sensitive values in the message' do
        error_with_values = described_class.new(received_fields: %w[token_type])
        expect(error_with_values.message).not_to match(/Bearer/)
      end
    end

    context 'with no arguments' do
      it 'has a generic fallback message' do
        expect(described_class.new.message).to match(/[Tt]oken/)
      end
    end
  end

  describe Safire::Errors::NetworkError do
    it 'is a Safire::Errors::Error' do
      expect(described_class.superclass).to eq(Safire::Errors::Error)
    end

    context 'with status and OAuth2 fields' do
      subject(:error) do
        described_class.new(status: 503, error_code: 'server_error', error_description: 'Service unavailable')
      end

      it 'exposes status, error_code, and error_description' do
        expect(error.status).to eq(503)
        expect(error.error_code).to eq('server_error')
        expect(error.error_description).to eq('Service unavailable')
      end

      it 'builds a message from typed attributes' do
        expect(error.message).to match(/503/)
        expect(error.message).to match(/server_error/)
      end
    end

    context 'with no arguments' do
      it 'has a generic fallback message' do
        expect(described_class.new.message).to match(/[Hh][Tt][Tt][Pp]|[Nn]etwork/)
      end
    end
  end

  describe 'rescue hierarchy' do
    it 'can rescue all typed errors as Safire::Errors::Error' do
      [
        Safire::Errors::ConfigurationError.new,
        Safire::Errors::DiscoveryError.new(endpoint: 'https://example.com'),
        Safire::Errors::TokenError.new,
        Safire::Errors::NetworkError.new
      ].each do |error|
        expect(error).to be_a(Safire::Errors::Error)
      end
    end
  end
end
