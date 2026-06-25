require 'spec_helper'

RSpec.describe Safire::Protocols::UdapRegistrationMetadata do
  subject(:metadata) { described_class.new(input, operation:) }

  let(:operation) { :register }
  let(:input) { authorization_code_input }
  let(:authorization_code_input) do
    {
      client_name: 'Example Health App',
      contacts: ['mailto:security@example.com'],
      grant_types: %w[authorization_code refresh_token],
      scope: 'openid system/Patient.rs',
      redirect_uris: ['https://app.example.com/callback'],
      logo_uri: 'https://app.example.com/logo.png'
    }
  end
  let(:client_credentials_input) do
    {
      client_name: 'Example Backend Service',
      contacts: ['mailto:security@example.com'],
      grant_types: ['client_credentials'],
      scope: 'system/Patient.rs'
    }
  end

  def expect_validation_error(attribute, reason = nil, &)
    expect(&).to raise_error(Safire::Errors::ValidationError) do |error|
      expect(error.attribute).to eq(attribute)
      expect(error.reason).to include(reason) if reason
    end
  end

  describe '#to_h' do
    it 'normalizes top-level keys and generates fixed authorization-code metadata' do
      expect(metadata.to_h).to include(
        'client_name' => 'Example Health App',
        'grant_types' => %w[authorization_code refresh_token],
        'response_types' => ['code'],
        'token_endpoint_auth_method' => 'private_key_jwt'
      )
    end

    it 'accepts string-keyed input' do
      string_input = authorization_code_input.stringify_keys

      expect(described_class.new(string_input).to_h['client_name']).to eq('Example Health App')
    end

    it 'generates client-credentials metadata without authorization-only fields' do
      output = described_class.new(client_credentials_input).to_h

      expect(output).to include(
        'grant_types' => ['client_credentials'],
        'token_endpoint_auth_method' => 'private_key_jwt'
      )
      expect(output).not_to include('response_types', 'redirect_uris', 'logo_uri')
    end

    it 'preserves JSON-compatible extension metadata' do
      input[:software_id] = 'app-123'
      input[:custom_extension] = { 'enabled' => true, 'levels' => [1, 2.5, nil] }

      expect(metadata.to_h).to include(
        'software_id' => 'app-123',
        'custom_extension' => { 'enabled' => true, 'levels' => [1, 2.5, nil] }
      )
    end

    it 'returns a defensive copy' do
      first_copy = metadata.to_h
      first_copy['contacts'] << 'mailto:other@example.com'
      first_copy['client_name'].replace('Changed')

      expect(metadata.to_h).to include(
        'client_name' => 'Example Health App',
        'contacts' => ['mailto:security@example.com']
      )
    end

    it 'freezes the value object after construction' do
      expect(metadata).to be_frozen
    end

    it 'does not retain mutable caller input' do
      input[:custom_extension] = { 'roles' => ['reader'] }
      built = metadata

      input[:custom_extension]['roles'] << 'writer'

      expect(built.to_h['custom_extension']).to eq('roles' => ['reader'])
    end
  end

  describe 'input normalization' do
    it 'requires a hash' do
      expect_validation_error(:metadata, 'must be a Hash') do
        described_class.new('not-a-hash')
      end
    end

    it 'rejects non-string and non-symbol top-level keys' do
      input[1] = 'unsupported'

      expect_validation_error(:metadata, 'keys must be strings or symbols') { metadata }
    end

    it 'rejects conflicting symbol and string forms of the same key' do
      input['client_name'] = input[:client_name]

      expect_validation_error(:client_name, 'specified more than once') { metadata }
    end

    it 'rejects an unsupported operation' do
      expect_validation_error(:operation, 'must be register or cancel') do
        described_class.new(input, operation: :update)
      end
    end
  end

  describe 'required metadata' do
    %i[client_name contacts grant_types scope].each do |attribute|
      it "requires #{attribute}" do
        input.delete(attribute)

        expect_validation_error(attribute, 'is required') { metadata }
      end
    end

    it 'requires a non-blank string client_name' do
      input[:client_name] = '  '

      expect_validation_error(:client_name, 'non-blank string') { metadata }
    end

    it 'rejects a non-string client_name' do
      input[:client_name] = 42

      expect_validation_error(:client_name, 'non-blank string') { metadata }
    end

    it 'does not include invalid field values in validation errors' do
      input[:client_name] = Object.new

      expect { metadata }.to raise_error(Safire::Errors::ValidationError) do |error|
        expect(error.message).not_to include(input[:client_name].inspect)
      end
    end

    it 'requires scope to be a non-blank string' do
      input[:scope] = "\t "

      expect_validation_error(:scope, 'non-blank string') { metadata }
    end

    it 'rejects a non-string scope' do
      input[:scope] = ['openid']

      expect_validation_error(:scope, 'non-blank string') { metadata }
    end

    it 'requires scopes to be delimited by spaces' do
      input[:scope] = "openid\tsystem/Patient.rs"

      expect_validation_error(:scope, 'space-delimited OAuth scope string') { metadata }
    end
  end

  describe 'contacts validation' do
    it 'requires a non-empty array' do
      input[:contacts] = []

      expect_validation_error(:contacts, 'non-empty array') { metadata }
    end

    it 'requires every contact to be a string' do
      input[:contacts] = ['mailto:security@example.com', nil]

      expect_validation_error(:contacts, 'URI strings') { metadata }
    end

    it 'requires every contact to be an absolute URI' do
      input[:contacts] = ['mailto:security@example.com', 'not-a-uri']

      expect_validation_error(:contacts, 'valid absolute URI') { metadata }
    end

    it 'requires at least one mailto contact with a valid email address' do
      input[:contacts] = ['https://example.com/security']

      expect_validation_error(:contacts, 'valid mailto email address') { metadata }
    end

    it 'rejects malformed mailto local and domain components' do
      input[:contacts] = ['mailto:@example.com']

      expect_validation_error(:contacts, 'valid absolute URI') { metadata }
    end

    it 'accepts multiple addresses in one mailto URI when they are valid' do
      input[:contacts] = ['mailto:security@example.com,privacy@example.org']

      expect(metadata.to_h['contacts']).to eq(input[:contacts])
    end

    it 'preserves non-mail contact URIs alongside a valid mailto contact' do
      input[:contacts] = ['https://example.com/security', 'mailto:security@example.com']

      expect(metadata.to_h['contacts']).to eq(input[:contacts])
    end
  end

  describe 'grant type validation' do
    it 'requires an array of strings' do
      input[:grant_types] = 'authorization_code'

      expect_validation_error(:grant_types, 'array of strings') { metadata }
    end

    it 'rejects unknown grant types' do
      input[:grant_types] = ['implicit']

      expect_validation_error(:grant_types, 'unsupported grant type') { metadata }
    end

    it 'requires exactly one primary grant type' do
      input[:grant_types] = %w[authorization_code client_credentials]

      expect_validation_error(:grant_types, 'exactly one primary grant') { metadata }
    end

    it 'accepts authorization_code without refresh_token' do
      input[:grant_types] = ['authorization_code']

      expect(metadata.to_h['grant_types']).to eq(['authorization_code'])
    end

    it 'rejects refresh_token without authorization_code' do
      input[:grant_types] = %w[client_credentials refresh_token]
      input.delete(:redirect_uris)
      input.delete(:logo_uri)

      expect_validation_error(:grant_types, 'refresh_token requires authorization_code') { metadata }
    end

    it 'rejects duplicate grant types' do
      input[:grant_types] = %w[authorization_code authorization_code]

      expect_validation_error(:grant_types, 'duplicate values') { metadata }
    end
  end

  describe 'authorization-code metadata' do
    it 'requires redirect_uris' do
      input.delete(:redirect_uris)

      expect_validation_error(:redirect_uris, 'is required') { metadata }
    end

    it 'requires a non-empty array of redirect URI strings' do
      input[:redirect_uris] = []

      expect_validation_error(:redirect_uris, 'non-empty array') { metadata }
    end

    it 'rejects a non-string redirect URI' do
      input[:redirect_uris] = ['https://app.example.com/callback', nil]

      expect_validation_error(:redirect_uris, 'non-empty array of strings') { metadata }
    end

    it 'requires every redirect URI to use HTTPS' do
      input[:redirect_uris] = ['http://app.example.com/callback']

      expect_validation_error(:redirect_uris, 'absolute HTTPS URI') { metadata }
    end

    it 'rejects HTTP localhost by default' do
      input[:redirect_uris] = ['http://localhost/callback']

      expect_validation_error(:redirect_uris, 'absolute HTTPS URI') { metadata }
    end

    it 'requires logo_uri' do
      input.delete(:logo_uri)

      expect_validation_error(:logo_uri, 'is required') { metadata }
    end

    it 'requires an HTTPS logo URI' do
      input[:logo_uri] = 'http://app.example.com/logo.png'

      expect_validation_error(:logo_uri, 'absolute HTTPS URI') { metadata }
    end

    it 'requires a supported image extension' do
      input[:logo_uri] = 'https://app.example.com/logo.svg'

      expect_validation_error(:logo_uri, 'PNG, JPEG, JPG, or GIF') { metadata }
    end

    it 'accepts a case-insensitive image extension before a query string' do
      input[:logo_uri] = 'https://app.example.com/logo.JPEG?version=2'

      expect(metadata.to_h['logo_uri']).to eq(input[:logo_uri])
    end
  end

  describe 'local development URI policy' do
    before { allow(Safire.logger).to receive(:warn) }

    it 'accepts HTTP localhost redirect and logo URIs when explicitly enabled' do
      input[:redirect_uris] = ['http://localhost:3000/callback']
      input[:logo_uri] = 'http://localhost:3000/logo.png'

      output = described_class.new(input, allow_insecure_localhost: true).to_h

      expect(output).to include(
        'redirect_uris' => ['http://localhost:3000/callback'],
        'logo_uri' => 'http://localhost:3000/logo.png'
      )
    end

    it 'accepts HTTP on 127.0.0.1 when explicitly enabled' do
      input[:redirect_uris] = ['http://127.0.0.1:3000/callback']
      input[:logo_uri] = 'http://127.0.0.1:3000/logo.gif'

      expect { described_class.new(input, allow_insecure_localhost: true) }.not_to raise_error
    end

    it 'still rejects HTTP on a remote host' do
      input[:redirect_uris] = ['http://app.example.com/callback']

      expect_validation_error(:redirect_uris, 'absolute HTTPS URI') do
        described_class.new(input, allow_insecure_localhost: true)
      end
    end

    it 'logs one development-only warning when insecure loopback URIs are accepted' do
      input[:redirect_uris] = ['http://localhost:3000/callback']
      input[:logo_uri] = 'http://localhost:3000/logo.png'

      described_class.new(input, allow_insecure_localhost: true)

      expect(Safire.logger).to have_received(:warn)
        .with(/allow_insecure_localhost.*development.*non-conformant/i).once
    end

    it 'does not warn when the policy is enabled but all URIs use HTTPS' do
      described_class.new(input, allow_insecure_localhost: true)

      expect(Safire.logger).not_to have_received(:warn)
    end

    it 'requires a literal boolean policy value' do
      expect_validation_error(:allow_insecure_localhost, 'must be true or false') do
        described_class.new(input, allow_insecure_localhost: 'true')
      end
    end
  end

  describe 'non-authorization registration metadata' do
    let(:input) { client_credentials_input }

    it 'rejects redirect_uris' do
      input[:redirect_uris] = ['https://app.example.com/callback']

      expect_validation_error(:redirect_uris, 'must be absent') { metadata }
    end

    it 'rejects logo_uri' do
      input[:logo_uri] = 'https://app.example.com/logo.png'

      expect_validation_error(:logo_uri, 'must be absent') { metadata }
    end
  end

  describe 'reserved fields' do
    reserved_fields = %i[
      iss sub aud iat exp jti software_statement certifications udap
      response_types token_endpoint_auth_method
    ]

    reserved_fields.each do |attribute|
      it "rejects caller-supplied #{attribute}" do
        input[attribute] = 'caller-controlled'

        expect_validation_error(attribute, 'reserved') { metadata }
      end
    end
  end

  describe 'extension metadata' do
    invalid_values = {
      symbol: :reader,
      object: Object.new,
      non_finite_number: Float::INFINITY,
      nested_symbol_key: { role: 'reader' }
    }

    invalid_values.each do |label, value|
      it "rejects a #{label} extension value" do
        input[:custom_extension] = value

        expect_validation_error(:custom_extension, 'JSON-compatible') { metadata }
      end
    end

    it 'rejects recursive extension values without leaking a runtime error' do
      recursive_value = []
      recursive_value << recursive_value
      input[:custom_extension] = recursive_value

      expect_validation_error(:custom_extension, 'recursive values') { metadata }
    end
  end

  describe 'cancellation metadata' do
    let(:operation) { :cancel }
    let(:input) { authorization_code_input.except(:grant_types) }

    it 'injects an empty grant_types array' do
      expect(metadata.to_h).to include(
        'grant_types' => [],
        'token_endpoint_auth_method' => 'private_key_jwt'
      )
    end

    it 'excludes authorization-only metadata' do
      expect(metadata.to_h).not_to include('redirect_uris', 'logo_uri', 'response_types')
    end

    it 'rejects caller-supplied grant_types' do
      input[:grant_types] = []

      expect_validation_error(:grant_types, 'must be omitted') { metadata }
    end

    it 'still requires client_name, contacts, and scope' do
      input.delete(:contacts)

      expect_validation_error(:contacts, 'is required') { metadata }
    end
  end
end
