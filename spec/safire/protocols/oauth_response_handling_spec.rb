require 'spec_helper'

RSpec.describe Safire::Protocols::OAuthResponseHandling do
  subject(:handler) { handler_class.new }

  let(:handler_class) do
    Class.new do
      include Safire::Protocols::OAuthResponseHandling

      def parse_registration(body)
        parse_registration_response(body)
      end

      def build_oauth_error(faraday_error, error_class)
        oauth_error_from(faraday_error, error_class)
      end
    end
  end

  describe '#parse_registration_response' do
    it 'returns a valid string-keyed registration response' do
      body = { 'client_id' => 'client-123', 'client_name' => 'Example App' }

      expect(handler.parse_registration(body)).to eq(body)
    end

    it 'normalizes symbol keys to strings' do
      body = {
        client_id: 'client-123',
        redirect_uris: [{ uri: 'https://app.example.com/callback' }]
      }

      expect(handler.parse_registration(body)).to eq(
        'client_id' => 'client-123',
        'redirect_uris' => [{ 'uri' => 'https://app.example.com/callback' }]
      )
    end

    it 'raises RegistrationError with field names when client_id is missing' do
      expect { handler.parse_registration('client_name' => 'Example App', 'expires_at' => 1234) }
        .to raise_error(Safire::Errors::RegistrationError) { |error|
          expect(error.received_fields).to contain_exactly('client_name', 'expires_at')
          expect(error.message).not_to include('Example App', '1234')
        }
    end

    it 'rejects a blank client_id' do
      expect { handler.parse_registration('client_id' => '  ') }
        .to raise_error(
          Safire::Errors::RegistrationError,
          /client_id must be a non-blank string/
        )
    end

    it 'rejects a non-string client_id' do
      expect { handler.parse_registration('client_id' => 123) }
        .to raise_error(
          Safire::Errors::RegistrationError,
          /client_id must be a non-blank string/
        )
    end

    it 'rejects a nil client_id' do
      expect { handler.parse_registration('client_id' => nil) }
        .to raise_error(
          Safire::Errors::RegistrationError,
          /client_id must be a non-blank string/
        )
    end

    it 'rejects a non-object JSON value' do
      expect { handler.parse_registration(%w[not an object]) }
        .to raise_error(Safire::Errors::RegistrationError, /not a JSON object/)
    end

    it 'rejects a malformed JSON body that was not parsed by middleware' do
      expect { handler.parse_registration('{not-json') }
        .to raise_error(Safire::Errors::RegistrationError, /not a JSON object/)
    end
  end

  describe '#oauth_error_from' do
    it 'extracts OAuth error fields from a parsed Hash' do
      faraday_error = instance_double(
        Faraday::Error,
        response: {
          status: 400,
          body: {
            'error' => 'invalid_client_metadata',
            'error_description' => 'Client metadata is invalid'
          }
        }
      )

      error = handler.build_oauth_error(faraday_error, Safire::Errors::RegistrationError)

      expect(error.status).to eq(400)
      expect(error.error_code).to eq('invalid_client_metadata')
      expect(error.error_description).to eq('Client metadata is invalid')
    end

    it 'extracts OAuth error fields from a JSON string' do
      faraday_error = instance_double(
        Faraday::Error,
        response: {
          status: 400,
          body: {
            error: 'invalid_redirect_uri',
            error_description: 'Redirect URI is invalid'
          }.to_json
        }
      )

      error = handler.build_oauth_error(faraday_error, Safire::Errors::RegistrationError)

      expect(error.error_code).to eq('invalid_redirect_uri')
      expect(error.error_description).to eq('Redirect URI is invalid')
    end

    it 'preserves UDAP registration error codes' do
      faraday_error = instance_double(
        Faraday::Error,
        response: {
          status: 400,
          body: {
            'error' => 'invalid_software_statement',
            'error_description' => 'The software statement is invalid'
          }
        }
      )

      error = handler.build_oauth_error(faraday_error, Safire::Errors::RegistrationError)

      expect(error.error_code).to eq('invalid_software_statement')
      expect(error.error_description).to eq('The software statement is invalid')
    end

    it 'preserves an unapproved_software_statement UDAP error code' do
      faraday_error = instance_double(
        Faraday::Error,
        response: {
          status: 401,
          body: {
            'error' => 'unapproved_software_statement',
            'error_description' => 'Software statement is not approved for this community'
          }
        }
      )

      error = handler.build_oauth_error(faraday_error, Safire::Errors::RegistrationError)

      expect(error.error_code).to eq('unapproved_software_statement')
      expect(error.error_description).to eq('Software statement is not approved for this community')
    end

    it 'returns a status-only error for malformed JSON' do
      faraday_error = instance_double(
        Faraday::Error,
        response: { status: 502, body: '{not-json' }
      )

      error = handler.build_oauth_error(faraday_error, Safire::Errors::RegistrationError)

      expect(error.status).to eq(502)
      expect(error.error_code).to be_nil
      expect(error.error_description).to be_nil
    end

    it 'returns a status-only error for a non-object JSON value' do
      faraday_error = instance_double(
        Faraday::Error,
        response: { status: 400, body: ['invalid_request'] }
      )

      error = handler.build_oauth_error(faraday_error, Safire::Errors::RegistrationError)

      expect(error.status).to eq(400)
      expect(error.error_code).to be_nil
      expect(error.error_description).to be_nil
    end
  end
end
