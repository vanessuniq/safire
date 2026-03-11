require 'spec_helper'

RSpec.describe Safire::HTTPClient do
  let(:base_url) { 'https://api.example.com' }
  let(:adapter) { :test }
  let(:client) { described_class.new(base_url:) }

  describe '#initialize' do
    it 'sets default headers with User-Agent and Accept' do
      request = stub_request(:get, base_url)
                .with(headers: {
                        'User-Agent' => "Safire v#{Safire::VERSION}",
                        'Accept' => 'application/json'
                      })
                .to_return(status: 200, body: {}.to_json)

      client.get

      expect(request).to have_been_made.once
    end

    context 'when a custom user_agent is configured' do
      before do
        allow(Safire).to receive_messages(
          configuration: instance_double(Safire::Configuration, user_agent: 'MyApp/1.0 Safire', log_http: true),
          logger: Logger.new(StringIO.new)
        )
      end

      it 'uses the configured user_agent in the User-Agent header' do
        request = stub_request(:get, base_url)
                  .with(headers: { 'User-Agent' => 'MyApp/1.0 Safire' })
                  .to_return(status: 200, body: {}.to_json)

        described_class.new(base_url:).get

        expect(request).to have_been_made.once
      end
    end

    it 'uses url_encoded request format by default' do
      expect(client.instance_variable_get(:@request_format)).to eq(:url_encoded)
    end

    it 'accepts custom request format' do
      json_client = described_class.new(base_url: base_url, request_format: :json)
      expect(json_client.instance_variable_get(:@request_format)).to eq(:json)
    end

    it 'converts request format to symbol' do
      json_client = described_class.new(base_url: base_url, request_format: 'json')
      expect(json_client.instance_variable_get(:@request_format)).to eq(:json)
    end

    it 'uses Faraday default adapter when adapter not provided' do
      expect(client.instance_variable_get(:@adapter)).to eq(Faraday.default_adapter)
    end

    it 'accepts custom SSL options' do
      ssl_options = { verify: false, ca_file: '/path/to/ca' }
      ssl_client = described_class.new(base_url: base_url, ssl_options: ssl_options)

      connection_options = ssl_client.instance_variable_get(:@connection).ssl

      expect(connection_options.verify?).to be(false)
      expect(connection_options.ca_file).to eq('/path/to/ca')
    end
  end

  describe 'SSL verification warning' do
    before { allow(Safire.logger).to receive(:warn) }

    context 'when ssl_options: { verify: false }' do
      it 'logs a security warning' do
        described_class.new(base_url:, ssl_options: { verify: false })
        expect(Safire.logger).to have_received(:warn)
          .with(/verify.*false.*TLS.*verification/i)
      end
    end

    context 'when verify is not explicitly false' do
      it 'does not warn with no ssl_options' do
        described_class.new(base_url:)
        expect(Safire.logger).not_to have_received(:warn)
      end

      it 'does not warn with verify: true' do
        described_class.new(base_url:, ssl_options: { verify: true })
        expect(Safire.logger).not_to have_received(:warn)
      end

      it 'does not warn with other ssl_options' do
        described_class.new(base_url:, ssl_options: { ca_file: '/path/to/ca' })
        expect(Safire.logger).not_to have_received(:warn)
      end
    end
  end

  describe 'HTTP request logging' do
    let(:log_output) { StringIO.new }
    let(:test_logger) { Logger.new(log_output) }

    context 'when log_http is true (default)' do
      before do
        allow(Safire).to receive_messages(
          configuration: instance_double(Safire::Configuration, log_http: true, user_agent: "Safire v#{Safire::VERSION}"),
          logger: test_logger
        )
      end

      let(:logging_client) { described_class.new(base_url:) }

      it 'logs HTTP requests' do
        stub_request(:get, base_url).to_return(status: 200, body: {}.to_json)
        logging_client.get
        expect(log_output.string).not_to be_empty
      end

      it 'filters the Authorization header value' do
        stub_request(:post, "#{base_url}/token").to_return(status: 200, body: {}.to_json)
        logging_client.post('/token', headers: { 'Authorization' => 'Basic c2VjcmV0' })
        expect(log_output.string).to include('[FILTERED]')
        expect(log_output.string).not_to include('c2VjcmV0')
      end

      it 'does not log request or response bodies' do
        stub_request(:post, "#{base_url}/token")
          .to_return(status: 200, body: { access_token: 'secret_token' }.to_json)
        logging_client.post('/token', body: { client_secret: 'my_secret' })
        expect(log_output.string).not_to include('my_secret')
        expect(log_output.string).not_to include('secret_token')
      end
    end

    context 'when log_http is false' do
      before do
        allow(Safire).to receive_messages(
          configuration: instance_double(Safire::Configuration, log_http: false, user_agent: "Safire v#{Safire::VERSION}"),
          logger: test_logger
        )
      end

      let(:quiet_client) { described_class.new(base_url:) }

      it 'does not log HTTP requests' do
        stub_request(:get, base_url).to_return(status: 200, body: {}.to_json)
        quiet_client.get
        expect(log_output.string).to be_empty
      end
    end
  end

  describe 'redirect safety' do
    it 'follows a redirect to an HTTPS URL' do
      stub_request(:get, base_url)
        .to_return(status: 301, headers: { 'Location' => "#{base_url}/new" })
      stub_request(:get, "#{base_url}/new")
        .to_return(status: 200, body: {}.to_json)

      expect { client.get }.not_to raise_error
    end

    it 'raises NetworkError when redirect points to HTTP on a non-localhost host' do
      stub_request(:get, base_url)
        .to_return(status: 301, headers: { 'Location' => 'http://api.example.com/new' })

      expect { client.get }
        .to raise_error(Safire::Errors::NetworkError, /non-HTTPS.*blocked/i)
    end

    it 'follows a redirect to HTTP localhost' do
      stub_request(:get, base_url)
        .to_return(status: 301, headers: { 'Location' => 'http://localhost:3000/callback' })
      stub_request(:get, 'http://localhost:3000/callback')
        .to_return(status: 200, body: {}.to_json)

      expect { client.get }.not_to raise_error
    end
  end

  describe 'integration scenarios' do
    it 'handles full CRUD cycle' do
      body = { id: 1, name: 'Item 1' }.to_json
      # Create
      stub_request(:post, "#{base_url}/items")
        .with(body: { name: 'Item 1' })
        .to_return(status: 201, body:)

      # Read
      stub_request(:get, "#{base_url}/items/1")
        .to_return(status: 200, body:)

      # Update
      stub_request(:put, "#{base_url}/items/1")
        .with(body: { name: 'Updated Item' })
        .to_return(status: 200, body: { id: 1, name: 'Updated Item' }.to_json)

      # Delete
      stub_request(:delete, "#{base_url}/items/1")
        .to_return(status: 204)

      create_response = client.post('/items', body: { name: 'Item 1' })
      expect(create_response.status).to eq(201)
      expect(create_response.body).to eq(body)

      read_response = client.get('/items/1')
      expect(read_response.status).to eq(200)

      update_response = client.put('/items/1', body: { name: 'Updated Item' })
      expect(update_response.status).to eq(200)

      delete_response = client.delete('/items/1')
      expect(delete_response.status).to eq(204)
    end

    it 'handles request with all options combined' do
      body = { success: true }.to_json
      stub_request(:post, "#{base_url}/complex")
        .with(
          query: { format: 'json', version: 'v2' },
          headers: { 'Authorization' => 'Bearer token', 'X-Request-ID' => '123' },
          body: { data: { key: 'value' } }
        )
        .to_return(status: 200, body:)

      response = client.post(
        '/complex',
        body: { data: { key: 'value' } },
        params: { format: 'json', version: 'v2' },
        headers: { 'Authorization' => 'Bearer token', 'X-Request-ID' => '123' }
      )

      expect(response.status).to eq(200)
      expect(response.body).to eq(body)
    end
  end
end
