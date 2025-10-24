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
