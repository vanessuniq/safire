require 'spec_helper'

RSpec.describe Safire::Protocols::Smart::Discovery do
  let(:base_url) { 'https://example.com' }
  let(:smart_config) do
    root = File.expand_path '../../..', File.dirname(File.absolute_path(__FILE__))
    File.read(File.join(root, 'fixtures', 'smart_config.json'))
  end
  let(:parsed_smart_config) { JSON.parse(smart_config) }
  let(:discovery) { described_class.new(base_url) }

  describe '#discover' do
    before do
      stub_request(:get, 'https://example.com/.well-known/smart-configuration')
        .to_return(
          status: 200,
          body: smart_config,
          headers: { 'Content-Type' => 'aplication/json' }
        )
    end

    it 'fetches and parses SMART configuration' do
      metadata = discovery.discover

      parsed_smart_config.each do |k, v|
        expect(metadata.send(k)).to eq(v)
      end
    end

    context 'when configuration is missing required fields' do
      let(:smart_config) { { authorization_endpoint: 'https://example.com/auth' }.to_json }

      it 'raises a DiscoveryError' do
        expect { discovery.discover }.to raise_error(
          Safire::Errors::DiscoveryError, /Missing required SMART configuration fields/
        )
      end
    end
  end
end
