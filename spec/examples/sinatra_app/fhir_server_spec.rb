require 'spec_helper'

require_relative '../../../examples/sinatra_app/models/fhir_server'

RSpec.describe FhirServer do
  let(:base_attrs) do
    {
      name: 'Example FHIR',
      base_url: 'https://fhir.example.com',
      client_id: 'client-123',
      udap_client_id: 'udap-client-456',
      scopes: %w[openid profile]
    }
  end

  before do
    allow(described_class).to receive(:load_all).and_return({})
  end

  describe '#protocols' do
    it 'defaults existing records to SMART' do
      server = described_class.new(base_attrs.except(:protocols, :udap_client_id))

      expect(server.protocols).to eq(['smart'])
      expect(server.udap_client_id).to be_nil
      expect(server).to be_supports_smart
      expect(server).not_to be_supports_udap
    end

    it 'normalizes multi-protocol values from form params' do
      server = described_class.new(base_attrs.merge(protocols: ['smart', 'udap', '', 'smart']))

      expect(server.protocols).to eq(%w[smart udap])
      expect(server.protocols_display).to eq('SMART App Launch, UDAP Security')
    end

    it 'accepts a single legacy protocol value' do
      server = described_class.new(base_attrs.merge(protocol: 'udap'))

      expect(server.protocols).to eq(['udap'])
      expect(server).not_to be_supports_smart
      expect(server).to be_supports_udap
    end

    it 'normalizes protocol assignments after initialization' do
      server = described_class.new(base_attrs)

      server.protocols = [' udap ', 'udap', '']

      expect(server.protocols).to eq(['udap'])
    end
  end

  describe '#valid?' do
    it 'requires client_id for SMART servers' do
      server = described_class.new(base_attrs.merge(client_id: nil, protocols: ['smart']))

      expect(server).not_to be_valid
      expect(server.errors).to include('Client ID is required for SMART App Launch')
    end

    it 'does not require client_id for UDAP-only discovery servers' do
      server = described_class.new(base_attrs.merge(client_id: nil, protocols: ['udap']))

      expect(server).to be_valid
    end

    it 'does not require udap_client_id for UDAP servers' do
      server = described_class.new(base_attrs.merge(udap_client_id: nil, protocols: ['udap']))

      expect(server).to be_valid
    end

    it 'requires at least one supported protocol' do
      server = described_class.new(base_attrs.merge(protocols: []))

      expect(server).not_to be_valid
      expect(server.errors).to include('At least one protocol is required')
    end

    it 'rejects unsupported protocol values' do
      server = described_class.new(base_attrs.merge(protocols: %w[smart foo]))

      expect(server).not_to be_valid
      expect(server.errors).to include('Protocols must be one or more of: smart, udap')
    end
  end

  describe '#to_hash' do
    it 'persists SMART and UDAP client identifiers separately' do
      server = described_class.new(base_attrs.merge(protocols: %w[smart udap]))

      expect(server.to_hash).to include(
        'client_id' => 'client-123',
        'udap_client_id' => 'udap-client-456'
      )
    end
  end
end
