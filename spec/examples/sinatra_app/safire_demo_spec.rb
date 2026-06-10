require 'rack/mock'
require 'spec_helper'

original_rack_env = ENV.fetch('RACK_ENV', nil)
ENV['RACK_ENV'] = 'test'
require_relative '../../../examples/sinatra_app/app'
original_rack_env.nil? ? ENV.delete('RACK_ENV') : ENV['RACK_ENV'] = original_rack_env

RSpec.describe SafireDemo do
  let(:request) { Rack::MockRequest.new(described_class) }
  let(:smart_server) { build_server('smart-only', protocols: ['smart']) }
  let(:udap_server) { build_server('udap-only', protocols: ['udap'], client_id: nil) }

  def build_server(id, protocols:, client_id: 'client-123')
    FhirServer.new(
      id: id,
      name: id.tr('-', ' ').split.map(&:capitalize).join(' '),
      base_url: "https://#{id}.example.com/fhir",
      client_id: client_id,
      scopes: %w[openid profile],
      protocols: protocols
    )
  end

  def response_for(method, path)
    request.request(method.to_s.upcase, path)
  end

  before do
    allow(FhirServer).to receive(:find).with('smart-only').and_return(smart_server)
    allow(FhirServer).to receive(:find).with('udap-only').and_return(udap_server)
    allow(FhirServer).to receive(:find_by_base_url).with(udap_server.base_url).and_return(udap_server)
  end

  describe 'protocol guards' do
    [
      [:get, '/demo/udap-only/discovery'],
      [:get, '/demo/udap-only/authorize'],
      [:post, '/demo/udap-only/authorize'],
      [:get, '/demo/udap-only/backend-token'],
      [:post, '/demo/udap-only/backend-token'],
      [:get, '/demo/udap-only/refresh']
    ].each do |method, path|
      it "redirects #{method.upcase} #{path} for a UDAP-only server" do
        response = response_for(method, path)

        expect(response.status).to be_between(300, 399)
        expect(response.location).to end_with('/servers/udap-only')
      end
    end

    it 'redirects UDAP discovery for a SMART-only server' do
      response = response_for(:get, '/demo/smart-only/udap-discovery')

      expect(response.status).to be_between(300, 399)
      expect(response.location).to end_with('/servers/smart-only')
    end

    it 'redirects EHR launch for a UDAP-only server' do
      response = response_for(:get, '/launch?launch=abc&iss=https%3A%2F%2Fudap-only.example.com%2Ffhir')

      expect(response.status).to be_between(300, 399)
      expect(response.location).to end_with('/servers/udap-only')
    end
  end
end
