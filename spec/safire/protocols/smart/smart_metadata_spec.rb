require 'spec_helper'

RSpec.describe Safire::Protocols::Smart::SmartMetadata do
  let(:smart_metadata) do
    root = File.expand_path '../../..', File.dirname(File.absolute_path(__FILE__))
    data = JSON.parse(File.read(File.join(root, 'fixtures', 'smart_config.json')))
    described_class.new(data)
  end

  describe '#supports_ehr_launch?' do
    it 'returns true if "launch-ehr" is in capabilities' do
      expect(smart_metadata.supports_ehr_launch?).to be(true)
    end

    it 'returns false if "launch-ehr" is not in capabilities' do
      smart_metadata.capabilities.delete('launch-ehr')
      expect(smart_metadata.supports_ehr_launch?).to be(false)
    end
  end

  describe '#supports_standalone_launch?' do
    it 'returns true if "launch-standalone" is in capabilities' do
      expect(smart_metadata.supports_standalone_launch?).to be(true)
    end

    it 'returns false if "launch-standalone" is not in capabilities' do
      smart_metadata.capabilities.delete('launch-standalone')
      expect(smart_metadata.supports_standalone_launch?).to be(false)
    end
  end

  describe 'supportd_post_based_authorization?' do
    it 'returns true if "authorize-post" is in capabilities' do
      expect(smart_metadata.supports_post_based_authorization?).to be(true)
    end

    it 'returns false if "authorize-post" is not in capabilities' do
      smart_metadata.capabilities.delete('authorize-post')
      expect(smart_metadata.supports_post_based_authorization?).to be(false)
    end
  end

  describe '#supports_public_clients?' do
    it 'returns true if "client-public" is in capabilities' do
      expect(smart_metadata.supports_public_clients?).to be(true)
    end

    it 'returns false if "client-public" is not in capabilities' do
      smart_metadata.capabilities.delete('client-public')
      expect(smart_metadata.supports_public_clients?).to be(false)
    end
  end

  describe '#supports_confidential_symmetric_clients?' do
    it 'returns true if "client-confidential-symmetric" is in capabilities' do
      expect(smart_metadata.supports_confidential_symmetric_clients?).to be(true)
    end

    it 'returns false if "client-confidential-symmetric" is not in capabilities' do
      smart_metadata.capabilities.delete('client-confidential-symmetric')
      expect(smart_metadata.supports_confidential_symmetric_clients?).to be(false)
    end
  end

  describe '#supports_confidential_asymmetric_clients?' do
    it 'returns true if "client-confidential-asymmetric" is in capabilities' do
      expect(smart_metadata.supports_confidential_asymmetric_clients?).to be(true)
    end

    it 'returns false if "client-confidential-asymmetric" is not in capabilities' do
      smart_metadata.capabilities.delete('client-confidential-asymmetric')
      expect(smart_metadata.supports_confidential_asymmetric_clients?).to be(false)
    end
  end

  describe '#supports_openid_connect?' do
    it 'returns true if "sso-openid-connect" is in capabilities' do
      expect(smart_metadata.supports_openid_connect?).to be(true)
    end

    it 'returns false if "sso-openid-connect" is not in capabilities' do
      smart_metadata.capabilities.delete('sso-openid-connect')
      expect(smart_metadata.supports_openid_connect?).to be(false)
    end
  end
end
