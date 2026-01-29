require 'spec_helper'

RSpec.describe Safire::Protocols::SmartMetadata do
  let(:full_metadata) do
    root = File.expand_path '../..', File.dirname(File.absolute_path(__FILE__))
    JSON.parse(File.read(File.join(root, 'fixtures', 'smart_config.json')))
  end

  let(:smart_metadata) { described_class.new(full_metadata) }

  describe '#valid?' do
    it 'returns true if all required fields are present' do
      expect(smart_metadata.valid?).to be(true)
    end

    it 'returns false if a required field is missing' do
      smart_metadata = described_class.new({ authorization_endpoint: 'example.com' })

      expect(smart_metadata.valid?).to be(false)
    end
  end

  describe '#supports_ehr_launch?' do
    it 'returns true if capability and authorization_endpoint are present' do
      expect(smart_metadata.supports_ehr_launch?).to be(true)
    end

    it 'returns false if "launch-ehr" capability is missing' do
      smart_metadata.capabilities.delete('launch-ehr')
      expect(smart_metadata.supports_ehr_launch?).to be(false)
    end

    it 'returns false if authorization_endpoint is missing' do
      data = full_metadata.except('authorization_endpoint')
      metadata = described_class.new(data)
      expect(metadata.supports_ehr_launch?).to be(false)
    end
  end

  describe '#supports_standalone_launch?' do
    it 'returns true if capability and authorization_endpoint are present' do
      expect(smart_metadata.supports_standalone_launch?).to be(true)
    end

    it 'returns false if "launch-standalone" capability is missing' do
      smart_metadata.capabilities.delete('launch-standalone')
      expect(smart_metadata.supports_standalone_launch?).to be(false)
    end

    it 'returns false if authorization_endpoint is missing' do
      data = full_metadata.except('authorization_endpoint')
      metadata = described_class.new(data)
      expect(metadata.supports_standalone_launch?).to be(false)
    end
  end

  describe '#supports_post_based_authorization?' do
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
    it 'returns true if capability, issuer, and jwks_uri are present' do
      expect(smart_metadata.supports_openid_connect?).to be(true)
    end

    it 'returns false if "sso-openid-connect" capability is missing' do
      smart_metadata.capabilities.delete('sso-openid-connect')
      expect(smart_metadata.supports_openid_connect?).to be(false)
    end

    it 'returns false if issuer is missing' do
      data = full_metadata.except('issuer')
      metadata = described_class.new(data)
      expect(metadata.supports_openid_connect?).to be(false)
    end

    it 'returns false if jwks_uri is missing' do
      data = full_metadata.except('jwks_uri')
      metadata = described_class.new(data)
      expect(metadata.supports_openid_connect?).to be(false)
    end
  end

  describe '#ehr_launch_capability?' do
    it 'returns true if "launch-ehr" is in capabilities' do
      expect(smart_metadata.ehr_launch_capability?).to be(true)
    end

    it 'returns false if "launch-ehr" is not in capabilities' do
      smart_metadata.capabilities.delete('launch-ehr')
      expect(smart_metadata.ehr_launch_capability?).to be(false)
    end
  end

  describe '#standalone_launch_capability?' do
    it 'returns true if "launch-standalone" is in capabilities' do
      expect(smart_metadata.standalone_launch_capability?).to be(true)
    end

    it 'returns false if "launch-standalone" is not in capabilities' do
      smart_metadata.capabilities.delete('launch-standalone')
      expect(smart_metadata.standalone_launch_capability?).to be(false)
    end
  end

  describe '#openid_connect_capability?' do
    it 'returns true if "sso-openid-connect" is in capabilities' do
      expect(smart_metadata.openid_connect_capability?).to be(true)
    end

    it 'returns false if "sso-openid-connect" is not in capabilities' do
      smart_metadata.capabilities.delete('sso-openid-connect')
      expect(smart_metadata.openid_connect_capability?).to be(false)
    end
  end
end
