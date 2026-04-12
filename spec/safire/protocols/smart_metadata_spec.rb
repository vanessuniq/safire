require 'spec_helper'

RSpec.describe Safire::Protocols::SmartMetadata do
  let(:full_metadata) do
    root = File.expand_path '../..', File.dirname(File.absolute_path(__FILE__))
    JSON.parse(File.read(File.join(root, 'fixtures', 'smart_config.json')))
  end

  let(:smart_metadata) { described_class.new(full_metadata) }

  describe '#valid?' do
    before { allow(Safire.logger).to receive(:warn) }

    it 'returns true if all required fields are present and PKCE methods are compliant' do
      result = smart_metadata.valid?

      expect(result).to be(true)
      expect(Safire.logger).not_to have_received(:warn)
    end

    it 'returns false if a required field is missing' do
      metadata = described_class.new({ authorization_endpoint: 'example.com' })

      expect(metadata.valid?).to be(false)
    end

    it 'logs a warning for each missing required field' do
      metadata = described_class.new({ authorization_endpoint: 'example.com' })
      metadata.valid?

      expect(Safire.logger).to have_received(:warn).with(/required field 'token_endpoint' is missing/)
      expect(Safire.logger).to have_received(:warn).with(/required field 'grant_types_supported' is missing/)
      expect(Safire.logger).to have_received(:warn).with(/required field 'capabilities' is missing/)
      expect(Safire.logger).to have_received(:warn).with(/required field 'code_challenge_methods_supported' is missing/)
    end

    context 'when checking PKCE method compliance' do
      it 'returns false and logs warnings when only plain is in code_challenge_methods_supported' do
        data = full_metadata.merge('code_challenge_methods_supported' => ['plain'])
        metadata = described_class.new(data)

        result = metadata.valid?

        expect(result).to be(false)
        expect(Safire.logger).to have_received(:warn).with(/'S256' is missing from code_challenge_methods_supported/)
        expect(Safire.logger).to have_received(:warn).with(/'plain' is present in code_challenge_methods_supported/)
      end

      it 'returns false and logs a warning when S256 is missing' do
        data = full_metadata.merge('code_challenge_methods_supported' => ['RS256'])
        metadata = described_class.new(data)

        result = metadata.valid?

        expect(result).to be(false)
        expect(Safire.logger).to have_received(:warn).with(/'S256' is missing from code_challenge_methods_supported/)
      end

      it 'returns false and logs a warning when plain is present alongside S256' do
        data = full_metadata.merge('code_challenge_methods_supported' => %w[S256 plain])
        metadata = described_class.new(data)

        result = metadata.valid?

        expect(result).to be(false)
        expect(Safire.logger).to have_received(:warn).with(/'plain' is present in code_challenge_methods_supported/)
      end

      it 'returns true and logs no warnings when S256 is present and plain is absent' do
        data = full_metadata.merge('code_challenge_methods_supported' => ['S256'])
        metadata = described_class.new(data)

        result = metadata.valid?

        expect(result).to be(true)
        expect(Safire.logger).not_to have_received(:warn)
      end

      it 'returns false and logs a warning when code_challenge_methods_supported is empty' do
        data = full_metadata.merge('code_challenge_methods_supported' => [])
        metadata = described_class.new(data)

        result = metadata.valid?

        expect(result).to be(false)
        expect(Safire.logger).to have_received(:warn).with(/'S256' is missing from code_challenge_methods_supported/)
      end
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

  describe '#supports_dynamic_registration?' do
    it 'returns true when registration_endpoint is present' do
      expect(smart_metadata.supports_dynamic_registration?).to be(true)
    end

    it 'returns false when registration_endpoint is absent' do
      metadata = described_class.new(full_metadata.except('registration_endpoint'))
      expect(metadata.supports_dynamic_registration?).to be(false)
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

  describe '#supports_public_auth?' do
    it 'returns true if "client-public" is in capabilities' do
      expect(smart_metadata.supports_public_auth?).to be(true)
    end

    it 'returns false if "client-public" is not in capabilities' do
      smart_metadata.capabilities.delete('client-public')
      expect(smart_metadata.supports_public_auth?).to be(false)
    end
  end

  describe '#supports_symmetric_auth?' do
    it 'returns true if capability present and auth methods not advertised' do
      data = full_metadata.except('token_endpoint_auth_methods_supported')
      metadata = described_class.new(data)
      expect(metadata.supports_symmetric_auth?).to be(true)
    end

    it 'returns true if capability present and client_secret_basic in auth methods' do
      expect(smart_metadata.supports_symmetric_auth?).to be(true)
    end

    it 'returns false if "client-confidential-symmetric" is not in capabilities' do
      smart_metadata.capabilities.delete('client-confidential-symmetric')
      expect(smart_metadata.supports_symmetric_auth?).to be(false)
    end

    it 'returns false if auth methods advertised but client_secret_basic not included' do
      data = full_metadata.merge('token_endpoint_auth_methods_supported' => ['private_key_jwt'])
      metadata = described_class.new(data)
      expect(metadata.supports_symmetric_auth?).to be(false)
    end
  end

  describe '#supports_asymmetric_auth?' do
    it 'returns true if capability present and auth methods not advertised' do
      data = full_metadata.except('token_endpoint_auth_methods_supported')
      metadata = described_class.new(data)
      expect(metadata.supports_asymmetric_auth?).to be(true)
    end

    it 'returns true if capability present and private_key_jwt in auth methods' do
      expect(smart_metadata.supports_asymmetric_auth?).to be(true)
    end

    it 'returns false if "client-confidential-asymmetric" is not in capabilities' do
      smart_metadata.capabilities.delete('client-confidential-asymmetric')
      expect(smart_metadata.supports_asymmetric_auth?).to be(false)
    end

    it 'returns false if auth methods advertised but private_key_jwt not included' do
      data = full_metadata.merge('token_endpoint_auth_methods_supported' => ['client_secret_basic'])
      metadata = described_class.new(data)
      expect(metadata.supports_asymmetric_auth?).to be(false)
    end

    it 'returns false if no supported algorithms available' do
      data = full_metadata.merge('token_endpoint_auth_signing_alg_values_supported' => ['RS256'])
      metadata = described_class.new(data)
      expect(metadata.supports_asymmetric_auth?).to be(false)
    end
  end

  describe '#supports_backend_services?' do
    it 'returns true when client_credentials grant and asymmetric auth are both supported' do
      expect(smart_metadata.supports_backend_services?).to be(true)
    end

    it 'returns false when client_credentials is not in grant_types_supported' do
      data = full_metadata.merge('grant_types_supported' => ['authorization_code'])
      metadata = described_class.new(data)
      expect(metadata.supports_backend_services?).to be(false)
    end

    it 'returns false when grant_types_supported is nil' do
      data = full_metadata.except('grant_types_supported')
      metadata = described_class.new(data)
      expect(metadata.supports_backend_services?).to be(false)
    end

    it 'returns false when supports_asymmetric_auth? is false' do
      smart_metadata.capabilities.delete('client-confidential-asymmetric')
      expect(smart_metadata.supports_backend_services?).to be(false)
    end
  end

  describe '#asymmetric_signing_algorithms_supported' do
    it 'returns intersection of server and supported algorithms' do
      data = full_metadata.merge('token_endpoint_auth_signing_alg_values_supported' => %w[RS384 RS256 ES384])
      metadata = described_class.new(data)
      expect(metadata.asymmetric_signing_algorithms_supported).to eq(%w[RS384 ES384])
    end

    it 'returns supported algorithms when server does not advertise any' do
      data = full_metadata.except('token_endpoint_auth_signing_alg_values_supported')
      metadata = described_class.new(data)
      expect(metadata.asymmetric_signing_algorithms_supported).to eq(%w[RS384 ES384])
    end

    it 'returns empty array when no algorithms match' do
      data = full_metadata.merge('token_endpoint_auth_signing_alg_values_supported' => ['RS256'])
      metadata = described_class.new(data)
      expect(metadata.asymmetric_signing_algorithms_supported).to eq([])
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
