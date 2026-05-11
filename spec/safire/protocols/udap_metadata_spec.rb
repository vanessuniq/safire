require 'spec_helper'

RSpec.describe Safire::Protocols::UdapMetadata do
  let(:full_metadata) do
    {
      'udap_versions_supported' => ['1'],
      'udap_profiles_supported' => %w[udap_dcr udap_authn udap_authz],
      'udap_authorization_extensions_supported' => %w[hl7-b2b hl7-b2b-user],
      'udap_certifications_supported' => ['https://www.example.com/udap/profile/1'],
      'grant_types_supported' => %w[authorization_code client_credentials],
      'scopes_supported' => %w[openid profile launch user/*.rs],
      'token_endpoint' => 'https://fhir.example.com/token',
      'token_endpoint_auth_methods_supported' => ['private_key_jwt'],
      'token_endpoint_auth_signing_alg_values_supported' => ['RS256'],
      'registration_endpoint' => 'https://fhir.example.com/register',
      'registration_endpoint_jwt_signing_alg_values_supported' => ['RS256'],
      'signed_metadata' => 'eyJhbGci...',
      'authorization_endpoint' => 'https://fhir.example.com/authorize',
      'udap_authorization_extensions_required' => ['hl7-b2b'],
      'udap_certifications_required' => ['https://www.example.com/udap/profile/1']
    }
  end

  let(:metadata) { described_class.new(full_metadata) }

  describe '#valid?' do
    before { allow(Safire.logger).to receive(:warn) }

    it 'returns true when all required fields are present and all constraints pass' do
      expect(metadata.valid?).to be(true)
      expect(Safire.logger).not_to have_received(:warn)
    end

    context 'when a required field is missing' do
      described_class::REQUIRED_ATTRIBUTES.each do |attr|
        it "returns false and logs a warning when #{attr} is absent" do
          m = described_class.new(full_metadata.except(attr.to_s))

          expect(m.valid?).to be(false)
          expect(Safire.logger).to have_received(:warn).with(/required field '#{attr}' is missing/)
        end
      end
    end

    context 'when an array-valued field has a malformed type' do
      described_class::ARRAY_ATTRIBUTES.each do |attr|
        it "returns false and logs a warning when #{attr} is not an array" do
          m = described_class.new(full_metadata.merge(attr.to_s => attr.to_s))
          result = nil

          expect { result = m.valid? }.not_to raise_error
          expect(result).to be(false)
          expect(Safire.logger).to have_received(:warn).with(/field '#{attr}' must be an array/)
        end
      end
    end

    context "when udap_versions_supported is not the fixed array ['1']" do
      it "returns false and logs a warning when '1' is absent" do
        m = described_class.new(full_metadata.merge('udap_versions_supported' => ['2']))

        expect(m.valid?).to be(false)
        expect(Safire.logger).to have_received(:warn).with(/udap_versions_supported must be the fixed array/)
      end

      it 'returns false and logs a warning when extra values are present alongside "1"' do
        m = described_class.new(full_metadata.merge('udap_versions_supported' => %w[1 2]))

        expect(m.valid?).to be(false)
        expect(Safire.logger).to have_received(:warn).with(/udap_versions_supported must be the fixed array/)
      end
    end

    context 'when udap_profiles_supported is missing required profiles' do
      it "returns false and logs a warning when 'udap_dcr' is absent" do
        m = described_class.new(full_metadata.merge('udap_profiles_supported' => ['udap_authn']))

        expect(m.valid?).to be(false)
        expect(Safire.logger).to have_received(:warn).with(/'udap_dcr' is missing from udap_profiles_supported/)
      end

      it "returns false and logs a warning when 'udap_authn' is absent" do
        m = described_class.new(full_metadata.merge('udap_profiles_supported' => ['udap_dcr']))

        expect(m.valid?).to be(false)
        expect(Safire.logger).to have_received(:warn).with(/'udap_authn' is missing from udap_profiles_supported/)
      end
    end

    context "when token_endpoint_auth_methods_supported is not the fixed array ['private_key_jwt']" do
      it "returns false and logs a warning when 'private_key_jwt' is absent" do
        m = described_class.new(full_metadata.merge('token_endpoint_auth_methods_supported' => ['client_secret_basic']))

        expect(m.valid?).to be(false)
        expect(Safire.logger).to have_received(:warn)
          .with(/token_endpoint_auth_methods_supported must be the fixed array/)
      end

      it 'returns false and logs a warning when extra methods are present alongside private_key_jwt' do
        data = full_metadata.merge('token_endpoint_auth_methods_supported' => %w[private_key_jwt client_secret_basic])
        m = described_class.new(data)

        expect(m.valid?).to be(false)
        expect(Safire.logger).to have_received(:warn)
          .with(/token_endpoint_auth_methods_supported must be the fixed array/)
      end
    end

    context 'when scopes_supported is empty' do
      it 'returns false and logs a warning' do
        m = described_class.new(full_metadata.merge('scopes_supported' => []))

        expect(m.valid?).to be(false)
        expect(Safire.logger).to have_received(:warn).with(/scopes_supported must be a non-empty array/)
      end
    end

    context 'when grant_types_supported is empty' do
      it 'returns false and logs a warning' do
        m = described_class.new(full_metadata.merge('grant_types_supported' => []))

        expect(m.valid?).to be(false)
        expect(Safire.logger).to have_received(:warn).with(/grant_types_supported must be a non-empty array/)
      end
    end

    context 'when token_endpoint_auth_signing_alg_values_supported is empty' do
      it 'returns false and logs a warning' do
        m = described_class.new(full_metadata.merge('token_endpoint_auth_signing_alg_values_supported' => []))

        expect(m.valid?).to be(false)
        expect(Safire.logger).to have_received(:warn)
          .with(/token_endpoint_auth_signing_alg_values_supported must be a non-empty array/)
      end
    end

    context 'when registration_endpoint_jwt_signing_alg_values_supported is empty' do
      it 'returns false and logs a warning' do
        m = described_class.new(full_metadata.merge('registration_endpoint_jwt_signing_alg_values_supported' => []))

        expect(m.valid?).to be(false)
        expect(Safire.logger).to have_received(:warn)
          .with(/registration_endpoint_jwt_signing_alg_values_supported must be a non-empty array/)
      end
    end

    context 'when a required endpoint URL is not an absolute HTTPS URL' do
      %w[token_endpoint registration_endpoint].each do |field|
        it "returns false and logs a warning when #{field} is an HTTP URL" do
          m = described_class.new(full_metadata.merge(field => 'http://fhir.example.com/endpoint'))

          expect(m.valid?).to be(false)
          expect(Safire.logger).to have_received(:warn).with(/#{field} must be an absolute HTTPS URL/)
        end

        it "returns false and logs a warning when #{field} is a blank string" do
          m = described_class.new(full_metadata.merge(field => ''))

          expect(m.valid?).to be(false)
          expect(Safire.logger).to have_received(:warn).with(/#{field} must be an absolute HTTPS URL/)
        end
      end
    end

    context 'when authorization_endpoint is present but not an absolute HTTPS URL' do
      it 'returns false and logs a warning' do
        m = described_class.new(full_metadata.merge('authorization_endpoint' => 'http://fhir.example.com/auth'))

        expect(m.valid?).to be(false)
        expect(Safire.logger).to have_received(:warn).with(/authorization_endpoint must be an absolute HTTPS URL/)
      end
    end

    context 'when signed_metadata is a blank string' do
      it 'returns false and logs a warning' do
        m = described_class.new(full_metadata.merge('signed_metadata' => ''))

        expect(m.valid?).to be(false)
        expect(Safire.logger).to have_received(:warn).with(/signed_metadata must be a non-empty string/)
      end
    end

    context 'when authorization_code is in grant_types_supported' do
      it 'returns false and logs a warning when authorization_endpoint is absent' do
        m = described_class.new(full_metadata.except('authorization_endpoint'))

        expect(m.valid?).to be(false)
        expect(Safire.logger).to have_received(:warn)
          .with(/authorization_endpoint is required when authorization_code grant type is supported/)
      end
    end

    context 'when authorization_code is not in grant_types_supported' do
      it 'does not require authorization_endpoint' do
        data = full_metadata.merge('grant_types_supported' => ['client_credentials']).except('authorization_endpoint')
        m = described_class.new(data)

        expect(m.valid?).to be(true)
        expect(Safire.logger).not_to have_received(:warn)
      end
    end

    context 'when udap_authorization_extensions_supported is non-empty' do
      it 'returns false and logs a warning when udap_authorization_extensions_required is absent' do
        m = described_class.new(full_metadata.except('udap_authorization_extensions_required'))

        expect(m.valid?).to be(false)
        expect(Safire.logger).to have_received(:warn)
          .with(/udap_authorization_extensions_required must be present/)
      end

      it 'returns false and logs a warning when a required extension is not in supported' do
        data = full_metadata.merge('udap_authorization_extensions_required' => %w[hl7-b2b custom-ext])
        m = described_class.new(data)

        expect(m.valid?).to be(false)
        expect(Safire.logger).to have_received(:warn)
          .with(/udap_authorization_extensions_required.*not in udap_authorization_extensions_supported.*custom-ext/)
      end
    end

    context 'when udap_authorization_extensions_supported is empty' do
      it 'does not require udap_authorization_extensions_required' do
        data = full_metadata
               .merge('udap_authorization_extensions_supported' => [])
               .except('udap_authorization_extensions_required')
        m = described_class.new(data)

        expect(m.valid?).to be(true)
        expect(Safire.logger).not_to have_received(:warn)
      end
    end

    context 'when udap_certifications_supported is non-empty' do
      it 'returns false and logs a warning when udap_certifications_required is absent' do
        m = described_class.new(full_metadata.except('udap_certifications_required'))

        expect(m.valid?).to be(false)
        expect(Safire.logger).to have_received(:warn)
          .with(/udap_certifications_required must be present/)
      end

      it 'returns false and logs a warning when a required certification is not in supported' do
        data = full_metadata.merge('udap_certifications_required' => ['https://other.example.com/cert'])
        m = described_class.new(data)

        expect(m.valid?).to be(false)
        expect(Safire.logger).to have_received(:warn)
          .with(/udap_certifications_required contains values not in udap_certifications_supported/)
      end
    end

    context 'when udap_certifications_supported is empty' do
      it 'does not require udap_certifications_required' do
        data = full_metadata
               .merge('udap_certifications_supported' => [])
               .except('udap_certifications_required')
        m = described_class.new(data)

        expect(m.valid?).to be(true)
        expect(Safire.logger).not_to have_received(:warn)
      end
    end

    context "when grant_types_supported includes 'client_credentials'" do
      it "returns false and logs a warning when 'udap_authz' is absent from udap_profiles_supported" do
        data = full_metadata.merge('udap_profiles_supported' => %w[udap_dcr udap_authn])
        m = described_class.new(data)

        expect(m.valid?).to be(false)
        expect(Safire.logger).to have_received(:warn)
          .with(/'udap_authz'.*required.*udap_profiles_supported.*client_credentials/)
      end

      it "does not require 'udap_authz' when 'client_credentials' is absent" do
        data = full_metadata
               .merge('grant_types_supported' => ['authorization_code'])
               .merge('udap_profiles_supported' => %w[udap_dcr udap_authn])
        m = described_class.new(data)

        expect(m.valid?).to be(true)
        expect(Safire.logger).not_to have_received(:warn)
      end
    end

    context "when grant_types_supported includes 'refresh_token'" do
      it "returns false and logs a warning when 'authorization_code' is absent" do
        data = full_metadata.merge('grant_types_supported' => %w[refresh_token client_credentials])
        m = described_class.new(data)

        expect(m.valid?).to be(false)
        expect(Safire.logger).to have_received(:warn)
          .with(/'refresh_token'.*requires.*'authorization_code'/)
      end

      it "passes when 'authorization_code' is also present" do
        data = full_metadata.merge('grant_types_supported' => %w[authorization_code refresh_token client_credentials])
        m = described_class.new(data)

        expect(m.valid?).to be(true)
        expect(Safire.logger).not_to have_received(:warn)
      end
    end
  end

  describe 'profile checks' do
    describe '#dynamic_registration_profile?' do
      it "returns true when 'udap_dcr' is in udap_profiles_supported" do
        expect(metadata.dynamic_registration_profile?).to be(true)
      end

      it "returns false when 'udap_dcr' is absent" do
        m = described_class.new(full_metadata.merge('udap_profiles_supported' => ['udap_authn']))

        expect(m.dynamic_registration_profile?).to be(false)
      end

      it 'does not substring-match malformed scalar metadata' do
        m = described_class.new(full_metadata.merge('udap_profiles_supported' => 'udap_dcr'))

        expect(m.dynamic_registration_profile?).to be(false)
      end
    end

    describe '#jwt_client_auth_profile?' do
      it "returns true when 'udap_authn' is in udap_profiles_supported" do
        expect(metadata.jwt_client_auth_profile?).to be(true)
      end

      it "returns false when 'udap_authn' is absent" do
        m = described_class.new(full_metadata.merge('udap_profiles_supported' => ['udap_dcr']))

        expect(m.jwt_client_auth_profile?).to be(false)
      end

      it 'does not substring-match malformed scalar metadata' do
        m = described_class.new(full_metadata.merge('udap_profiles_supported' => 'udap_authn'))

        expect(m.jwt_client_auth_profile?).to be(false)
      end
    end

    describe '#client_authorization_profile?' do
      it "returns true when 'udap_authz' is in udap_profiles_supported" do
        expect(metadata.client_authorization_profile?).to be(true)
      end

      it "returns false when 'udap_authz' is absent" do
        m = described_class.new(full_metadata.merge('udap_profiles_supported' => %w[udap_dcr udap_authn]))

        expect(m.client_authorization_profile?).to be(false)
      end

      it 'does not substring-match malformed scalar metadata' do
        m = described_class.new(full_metadata.merge('udap_profiles_supported' => 'udap_authz'))

        expect(m.client_authorization_profile?).to be(false)
      end
    end

    describe '#tiered_oauth_profile?' do
      it "returns true when 'udap_to' is in udap_profiles_supported" do
        m = described_class.new(full_metadata.merge('udap_profiles_supported' => %w[udap_dcr udap_authn udap_to]))

        expect(m.tiered_oauth_profile?).to be(true)
      end

      it "returns false when 'udap_to' is absent" do
        expect(metadata.tiered_oauth_profile?).to be(false)
      end

      it 'does not substring-match malformed scalar metadata' do
        m = described_class.new(full_metadata.merge('udap_profiles_supported' => 'udap_to'))

        expect(m.tiered_oauth_profile?).to be(false)
      end
    end
  end

  describe 'capability checks' do
    describe '#supports_dynamic_registration?' do
      it "returns true when 'udap_dcr' profile and registration_endpoint are both present" do
        expect(metadata.supports_dynamic_registration?).to be(true)
      end

      it "returns false when 'udap_dcr' profile is absent" do
        m = described_class.new(full_metadata.merge('udap_profiles_supported' => ['udap_authn']))

        expect(m.supports_dynamic_registration?).to be(false)
      end

      it 'returns false when registration_endpoint is absent' do
        m = described_class.new(full_metadata.except('registration_endpoint'))

        expect(m.supports_dynamic_registration?).to be(false)
      end
    end

    describe '#supports_jwt_client_auth?' do
      it "returns true when 'udap_authn' is in udap_profiles_supported" do
        expect(metadata.supports_jwt_client_auth?).to be(true)
      end

      it "returns false when 'udap_authn' is absent" do
        m = described_class.new(full_metadata.merge('udap_profiles_supported' => ['udap_dcr']))

        expect(m.supports_jwt_client_auth?).to be(false)
      end
    end

    describe '#supports_client_authorization?' do
      it "returns true when 'udap_authz' is in udap_profiles_supported" do
        expect(metadata.supports_client_authorization?).to be(true)
      end

      it "returns false when 'udap_authz' is absent" do
        m = described_class.new(full_metadata.merge('udap_profiles_supported' => %w[udap_dcr udap_authn]))

        expect(m.supports_client_authorization?).to be(false)
      end
    end

    describe '#supports_authorization_code?' do
      it "returns true when 'authorization_code' is in grant_types_supported" do
        expect(metadata.supports_authorization_code?).to be(true)
      end

      it "returns false when 'authorization_code' is absent" do
        m = described_class.new(full_metadata.merge('grant_types_supported' => ['client_credentials']))

        expect(m.supports_authorization_code?).to be(false)
      end

      it 'returns false when grant_types_supported is nil' do
        m = described_class.new(full_metadata.except('grant_types_supported'))

        expect(m.supports_authorization_code?).to be(false)
      end

      it 'does not substring-match malformed scalar metadata' do
        m = described_class.new(full_metadata.merge('grant_types_supported' => 'authorization_code'))

        expect(m.supports_authorization_code?).to be(false)
      end
    end

    describe '#supports_refresh_token?' do
      it "returns true when 'refresh_token' is in grant_types_supported" do
        m = described_class.new(full_metadata.merge('grant_types_supported' => %w[authorization_code refresh_token]))

        expect(m.supports_refresh_token?).to be(true)
      end

      it "returns false when 'refresh_token' is absent" do
        expect(metadata.supports_refresh_token?).to be(false)
      end

      it 'returns false when grant_types_supported is nil' do
        m = described_class.new(full_metadata.except('grant_types_supported'))

        expect(m.supports_refresh_token?).to be(false)
      end

      it 'does not substring-match malformed scalar metadata' do
        m = described_class.new(full_metadata.merge('grant_types_supported' => 'refresh_token'))

        expect(m.supports_refresh_token?).to be(false)
      end
    end

    describe '#supports_tiered_oauth?' do
      it "returns true when 'udap_to' is in udap_profiles_supported" do
        m = described_class.new(full_metadata.merge('udap_profiles_supported' => %w[udap_dcr udap_authn udap_to]))

        expect(m.supports_tiered_oauth?).to be(true)
      end

      it "returns false when 'udap_to' is absent" do
        expect(metadata.supports_tiered_oauth?).to be(false)
      end
    end

    describe '#supports_signed_metadata?' do
      it 'returns true when signed_metadata is present' do
        expect(metadata.supports_signed_metadata?).to be(true)
      end

      it 'returns false when signed_metadata is absent' do
        m = described_class.new(full_metadata.except('signed_metadata'))

        expect(m.supports_signed_metadata?).to be(false)
      end
    end
  end
end
