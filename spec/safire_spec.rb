require 'spec_helper'

RSpec.describe Safire do
  describe '.token_response_valid?' do
    before { allow(described_class.logger).to receive(:warn) }

    let(:valid_response) do
      { 'access_token' => 'abc123', 'token_type' => 'Bearer', 'scope' => 'openid profile' }
    end

    context 'when all required fields are present and token_type is "Bearer"' do
      it 'returns true and does not warn' do
        result = described_class.token_response_valid?(valid_response)
        expect(result).to be(true)
        expect(described_class.logger).not_to have_received(:warn)
      end
    end

    context 'when access_token is missing' do
      it 'returns false and logs a warning' do
        result = described_class.token_response_valid?(valid_response.except('access_token'))
        expect(result).to be(false)
        expect(described_class.logger).to have_received(:warn).with(/'access_token' is missing/)
      end
    end

    context 'when scope is missing' do
      it 'returns false and logs a warning' do
        result = described_class.token_response_valid?(valid_response.except('scope'))
        expect(result).to be(false)
        expect(described_class.logger).to have_received(:warn).with(/'scope' is missing/)
      end
    end

    context 'when token_type is missing' do
      it 'returns false and logs a warning' do
        result = described_class.token_response_valid?(valid_response.except('token_type'))
        expect(result).to be(false)
        expect(described_class.logger).to have_received(:warn).with(/'token_type' is missing/)
      end
    end

    context 'when token_type is lowercase "bearer"' do
      it 'returns false and logs a warning' do
        result = described_class.token_response_valid?(valid_response.merge('token_type' => 'bearer'))
        expect(result).to be(false)
        expect(described_class.logger).to have_received(:warn).with(/token_type.*bearer.*Bearer/)
      end
    end

    context 'when token_type is "BEARER"' do
      it 'returns false and logs a warning' do
        result = described_class.token_response_valid?(valid_response.merge('token_type' => 'BEARER'))
        expect(result).to be(false)
        expect(described_class.logger).to have_received(:warn).with(/token_type/)
      end
    end

    context 'when multiple required fields are missing' do
      it 'returns false and logs a warning for each missing field' do
        result = described_class.token_response_valid?({})
        expect(result).to be(false)
        expect(described_class.logger).to have_received(:warn).with(/'access_token' is missing/)
        expect(described_class.logger).to have_received(:warn).with(/'scope' is missing/)
        expect(described_class.logger).to have_received(:warn).with(/'token_type' is missing/)
      end
    end

    context 'when response is not a Hash' do
      it 'returns false and logs a warning' do
        result = described_class.token_response_valid?('not a hash')
        expect(result).to be(false)
        expect(described_class.logger).to have_received(:warn).with(/not a JSON object/)
      end
    end

    context 'when response is nil' do
      it 'returns false and logs a warning' do
        result = described_class.token_response_valid?(nil)
        expect(result).to be(false)
        expect(described_class.logger).to have_received(:warn).with(/not a JSON object/)
      end
    end
  end
end
