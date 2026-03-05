require 'spec_helper'

RSpec.describe Safire do
  describe '.logger' do
    let(:custom_logger) { Logger.new(StringIO.new) }

    before { described_class.instance_variable_set(:@default_logger, nil) }

    after do
      described_class.instance_variable_set(:@configuration, nil)
      described_class.instance_variable_set(:@default_logger, nil)
    end

    context 'when no configure block has run' do
      it 'returns a Logger instance' do
        expect(described_class.logger).to be_a(Logger)
      end
    end

    context 'when config.logger is set' do
      before { described_class.configure { |c| c.logger = custom_logger } }

      it 'returns the configured logger' do
        expect(described_class.logger).to be(custom_logger)
      end

      it 'wins even after default_logger was already accessed' do
        described_class.default_logger
        expect(described_class.logger).to be(custom_logger)
      end
    end

    context 'when config.log_level is set' do
      before { described_class.configure { |c| c.log_level = Logger::DEBUG } }

      it 'applies log_level to the logger' do
        expect(described_class.logger.level).to eq(Logger::DEBUG)
      end
    end
  end

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

    %w[access_token scope token_type].each do |field|
      context "when #{field} is missing" do
        it 'returns false and logs a warning' do
          result = described_class.token_response_valid?(valid_response.except(field))
          expect(result).to be(false)
          expect(described_class.logger).to have_received(:warn).with(/'#{field}' is missing/)
        end
      end
    end

    [
      ['lowercase "bearer"', 'bearer', /token_type.*bearer.*Bearer/],
      ['"BEARER"', 'BEARER', /token_type/]
    ].each do |description, value, warning_pattern|
      context "when token_type is #{description}" do
        it 'returns false and logs a warning' do
          result = described_class.token_response_valid?(valid_response.merge('token_type' => value))
          expect(result).to be(false)
          expect(described_class.logger).to have_received(:warn).with(warning_pattern)
        end
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
      [nil, 'not a hash'].each do |invalid|
        it "returns false for #{invalid.inspect} and logs a warning" do
          result = described_class.token_response_valid?(invalid)
          expect(result).to be(false)
          expect(described_class.logger).to have_received(:warn).with(/not a JSON object/)
        end
      end
    end
  end
end
