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
end
