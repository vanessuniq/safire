require 'spec_helper'

RSpec.describe Safire::Protocols::UdapTieredAuthorizationRequest do
  let(:idp) { 'https://idp.example.com/optionalPathComponent' }

  describe '.new' do
    it 'keeps a valid HTTPS IdP base URL unchanged and frozen' do
      request = described_class.new(idp:)

      expect(request.idp).to eq(idp)
      expect(request.idp).to be_frozen
      expect(request).to be_frozen
    end

    it 'accepts an IdP base URL with a port and no path' do
      expect(described_class.new(idp: 'https://idp.example.com:8443').idp).to eq('https://idp.example.com:8443')
    end

    [
      ['is nil', nil, 'must be a String'],
      ['is not a String', 42, 'must be a String'],
      ['is a URI object', URI('https://idp.example.com'), 'must be a String'],
      ['is empty', '', 'must be an absolute URL'],
      ['is blank', '   ', 'must be an absolute URL'],
      ['is relative', '/idp', 'must be an absolute URL'],
      ['has no scheme', 'idp.example.com', 'must be an absolute URL'],
      ['has no host', 'https:///idp', 'must be an absolute URL'],
      ['uses HTTP', 'http://idp.example.com', 'must use HTTPS'],
      ['uses another scheme', 'ftp://idp.example.com', 'must use HTTPS'],
      ['uses HTTP loopback without the development policy', 'http://localhost:9000', 'must use HTTPS'],
      ['has a fragment', 'https://idp.example.com/#frag', 'must not include a fragment'],
      ['has an empty fragment', 'https://idp.example.com/#', 'must not include a fragment']
    ].each do |label, value, reason|
      it "raises ValidationError on :idp when it #{label}" do
        expect { described_class.new(idp: value) }.to raise_error(Safire::Errors::ValidationError) { |error|
          expect(error.attribute).to eq(:idp)
          expect(error.reason).to eq(reason)
        }
      end
    end

    it 'does not include the rejected value in the error message' do
      expect { described_class.new(idp: 'http://secret-idp.example.com') }
        .to raise_error(Safire::Errors::ValidationError) { |error|
          expect(error.message).not_to include('secret-idp')
        }
    end

    it 'rejects a non-boolean localhost policy' do
      expect { described_class.new(idp:, allow_insecure_localhost: 'yes') }
        .to raise_error(Safire::Errors::ConfigurationError)
    end

    context 'with allow_insecure_localhost' do
      %w[http://localhost:9000 http://127.0.0.1:9000/idp].each do |value|
        it "accepts the HTTP loopback URL #{value}" do
          expect(described_class.new(idp: value, allow_insecure_localhost: true).idp).to eq(value)
        end
      end

      it 'still rejects a non-loopback HTTP URL' do
        expect { described_class.new(idp: 'http://idp.example.com', allow_insecure_localhost: true) }
          .to raise_error(Safire::Errors::ValidationError, /idp: must use HTTPS/)
      end
    end
  end

  describe '#scopes' do
    subject(:request) { described_class.new(idp:) }

    it 'appends udap and keeps the requested order' do
      expect(request.scopes(%w[openid patient/Patient.rs])).to eq(%w[openid patient/Patient.rs udap])
    end

    it 'does not duplicate udap or move it when already requested' do
      expect(request.scopes(%w[udap openid])).to eq(%w[udap openid])
    end

    it 'does not mutate the input' do
      scopes = %w[openid].freeze

      expect { request.scopes(scopes) }.not_to raise_error
      expect(scopes).to eq(%w[openid])
    end
  end

  describe '#params' do
    it 'returns the idp extension parameter' do
      expect(described_class.new(idp:).params).to eq(idp:)
    end
  end
end
