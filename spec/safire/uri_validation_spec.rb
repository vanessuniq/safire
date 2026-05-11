require 'spec_helper'

RSpec.describe Safire::URIValidation do
  subject(:host) do
    Class.new do
      include Safire::URIValidation

      public :classify_uri
    end.new
  end

  describe '#classify_uri' do
    it 'returns nil for an absolute HTTPS URL' do
      expect(host.classify_uri('https://example.com/path')).to be_nil
    end

    it 'returns :non_https for HTTP on a remote host' do
      expect(host.classify_uri('http://example.com/path')).to eq(:non_https)
    end

    it 'returns :non_https for an FTP URL on a remote host' do
      expect(host.classify_uri('ftp://example.com/path')).to eq(:non_https)
    end

    it 'returns nil for HTTP on localhost' do
      expect(host.classify_uri('http://localhost/path')).to be_nil
    end

    it 'returns nil for HTTP on localhost with a port' do
      expect(host.classify_uri('http://localhost:3000/path')).to be_nil
    end

    it 'returns nil for HTTP on 127.0.0.1' do
      expect(host.classify_uri('http://127.0.0.1/path')).to be_nil
    end

    it 'returns :non_https for FTP on localhost (only HTTP is exempt)' do
      expect(host.classify_uri('ftp://localhost/path')).to eq(:non_https)
    end

    it 'returns :non_https for WS on localhost (only HTTP is exempt)' do
      expect(host.classify_uri('ws://localhost/path')).to eq(:non_https)
    end

    it 'returns :invalid for a string without a scheme or host' do
      expect(host.classify_uri('not-a-url')).to eq(:invalid)
    end

    it 'returns :invalid for an empty string' do
      expect(host.classify_uri('')).to eq(:invalid)
    end
  end
end
