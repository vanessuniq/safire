require 'spec_helper'

RSpec.describe Safire::URIValidation do
  subject(:host) do
    Class.new do
      include Safire::URIValidation

      public :classify_uri, :localhost_http_uri?, :strict_https_uri?
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

    it 'returns :non_https for HTTP on localhost by default' do
      expect(host.classify_uri('http://localhost/path')).to eq(:non_https)
    end

    it 'returns :non_https for HTTP on localhost with a port by default' do
      expect(host.classify_uri('http://localhost:3000/path')).to eq(:non_https)
    end

    it 'returns :non_https for HTTP on 127.0.0.1 by default' do
      expect(host.classify_uri('http://127.0.0.1/path')).to eq(:non_https)
    end

    it 'returns nil for HTTP on localhost when explicitly allowed' do
      expect(host.classify_uri('http://localhost/path', allow_insecure_localhost: true)).to be_nil
    end

    it 'returns nil for HTTP on 127.0.0.1 when explicitly allowed' do
      expect(host.classify_uri('http://127.0.0.1/path', allow_insecure_localhost: true)).to be_nil
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

    it 'returns :invalid for a malformed URI' do
      expect(host.classify_uri('https://exa mple.com')).to eq(:invalid)
    end
  end

  describe '#strict_https_uri?' do
    it 'returns true for an absolute HTTPS URI' do
      expect(host.strict_https_uri?('https://example.com/path')).to be(true)
    end

    it 'returns false for HTTP on a remote host' do
      expect(host.strict_https_uri?('http://example.com/path')).to be(false)
    end

    it 'returns false for HTTP on localhost' do
      expect(host.strict_https_uri?('http://localhost/path')).to be(false)
    end

    it 'returns false for a non-HTTP scheme' do
      expect(host.strict_https_uri?('ftp://example.com/path')).to be(false)
    end

    it 'returns false for a relative URI' do
      expect(host.strict_https_uri?('/relative/path')).to be(false)
    end

    it 'returns false for an HTTPS URI without a host' do
      expect(host.strict_https_uri?('https:///path')).to be(false)
    end

    it 'returns false for a malformed HTTPS URI' do
      expect(host.strict_https_uri?('https://exa mple.com')).to be(false)
    end

    it 'returns false for a non-string value' do
      expect(host.strict_https_uri?(nil)).to be(false)
    end
  end

  describe '#localhost_http_uri?' do
    it 'returns true for HTTP on localhost with a port' do
      expect(host.localhost_http_uri?('http://localhost:3000/callback')).to be(true)
    end

    it 'returns true for HTTP on 127.0.0.1' do
      expect(host.localhost_http_uri?('http://127.0.0.1/callback')).to be(true)
    end

    it 'returns false for HTTPS on localhost' do
      expect(host.localhost_http_uri?('https://localhost/callback')).to be(false)
    end

    it 'returns false for HTTP on a remote host' do
      expect(host.localhost_http_uri?('http://example.com/callback')).to be(false)
    end

    it 'returns false for malformed and non-string values' do
      expect(host.localhost_http_uri?('http://local host/callback')).to be(false)
      expect(host.localhost_http_uri?(nil)).to be(false)
    end
  end
end
