require 'spec_helper'

RSpec.describe Safire::Middleware::HttpsOnlyRedirects do
  subject(:middleware) { described_class.new(app) }

  let(:app) { ->(env) { Faraday::Response.new(env) } }

  def build_env(status:, location: nil)
    headers = {}
    headers['location'] = location if location
    Faraday::Env.from(
      method: :get,
      url: URI.parse('https://api.example.com/endpoint'),
      response_headers: Faraday::Utils::Headers.new(headers),
      status: status
    )
  end

  context 'when response is not a redirect' do
    it 'does not raise on 200' do
      env = build_env(status: 200)
      expect { middleware.call(env) }.not_to raise_error
    end

    it 'does not raise on 404' do
      env = build_env(status: 404)
      expect { middleware.call(env) }.not_to raise_error
    end
  end

  context 'when redirect Location is HTTPS' do
    it 'does not raise on 301 to https' do
      env = build_env(status: 301, location: 'https://api.example.com/new')
      expect { middleware.call(env) }.not_to raise_error
    end

    it 'does not raise on 302 to https' do
      env = build_env(status: 302, location: 'https://other.example.com/')
      expect { middleware.call(env) }.not_to raise_error
    end
  end

  context 'when redirect Location is HTTP on localhost' do
    it 'does not raise for localhost' do
      env = build_env(status: 301, location: 'http://localhost:3000/callback')
      expect { middleware.call(env) }.not_to raise_error
    end

    it 'does not raise for 127.0.0.1' do
      env = build_env(status: 302, location: 'http://127.0.0.1:8080/path')
      expect { middleware.call(env) }.not_to raise_error
    end
  end

  context 'when redirect Location is HTTP on a non-localhost host' do
    it 'raises NetworkError on 301 to http' do
      env = build_env(status: 301, location: 'http://api.example.com/new')
      expect { middleware.call(env) }
        .to raise_error(Safire::Errors::NetworkError, /non-HTTPS.*blocked/i)
    end

    it 'raises NetworkError on 302 to http' do
      env = build_env(status: 302, location: 'http://other.example.com/')
      expect { middleware.call(env) }
        .to raise_error(Safire::Errors::NetworkError, /non-HTTPS.*blocked/i)
    end

    it 'includes the blocked URL in the error message' do
      env = build_env(status: 301, location: 'http://attacker.example.com/steal')
      expect { middleware.call(env) }
        .to raise_error(Safire::Errors::NetworkError, %r{http://attacker\.example\.com/steal})
    end
  end

  context 'when redirect has no Location header' do
    it 'does not raise' do
      env = build_env(status: 301)
      expect { middleware.call(env) }.not_to raise_error
    end
  end
end
