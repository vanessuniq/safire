module Safire
  # ClientConfigBuilder helps to build a Safire::ClientConfig instance
  class ClientConfigBuilder
    def initialize
      @config = {}
    end

    def base_url(url)
      @config[:base_url] = url
      self
    end

    def issuer(issuer)
      @config[:issuer] = issuer
      self
    end

    def client_id(client_id)
      @config[:client_id] = client_id
      self
    end

    def redirect_uri(uri)
      @config[:redirect_uri] = uri
      self
    end

    def scopes(scopes)
      @config[:scopes] = scopes
      self
    end

    def build
      Safire::ClientConfig.new(@config)
    end
  end
end
