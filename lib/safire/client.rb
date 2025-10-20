module Safire
  class Client
    attr_reader :config, :smart_metadata

    # Initialie Safire client with a set of config
    #
    # @param config an instance of Safire::Client::Config
    def initialize(config)
      @config = config
    end

    def smart_discovery
      return @smart_metadata if @smart_metadata

      @smart_metadata = Safire::Protocols::Smart::Discovery.new(config.base_url).discover
    end
  end
end
