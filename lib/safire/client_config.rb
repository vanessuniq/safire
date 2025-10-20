# require_relative 'entity'

module Safire
  class ClientConfig < Entity
    ATTRIBUTES = %i[base_url].freeze

    attr_reader(*ATTRIBUTES)

    def initialize(config)
      super(config, ATTRIBUTES)
    end
  end
end
