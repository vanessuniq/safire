module Safire
  class Entity
    def initialize(params, attributes)
      attributes.each { |name| instance_variable_set("@#{name}", params[name] || params[name.to_s]) }
    end
  end
end
