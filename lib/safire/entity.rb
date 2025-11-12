module Safire
  class Entity
    def initialize(params, attributes)
      attributes.each { |name| instance_variable_set("@#{name}", params[name] || params[name.to_s]) }
    end

    def to_hash
      hash = {}
      instance_variables.each do |var|
        key = var.to_s.delete_prefix('@').to_sym
        hash[key] = instance_variable_get(var)
      end
      hash.deep_symbolize_keys
    end
  end
end
