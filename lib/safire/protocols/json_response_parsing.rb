module Safire
  module Protocols
    # Parses protocol response bodies into JSON-compatible, string-keyed Hashes.
    #
    # Consumers remain responsible for translating a nil result into their
    # protocol-specific error. This collaborator performs no HTTP or policy work.
    #
    # @api private
    module JSONResponseParsing
      INVALID = Object.new.freeze
      MAX_NESTING = 100

      class << self
        # @param body [Hash, String, Object] parsed or raw response body
        # @return [Hash, nil] normalized JSON object, or nil when unusable
        def parse_object(body)
          parsed = body.is_a?(String) ? JSON.parse(body) : body
          return unless parsed.is_a?(Hash)

          normalized = normalize_value(parsed, {}, 0)
          normalized unless normalized.equal?(INVALID)
        rescue JSON::ParserError, EncodingError
          nil
        end

        private

        def normalize_value(value, ancestors, depth)
          case value
          when Hash then normalize_hash(value, ancestors, depth)
          when Array then normalize_array(value, ancestors, depth)
          else normalize_scalar(value)
          end
        end

        def normalize_scalar(value)
          case value
          when String then normalize_string(value)
          when Float then value.finite? ? value : INVALID
          when Integer, TrueClass, FalseClass, NilClass then value
          else INVALID
          end
        end

        def normalize_hash(value, ancestors, depth)
          return INVALID if depth >= MAX_NESTING

          with_ancestor(value, ancestors) do
            value.each_with_object({}) do |(key, item), normalized|
              key = normalize_key(key)
              break INVALID if key.equal?(INVALID) || normalized.key?(key)

              item = normalize_value(item, ancestors, depth + 1)
              break INVALID if item.equal?(INVALID)

              normalized[key] = item
            end
          end
        end

        def normalize_array(value, ancestors, depth)
          return INVALID if depth >= MAX_NESTING

          with_ancestor(value, ancestors) do
            value.each_with_object([]) do |item, normalized|
              item = normalize_value(item, ancestors, depth + 1)
              break INVALID if item.equal?(INVALID)

              normalized << item
            end
          end
        end

        def normalize_key(key)
          return INVALID unless key.is_a?(String) || key.is_a?(Symbol)

          normalize_string(key.to_s)
        end

        def normalize_string(value)
          return INVALID unless value.valid_encoding?

          value.encode(Encoding::UTF_8)
        rescue EncodingError
          INVALID
        end

        def with_ancestor(value, ancestors)
          object_id = value.object_id
          added = false
          return INVALID if ancestors.key?(object_id)

          ancestors[object_id] = true
          added = true
          yield
        ensure
          ancestors.delete(object_id) if added
        end
      end

      private_constant :INVALID, :MAX_NESTING
    end
  end
end
