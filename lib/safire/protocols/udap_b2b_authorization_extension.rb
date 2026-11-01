require 'addressable/uri'

module Safire
  module Protocols
    # Validates and normalizes a caller-supplied UDAP B2B Authorization
    # Extension Object (extension key name +hl7-b2b+).
    #
    # The object enforces the locally provable member rules from
    # [UDAP Security STU2 §5.2.1.1](https://hl7.org/fhir/us/udap-security/STU2/b2b.html#b2b-authorization-extension-object)
    # and produces a deeply frozen, string-keyed canonical Hash suitable for
    # embedding under +extensions['hl7-b2b']+ in a client_credentials
    # Authentication Token. It does not sign, send, or dereference anything.
    #
    # Rules are labelled below as *normative* (quoted from STU2), *implementation
    # choice* (Safire policy stricter or more specific than STU2), or *not
    # locally verifiable* (documented caller or trust-community responsibility).
    #
    # Members:
    # - +version+ — normative: "String with fixed value: \"1\"". Safire always
    #   emits +"1"+; callers may omit it or pass exactly +"1"+.
    # - +organization_id+ — required. Normative: "The identifier SHALL be a
    #   Uniform Resource Identifier (URI)." Safire requires a non-blank absolute
    #   URI (a scheme followed by a non-empty remainder, no whitespace).
    #   Not locally verifiable: "Trust communities SHALL define the allowed URI
    #   scheme(s)" and "If a URL is used, the issuer SHALL include a URL that is
    #   resolvable by the receiving party."
    # - +purpose_of_use+ — required. Normative: "An array of one or more
    #   strings". Safire requires each element to be a non-blank String.
    # - +organization_name+, +subject_name+ — optional non-blank Strings.
    #   +subject_name+ is "required if known"; Safire cannot know this, so it is
    #   not required.
    # - +subject_id+, +subject_role+ — optional non-blank Strings. STU2 makes
    #   them "required if known for human requestors when the subject_name
    #   parameter is present" and says to omit +subject_id+ "for non-human
    #   requestors". Safire cannot know whether the requestor is human or an
    #   identifier is known, so it never requires them. Implementation choice:
    #   both are rejected when +subject_name+ is absent, because STU2 only
    #   defines them in relation to a named subject. A more permissive
    #   alternative would be to accept them with a warning.
    # - +consent_policy+ — optional. Normative: "An array of one or more
    #   strings, each containing a URI". Safire requires non-blank absolute URIs.
    # - +consent_reference+ — conditional. Normative: "An array of one or more
    #   strings, each containing an absolute URL" and "Omit if consent_policy is
    #   not present." Implementation choice: each URL must be an absolute
    #   +http+ or +https+ URL with a host and no whitespace. Not locally
    #   verifiable: URLs "resolvable by the receiving party" and literal
    #   references to FHIR Consent or DocumentReference resources.
    #
    # Further implementation choices:
    # - Unknown keys are rejected. STU2 fixes this object's members; other
    #   implementation guides "MAY define additional Authorization Extension
    #   Objects" under their own extension keys rather than adding members here.
    # - Keys may be Strings or Symbols; a key supplied in both forms is rejected.
    # - A +nil+ value is treated as absent: omitted from {#to_h} for optional
    #   members and reported as missing for required members.
    # - String values are copied as given (not stripped); URI-valued members
    #   reject any whitespace because RFC 3986 URIs cannot contain it.
    # - No NPI, NUCC Provider Taxonomy, or HL7 PurposeOfUse code validation is
    #   performed. STU2 "Preferred code systems and naming systems for US Realm"
    #   states trust communities "SHALL constrain" the
    #   +subject_id+ naming systems and "SHOULD constrain" +subject_role+ and
    #   +purpose_of_use+ values; conformance to those rules is the caller's and
    #   trust community's responsibility.
    #
    # Validation errors name the offending member but never include its value.
    #
    # @example Minimal object
    #   extension = Safire::Protocols::UdapB2bAuthorizationExtension.new(
    #     organization_id: 'https://fhir.example.com/Organization/123',
    #     purpose_of_use: ['urn:oid:2.16.840.1.113883.5.8#TREAT']
    #   )
    #   extension.to_h
    #   # => { 'version' => '1',
    #   #      'organization_id' => 'https://fhir.example.com/Organization/123',
    #   #      'purpose_of_use' => ['urn:oid:2.16.840.1.113883.5.8#TREAT'] }
    #
    # @see https://hl7.org/fhir/us/udap-security/STU2/b2b.html#b2b-authorization-extension-object
    # @api private
    class UdapB2bAuthorizationExtension
      # Key name under which STU2 places this object in the Authentication
      # Token +extensions+ claim.
      EXTENSION_KEY = 'hl7-b2b'.freeze
      VERSION_VALUE = '1'.freeze
      STRING_FIELDS = %w[subject_name subject_id subject_role organization_name].freeze
      SUBJECT_DEPENDENT_FIELDS = %w[subject_id subject_role].freeze
      MEMBER_ORDER = %w[
        version
        subject_name
        subject_id
        subject_role
        organization_name
        organization_id
        purpose_of_use
        consent_policy
        consent_reference
      ].freeze
      # RFC 3986 §3.1 scheme, then only unreserved/reserved characters or
      # well-formed percent-encoded octets (RFC 3986 §2.1–2.3).
      URI_SCHEME_PATTERN = %r{\A[A-Za-z][A-Za-z0-9+.-]*:(?:[A-Za-z0-9\-._~!$&'()*+,;=:@/?\#\[\]]|%\h\h)+\z}
      WEB_SCHEMES = %w[http https].freeze

      private_constant :VERSION_VALUE, :STRING_FIELDS, :SUBJECT_DEPENDENT_FIELDS,
                       :MEMBER_ORDER, :URI_SCHEME_PATTERN, :WEB_SCHEMES

      # @param input [Hash{String, Symbol => Object}] caller-supplied B2B
      #   Authorization Extension Object members
      # @raise [Safire::Errors::ValidationError] when input violates a locally
      #   provable STU2 rule or a documented Safire implementation choice
      def initialize(input)
        members = normalize_input(input)
        validate_version!(members)
        validate_organization_id!(members)
        validate_purpose_of_use!(members)
        validate_strings!(members)
        validate_subject_fields!(members)
        validate_consent_fields!(members)
        members['version'] = VERSION_VALUE
        @extension = canonicalize(members)
        freeze
      end

      # Returns the deeply frozen canonical extension object with String keys,
      # +version+ first, and members in STU2 table order.
      #
      # @return [Hash{String => String, Array<String>}]
      def to_h
        @extension
      end

      private

      def normalize_input(input)
        fail_validation!(:'hl7-b2b', 'must be a Hash') unless input.is_a?(Hash)

        seen = Set.new
        input.each_with_object({}) do |(key, value), members|
          name = member_name(key)
          fail_validation!(name.to_sym, 'must not be specified more than once') unless seen.add?(name)

          members[name] = value unless value.nil?
        end
      end

      def member_name(key)
        fail_validation!(:'hl7-b2b', 'keys must be strings or symbols') unless key.is_a?(String) || key.is_a?(Symbol)

        name = key.to_s
        return name if MEMBER_ORDER.include?(name)

        fail_validation!(name.to_sym, 'is not a B2B Authorization Extension Object member')
      end

      def validate_version!(members)
        return unless members.key?('version')
        return if members['version'] == VERSION_VALUE

        fail_validation!(:version, 'must be omitted or the string "1"')
      end

      def validate_organization_id!(members)
        fail_validation!(:organization_id, 'is required') unless members.key?('organization_id')
        return if absolute_uri?(members['organization_id'])

        fail_validation!(:organization_id, 'must be an absolute URI string')
      end

      def validate_purpose_of_use!(members)
        fail_validation!(:purpose_of_use, 'is required') unless members.key?('purpose_of_use')
        return if non_blank_string_array?(members['purpose_of_use'])

        fail_validation!(:purpose_of_use, 'must be a non-empty array of non-blank strings')
      end

      def validate_strings!(members)
        invalid = STRING_FIELDS.find { |field| members.key?(field) && !non_blank_string?(members[field]) }
        fail_validation!(invalid.to_sym, 'must be a non-blank string') if invalid
      end

      def validate_subject_fields!(members)
        return if members.key?('subject_name')

        dependent = SUBJECT_DEPENDENT_FIELDS.find { |field| members.key?(field) }
        fail_validation!(dependent.to_sym, 'requires subject_name') if dependent
      end

      def validate_consent_fields!(members)
        validate_uri_array!(members, 'consent_policy', 'absolute URI') { |value| absolute_uri?(value) }
        return unless members.key?('consent_reference')

        fail_validation!(:consent_reference, 'requires consent_policy') unless members.key?('consent_policy')
        validate_uri_array!(members, 'consent_reference', 'absolute HTTP(S) URL') { |value| absolute_web_url?(value) }
      end

      def validate_uri_array!(members, field, description, &)
        return unless members.key?(field)

        values = members[field]
        return if non_blank_string_array?(values) && values.all?(&)

        fail_validation!(field.to_sym, "must be a non-empty array of #{description} strings")
      end

      def canonicalize(members)
        MEMBER_ORDER.each_with_object({}) do |field, canonical|
          next unless members.key?(field)

          canonical[field.dup.freeze] = frozen_copy(members[field])
        end.freeze
      end

      def frozen_copy(value)
        return value.map { |entry| entry.dup.freeze }.freeze if value.is_a?(Array)

        value.dup.freeze
      end

      def non_blank_string?(value)
        value.is_a?(String) && value.present?
      end

      def non_blank_string_array?(value)
        value.is_a?(Array) && value.any? && value.all? { |entry| non_blank_string?(entry) }
      end

      def absolute_uri?(value)
        return false unless value.is_a?(String) && URI_SCHEME_PATTERN.match?(value)

        Addressable::URI.parse(value).scheme.present?
      rescue Addressable::URI::InvalidURIError
        false
      end

      def absolute_web_url?(value)
        return false unless absolute_uri?(value)

        uri = Addressable::URI.parse(value)
        WEB_SCHEMES.include?(uri.scheme.downcase) && uri.host.present?
      end

      def fail_validation!(attribute, reason)
        raise Errors::ValidationError.new(attribute:, reason:)
      end
    end
  end
end
