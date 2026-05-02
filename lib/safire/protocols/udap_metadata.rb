module Safire
  module Protocols
    # UDAP Metadata obtained from the UDAP well-known discovery endpoint.
    # Attributes are defined as per
    # [UDAP Security STU2](https://hl7.org/fhir/us/udap-security/STU2/discovery.html).
    #
    # All twelve required attributes must be present and non-nil in a conformant
    # discovery response. {#valid?} checks both field presence and the value-level
    # constraints mandated by STU2.
    #
    # @!attribute [r] udap_versions_supported
    #   @return [Array<String>, nil] UDAP versions supported; must contain +"1"+ per STU2
    # @!attribute [r] udap_profiles_supported
    #   @return [Array<String>, nil] UDAP profiles advertised; must include +"udap_dcr"+ and +"udap_authn"+
    # @!attribute [r] udap_authorization_extensions_supported
    #   @return [Array<String>, nil] UDAP authorization extensions the server supports
    # @!attribute [r] udap_certifications_supported
    #   @return [Array<String>, nil] UDAP certifications the server supports
    # @!attribute [r] grant_types_supported
    #   @return [Array<String>, nil] OAuth2 grant types supported at the token endpoint
    # @!attribute [r] scopes_supported
    #   @return [Array<String>, nil] scopes a client may request
    # @!attribute [r] token_endpoint
    #   @return [String, nil] URL of the server's OAuth2 Token Endpoint
    # @!attribute [r] token_endpoint_auth_methods_supported
    #   @return [Array<String>, nil] client authentication methods at the token endpoint;
    #     must include +"private_key_jwt"+ per STU2
    # @!attribute [r] token_endpoint_auth_signing_alg_values_supported
    #   @return [Array<String>, nil] JWT signing algorithms supported for client authentication
    # @!attribute [r] registration_endpoint
    #   @return [String, nil] URL of the server's UDAP Dynamic Client Registration Endpoint
    # @!attribute [r] registration_endpoint_jwt_signing_alg_values_supported
    #   @return [Array<String>, nil] JWT signing algorithms supported for registration requests
    # @!attribute [r] signed_metadata
    #   @return [String, nil] a signed JWT containing a subset of the server's metadata claims
    # @!attribute [r] udap_authorization_extensions_required
    #   @return [Array<String>, nil] extensions the server requires; values must be a subset of
    #     {#udap_authorization_extensions_supported}; conditionally required when
    #     {#udap_authorization_extensions_supported} is non-empty
    # @!attribute [r] udap_certifications_required
    #   @return [Array<String>, nil] certifications the server requires; values must be a subset of
    #     {#udap_certifications_supported}; conditionally required when {#udap_certifications_supported}
    #     is non-empty
    # @!attribute [r] authorization_endpoint
    #   @return [String, nil] URL of the server's Authorization Endpoint; conditionally required
    #     when {#grant_types_supported} includes +"authorization_code"+
    class UdapMetadata < Safire::Entity
      REQUIRED_ATTRIBUTES = %i[
        udap_versions_supported
        udap_profiles_supported
        udap_authorization_extensions_supported
        udap_certifications_supported
        grant_types_supported
        scopes_supported
        token_endpoint
        token_endpoint_auth_methods_supported
        token_endpoint_auth_signing_alg_values_supported
        registration_endpoint
        registration_endpoint_jwt_signing_alg_values_supported
        signed_metadata
      ].freeze

      OPTIONAL_ATTRIBUTES = %i[
        udap_authorization_extensions_required
        udap_certifications_required
        authorization_endpoint
      ].freeze

      ATTRIBUTES = (REQUIRED_ATTRIBUTES | OPTIONAL_ATTRIBUTES).freeze
      ARRAY_ATTRIBUTES = %i[
        udap_versions_supported
        udap_profiles_supported
        udap_authorization_extensions_supported
        udap_certifications_supported
        grant_types_supported
        scopes_supported
        token_endpoint_auth_methods_supported
        token_endpoint_auth_signing_alg_values_supported
        registration_endpoint_jwt_signing_alg_values_supported
        udap_authorization_extensions_required
        udap_certifications_required
      ].freeze

      attr_reader(*ATTRIBUTES)

      def initialize(metadata)
        super(metadata, ATTRIBUTES)
      end

      # Checks whether the server's UDAP metadata is valid according to UDAP Security STU2.
      #
      # This is a user-callable helper. Safire performs discovery without automatically
      # asserting server compliance — it is the caller's responsibility to invoke this
      # method when they wish to verify conformance.
      #
      # Checks performed:
      # - All required fields are present (nil? check; empty arrays are valid required values)
      # - All array-valued fields are arrays before any profile/grant/subset checks are performed
      # - +udap_versions_supported+ must equal <tt>["1"]</tt> exactly (STU2 fixed value)
      # - +udap_profiles_supported+ includes +"udap_dcr"+ and +"udap_authn"+
      # - +token_endpoint_auth_methods_supported+ must equal <tt>["private_key_jwt"]</tt> exactly (STU2 fixed value)
      # - +scopes_supported+ and +grant_types_supported+ each have at least one element
      # - +authorization_endpoint+ present when +authorization_code+ is in +grant_types_supported+
      # - +udap_authz+ present in +udap_profiles_supported+ when +client_credentials+ is in +grant_types_supported+
      # - +authorization_code+ present in +grant_types_supported+ when +refresh_token+ is also present
      # - +udap_authorization_extensions_required+ present when +udap_authorization_extensions_supported+
      #   is non-empty, and its values are a subset of the supported list
      # - +udap_certifications_required+ present when +udap_certifications_supported+ is non-empty,
      #   and its values are a subset of the supported list
      #
      # A warning is logged for each STU2 violation detected.
      #
      # @return [Boolean] true if all checks pass, false if any violation is found
      def valid?
        fields_present = required_fields_present?
        arrays_valid = array_fields_valid?
        return false unless fields_present && arrays_valid

        [
          version_valid?,
          required_profiles_valid?,
          auth_methods_valid?,
          non_empty_arrays_valid?,
          conditional_presence_valid?,
          required_subset_valid?
        ].all?
      end

      # Profile checks — test profile advertisement only, not whether required fields are present.

      # @return [Boolean] true when the server advertises the +udap_dcr+ profile
      def dynamic_registration_profile? = profile?('udap_dcr')

      # @return [Boolean] true when the server advertises the +udap_authn+ profile
      def jwt_client_auth_profile? = profile?('udap_authn')

      # @return [Boolean] true when the server advertises the +udap_authz+ profile
      def client_authorization_profile? = profile?('udap_authz')

      # @return [Boolean] true when the server advertises the +udap_to+ (Tiered OAuth) profile
      def tiered_oauth_profile? = profile?('udap_to')

      # Capability checks — combine profile advertisement with any additional preconditions.

      # @return [Boolean] true when the server supports UDAP Dynamic Client Registration
      #   (advertises +udap_dcr+ profile and provides a +registration_endpoint+)
      def supports_dynamic_registration?
        dynamic_registration_profile? && registration_endpoint.present?
      end

      # @return [Boolean] true when the server supports JWT client authentication (+udap_authn+ profile)
      def supports_jwt_client_auth? = jwt_client_auth_profile?

      # @return [Boolean] true when the server supports the UDAP client authorization profile (+udap_authz+)
      def supports_client_authorization? = client_authorization_profile?

      # @return [Boolean] true when the server supports the authorization_code grant type
      def supports_authorization_code?
        grant_type?('authorization_code')
      end

      # @return [Boolean] true when the server supports the refresh_token grant type
      def supports_refresh_token?
        grant_type?('refresh_token')
      end

      # @return [Boolean] true when the server supports Tiered OAuth (+udap_to+ profile)
      def supports_tiered_oauth? = tiered_oauth_profile?

      # @return [Boolean] true when the server provides a signed_metadata JWT
      def supports_signed_metadata? = signed_metadata.present?

      private

      def profile?(name)
        array_includes?(:udap_profiles_supported, name)
      end

      def grant_type?(name)
        array_includes?(:grant_types_supported, name)
      end

      def array_includes?(attr, value)
        values = public_send(attr)
        values.is_a?(Array) && values.include?(value)
      end

      def array_any?(attr)
        values = public_send(attr)
        values.is_a?(Array) && values.any?
      end

      def array_or_empty(attr)
        values = public_send(attr)
        values.is_a?(Array) ? values : []
      end

      def warn_noncompliance(message)
        Safire.logger.warn("UDAP metadata non-compliance: #{message}")
      end

      def required_fields_present?
        missing = REQUIRED_ATTRIBUTES.select { |attr| public_send(attr).nil? }
        missing.each { |attr| warn_noncompliance("required field '#{attr}' is missing") }
        missing.empty?
      end

      def array_fields_valid?
        invalid = ARRAY_ATTRIBUTES.reject do |attr|
          value = public_send(attr)
          value.nil? || value.is_a?(Array)
        end
        invalid.each { |attr| warn_noncompliance("field '#{attr}' must be an array") }
        invalid.empty?
      end

      def version_valid?
        return true if udap_versions_supported == ['1']

        warn_noncompliance("udap_versions_supported must be the fixed array ['1'] (UDAP Security STU2 fixed value)")
        false
      end

      def required_profiles_valid?
        valid = true
        %w[udap_dcr udap_authn].each do |profile|
          next if profile?(profile)

          warn_noncompliance("'#{profile}' is missing from udap_profiles_supported (required by UDAP Security STU2)")
          valid = false
        end
        valid
      end

      def auth_methods_valid?
        return true if token_endpoint_auth_methods_supported == ['private_key_jwt']

        warn_noncompliance(
          "token_endpoint_auth_methods_supported must be the fixed array ['private_key_jwt'] " \
          '(required by UDAP Security STU2)'
        )
        false
      end

      def non_empty_arrays_valid?
        valid = true
        %i[scopes_supported grant_types_supported].each do |attr|
          next if array_any?(attr)

          warn_noncompliance("#{attr} must be a non-empty array (required by UDAP Security STU2)")
          valid = false
        end
        valid
      end

      def conditional_presence_valid?
        [
          authorization_endpoint_conditionally_present?,
          extensions_required_conditionally_present?,
          certifications_required_conditionally_present?,
          authz_profile_conditionally_present?,
          refresh_token_requires_authorization_code?
        ].all?
      end

      def authorization_endpoint_conditionally_present?
        return true unless grant_type?('authorization_code')
        return true unless authorization_endpoint.nil?

        warn_noncompliance('authorization_endpoint is required when authorization_code grant type is supported')
        false
      end

      def extensions_required_conditionally_present?
        return true unless array_any?(:udap_authorization_extensions_supported)
        return true unless udap_authorization_extensions_required.nil?

        warn_noncompliance(
          'udap_authorization_extensions_required must be present ' \
          'when udap_authorization_extensions_supported is non-empty'
        )
        false
      end

      def certifications_required_conditionally_present?
        return true unless array_any?(:udap_certifications_supported)
        return true unless udap_certifications_required.nil?

        warn_noncompliance(
          'udap_certifications_required must be present when udap_certifications_supported is non-empty'
        )
        false
      end

      def authz_profile_conditionally_present?
        return true unless grant_type?('client_credentials')
        return true if profile?('udap_authz')

        warn_noncompliance(
          "'udap_authz' is required in udap_profiles_supported when client_credentials grant type is supported"
        )
        false
      end

      def refresh_token_requires_authorization_code?
        return true unless grant_type?('refresh_token')
        return true if grant_type?('authorization_code')

        warn_noncompliance(
          "'refresh_token' grant type requires 'authorization_code' to also be in grant_types_supported"
        )
        false
      end

      def required_subset_valid?
        [
          extensions_required_subset_valid?,
          certifications_required_subset_valid?
        ].all?
      end

      def extensions_required_subset_valid?
        return true unless array_any?(:udap_authorization_extensions_required)

        unsupported = array_or_empty(:udap_authorization_extensions_required) -
                      array_or_empty(:udap_authorization_extensions_supported)
        return true unless unsupported.any?

        warn_noncompliance(
          'udap_authorization_extensions_required contains values not in ' \
          "udap_authorization_extensions_supported: #{unsupported.join(', ')}"
        )
        false
      end

      def certifications_required_subset_valid?
        return true unless array_any?(:udap_certifications_required)

        unsupported = array_or_empty(:udap_certifications_required) -
                      array_or_empty(:udap_certifications_supported)
        return true unless unsupported.any?

        warn_noncompliance(
          'udap_certifications_required contains values not in ' \
          "udap_certifications_supported: #{unsupported.join(', ')}"
        )
        false
      end
    end
  end
end
