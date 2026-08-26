require 'spec_helper'
require 'tempfile'

require_relative '../../../examples/sinatra_app/models/fhir_server'
require_relative '../../../examples/sinatra_app/models/udap_registration_presenter'

RSpec.describe UdapRegistrationPresenter do
  let(:server) do
    FhirServer.new(
      id: 'udap-server',
      name: 'UDAP Server',
      base_url: 'https://fhir.example.com',
      protocols: ['udap'],
      scopes: ['system/*.rs'],
      udap_client_id: 'stored-client'
    )
  end
  let(:credentials) { instance_double(UdapClientCredentials, configured?: true) }
  let(:trust_policy) { instance_double(UdapTrustPolicy, development_mode?: true) }
  let(:env) do
    {
      'UDAP_CLIENT_NAME' => 'Configured UDAP Client',
      'CLIENT_NAME' => 'Generic Client',
      'UDAP_CLIENT_CONTACTS' => "mailto:admin@example.com\nmailto:security@example.com",
      'UDAP_CLIENT_LOGO_URI' => 'https://client.example.com/logo.png'
    }
  end

  def build_presenter(**attrs)
    presenter_attrs = {
      server:,
      params: {},
      credentials:,
      trust_policy:,
      client_uri: 'https://client.example.com',
      redirect_uri: 'https://client.example.com/callback',
      env:
    }.merge(attrs)

    described_class.new(**presenter_attrs)
  end

  def registration_response_with_sensitive_values
    {
      'client_id' => 'client-123',
      'client_name' => 'Visible Client',
      'grant_types' => ['client_credentials'],
      'software_statement' => 'secret.jwt.value',
      'certifications' => ['cert.jwt.value'],
      'registration_access_token' => 'registration-access-token',
      'access_token' => 'access-token',
      'client_assertion' => 'client-assertion',
      'private_key_pem' => 'private-key-value',
      'vendor_credential' => 'vendor-secret',
      'contacts' => { 'private_key_pem' => 'nested-secret' }
    }
  end

  def filtered_registration_response
    {
      'client_id' => 'client-123',
      'client_name' => 'Visible Client',
      'grant_types' => ['client_credentials'],
      'software_statement' => '[FILTERED]',
      'certifications' => '[FILTERED]',
      'registration_access_token' => '[FILTERED]',
      'access_token' => '[FILTERED]',
      'client_assertion' => '[FILTERED]',
      'private_key_pem' => '[FILTERED]',
      'vendor_credential' => '[FILTERED]',
      'contacts' => '[FILTERED]'
    }
  end

  def certification_jwt(grant_types:, response_types: nil)
    payload = { 'grant_types' => grant_types }
    payload['response_types'] = response_types if response_types
    JWT.encode(payload, nil, 'none')
  end

  it 'prepopulates client-owned registration fields without automatically loading certifications' do
    Tempfile.create('udap-certifications') do |file|
      file.write("#{certification_jwt(grant_types: ['client_credentials'])}\n")
      file.flush

      presenter = build_presenter(env: env.merge('UDAP_CLIENT_CERTIFICATIONS_FILE' => file.path))

      expect(presenter.client_uri).to eq('https://client.example.com')
      expect(presenter.client_name).to eq('Configured UDAP Client')
      expect(presenter.contacts_value).to eq("mailto:admin@example.com\nmailto:security@example.com")
      expect(presenter.certifications_value).to eq('')
      expect(presenter).to be_configured_certifications
      expect(presenter).not_to be_configured_certifications_selected
      expect(presenter.redirect_uris_value).to eq('https://client.example.com/callback')
      expect(presenter.logo_uri).to eq('https://client.example.com/logo.png')
      expect(presenter.response_types_value).to eq('code')
      expect(presenter.scope).to eq('system/*.rs')
    end
  end

  it 'lets submitted values override defaults after validation errors' do
    presenter = build_presenter(
      params: {
        'grant_type' => 'authorization_code',
        'client_uri' => 'https://override.example.com',
        'client_name' => 'Override Client',
        'contacts' => 'mailto:override@example.com',
        'scope' => 'openid profile',
        'community' => 'https://community.example.org/udap',
        'redirect_uris' => 'https://override.example.com/callback',
        'logo_uri' => 'https://override.example.com/logo.gif'
      }
    )

    expect(presenter).to be_authorization_code
    expect(presenter.client_uri).to eq('https://override.example.com')
    expect(presenter.client_name).to eq('Override Client')
    expect(presenter.contacts_value).to eq('mailto:override@example.com')
    expect(presenter.scope).to eq('openid profile')
    expect(presenter.community).to eq('https://community.example.org/udap')
    expect(presenter.redirect_uris_value).to eq('https://override.example.com/callback')
    expect(presenter.logo_uri).to eq('https://override.example.com/logo.gif')
  end

  it 'leaves scope empty when the server has no configured scopes' do
    server.scopes = []

    expect(build_presenter.scope).to eq('')
  end

  it 'preserves a submitted blank scope for validation feedback' do
    presenter = build_presenter(params: { 'scope' => '   ' })

    expect(presenter.scope).to eq('   ')
  end

  it 'falls back to the generated demo logo URI when no logo env is configured' do
    presenter = build_presenter(env: env.except('UDAP_CLIENT_LOGO_URI'))

    expect(presenter.logo_uri).to eq('https://client.example.com/safire-demo-logo.png')
  end

  it 'loads only grant-matched JWTs when the configured file is explicitly selected' do
    Tempfile.create('udap-certifications') do |file|
      client_credentials = certification_jwt(grant_types: ['client_credentials'])
      authorization_code = certification_jwt(
        grant_types: %w[authorization_code refresh_token],
        response_types: ['code']
      )
      file.write("#{client_credentials}\n#{authorization_code}\n")
      file.flush

      presenter = build_presenter(
        params: { 'use_configured_certifications' => '1' },
        env: env.merge('UDAP_CLIENT_CERTIFICATIONS_FILE' => file.path)
      )

      expect(presenter.certifications_value).to eq('')
      expect(presenter.certifications_value!).to eq(client_credentials)
    end
  end

  it 'loads the authorization-code certification for that grant flow' do
    Tempfile.create('udap-certifications') do |file|
      client_credentials = certification_jwt(grant_types: ['client_credentials'])
      authorization_code = certification_jwt(
        grant_types: %w[authorization_code refresh_token],
        response_types: ['code']
      )
      file.write("#{client_credentials}\n#{authorization_code}\n")
      file.flush

      presenter = build_presenter(
        params: { 'grant_type' => 'authorization_code', 'use_configured_certifications' => '1' },
        env: env.merge('UDAP_CLIENT_CERTIFICATIONS_FILE' => file.path)
      )

      expect(presenter.certifications_value!).to eq(authorization_code)
    end
  end

  it 'resolves relative certification paths from the demo app root' do
    relative_path = 'data/relative-certifications.jwt'
    expanded_path = File.expand_path("../../../examples/sinatra_app/#{relative_path}", __dir__)
    certification = certification_jwt(grant_types: ['client_credentials'])
    allow(File).to receive(:read).with(expanded_path).and_return("#{certification}\n")

    presenter = build_presenter(
      params: { 'use_configured_certifications' => '1' },
      env: env.merge('UDAP_CLIENT_CERTIFICATIONS_FILE' => relative_path)
    )

    expect(presenter.certifications_value!).to eq(certification)
  end

  it 'surfaces a configuration error when the configured certifications file is unreadable' do
    presenter = build_presenter(
      params: { 'use_configured_certifications' => '1' },
      env: env.merge('UDAP_CLIENT_CERTIFICATIONS_FILE' => '/tmp/safire-missing-certifications.jwt')
    )

    expect(presenter.certifications_value).to eq('')
    expect(presenter.display_error).to be_a(Safire::Errors::ConfigurationError)
    expect(presenter.display_error.message).to include('UDAP_CLIENT_CERTIFICATIONS_FILE')
  end

  it 'raises the configuration error when an operation consumes an unreadable certifications file' do
    presenter = build_presenter(
      params: { 'use_configured_certifications' => '1' },
      env: env.merge('UDAP_CLIENT_CERTIFICATIONS_FILE' => '/tmp/safire-missing-certifications.jwt')
    )

    expect { presenter.certifications_value! }.to raise_error(Safire::Errors::ConfigurationError)
  end

  it 'uses submitted certification JWTs without reading the configured file' do
    presenter = build_presenter(
      params: { 'certifications' => 'submitted.jwt.value' },
      env: env.merge('UDAP_CLIENT_CERTIFICATIONS_FILE' => '/tmp/safire-missing-certifications.jwt')
    )

    expect(presenter.certifications_value).to eq('submitted.jwt.value')
    expect(presenter.display_error).to be_nil
  end

  it 'rejects a configured file without a certification matching the selected grant flow' do
    Tempfile.create('udap-certifications') do |file|
      file.write("#{certification_jwt(grant_types: ['client_credentials'])}\n")
      file.flush

      presenter = build_presenter(
        params: { 'grant_type' => 'authorization_code', 'use_configured_certifications' => '1' },
        env: env.merge('UDAP_CLIENT_CERTIFICATIONS_FILE' => file.path)
      )

      expect { presenter.certifications_value! }
        .to raise_error(Safire::Errors::ConfigurationError, /authorization_code/)
    end
  end

  it 'reports malformed configured certification JWTs as configuration errors' do
    Tempfile.create('udap-certifications') do |file|
      file.write("not-a-compact-jws\n")
      file.flush

      presenter = build_presenter(
        params: { 'use_configured_certifications' => '1' },
        env: env.merge('UDAP_CLIENT_CERTIFICATIONS_FILE' => file.path)
      )

      expect { presenter.certifications_value! }
        .to raise_error(Safire::Errors::ConfigurationError, /client_credentials/)
    end
  end

  it 'filters sensitive values from returned registration metadata' do
    presenter = build_presenter(registration_response: registration_response_with_sensitive_values)

    expect(presenter.safe_registration_response).to eq(filtered_registration_response)
  end

  it 'filters access tokens from returned cancellation metadata' do
    presenter = build_presenter(
      cancellation_response: {
        'client_id' => 'stored-client',
        'grant_types' => [],
        'registration_access_token' => 'registration-access-token',
        'access_token' => 'access-token'
      }
    )

    expect(presenter.safe_cancellation_response).to include(
      'registration_access_token' => '[FILTERED]',
      'access_token' => '[FILTERED]'
    )
  end

  it 'detects cancellation confirmation and client-id mismatches' do
    confirmed = build_presenter(cancellation_response: { 'client_id' => 'stored-client', 'grant_types' => [] },
                                expected_client_id: 'stored-client')
    mismatched = build_presenter(cancellation_response: { 'client_id' => 'different-client', 'grant_types' => [] },
                                 expected_client_id: 'stored-client')

    expect(confirmed).to be_cancellation_confirmed
    expect(confirmed).not_to be_cancellation_mismatch
    expect(mismatched).to be_cancellation_confirmed
    expect(mismatched).to be_cancellation_mismatch
  end

  it 'memoizes trust policy configuration errors for display' do
    error = Safire::Errors::ConfigurationError.new(invalid_attribute: :UDAP_VERIFY_CHAIN)
    trust_policy = instance_double(UdapTrustPolicy)
    allow(trust_policy).to receive(:development_mode?).and_raise(error)

    presenter = build_presenter(trust_policy:)

    expect(presenter).to be_development_trust_mode
    expect(presenter.display_error).to eq(error)
    expect(trust_policy).to have_received(:development_mode?).once
  end
end
