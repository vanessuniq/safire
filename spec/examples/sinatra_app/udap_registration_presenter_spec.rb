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
      'software_statement' => 'secret.jwt.value',
      'certifications' => ['cert.jwt.value'],
      'registration_access_token' => 'registration-access-token',
      'access_token' => 'access-token',
      'refresh_token' => 'refresh-token',
      'id_token' => 'id-token',
      'nested' => {
        'private_key' => 'private-key-value',
        'x5c' => ['raw-cert-value'],
        'client_name' => 'Visible Client'
      }
    }
  end

  def filtered_registration_response
    {
      'client_id' => 'client-123',
      'software_statement' => '[FILTERED]',
      'certifications' => '[FILTERED]',
      'registration_access_token' => '[FILTERED]',
      'access_token' => '[FILTERED]',
      'refresh_token' => '[FILTERED]',
      'id_token' => '[FILTERED]',
      'nested' => {
        'private_key' => '[FILTERED]',
        'x5c' => '[FILTERED]',
        'client_name' => 'Visible Client'
      }
    }
  end

  it 'prepopulates client-owned registration fields from demo configuration' do
    Tempfile.create('udap-certifications') do |file|
      file.write("aaa.bbb.ccc\nxxx.yyy.zzz\n")
      file.flush

      presenter = build_presenter(env: env.merge('UDAP_CLIENT_CERTIFICATIONS_FILE' => file.path))

      expect(presenter.client_uri).to eq('https://client.example.com')
      expect(presenter.client_name).to eq('Configured UDAP Client')
      expect(presenter.contacts_value).to eq("mailto:admin@example.com\nmailto:security@example.com")
      expect(presenter.certifications_value).to eq("aaa.bbb.ccc\nxxx.yyy.zzz")
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

  it 'falls back to the generated demo logo URI when no logo env is configured' do
    presenter = build_presenter(env: env.except('UDAP_CLIENT_LOGO_URI'))

    expect(presenter.logo_uri).to eq('https://client.example.com/safire-demo-logo.png')
  end

  it 'loads certification JWTs from a configured file' do
    Tempfile.create('udap-certifications') do |file|
      file.write("file.jwt.value\n")
      file.flush

      presenter = build_presenter(env: env.merge('UDAP_CLIENT_CERTIFICATIONS_FILE' => file.path))

      expect(presenter.certifications_value).to eq('file.jwt.value')
    end
  end

  it 'resolves relative certification paths from the demo app root' do
    relative_path = 'data/relative-certifications.jwt'
    expanded_path = File.expand_path("../../../examples/sinatra_app/#{relative_path}", __dir__)
    allow(File).to receive(:read).with(expanded_path).and_return("relative.jwt.value\n")

    presenter = build_presenter(env: env.merge('UDAP_CLIENT_CERTIFICATIONS_FILE' => relative_path))

    expect(presenter.certifications_value).to eq('relative.jwt.value')
  end

  it 'surfaces a configuration error when the configured certifications file is unreadable' do
    presenter = build_presenter(
      env: env.merge('UDAP_CLIENT_CERTIFICATIONS_FILE' => '/tmp/safire-missing-certifications.jwt')
    )

    expect(presenter.certifications_value).to eq('')
    expect(presenter.display_error).to be_a(Safire::Errors::ConfigurationError)
    expect(presenter.display_error.message).to include('UDAP_CLIENT_CERTIFICATIONS_FILE')
  end

  it 'raises the configuration error when an operation consumes an unreadable certifications file' do
    presenter = build_presenter(
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
