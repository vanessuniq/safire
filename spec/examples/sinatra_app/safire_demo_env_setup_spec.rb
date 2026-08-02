require 'fileutils'
require 'jwt'
require 'openssl'
require 'stringio'
require 'tmpdir'
require 'spec_helper'
require_relative '../../../examples/sinatra_app/bin/setup_env'

RSpec.describe SafireDemoEnvSetup do
  subject(:setup) do
    described_class.new(app_root:, env_path:, example_env_path:, output:, client_uri:, now:)
  end

  let(:app_root) { Dir.mktmpdir('safire-demo-env') }
  let(:env_path) { File.join(app_root, '.env') }
  let(:example_env_path) { File.join(app_root, '.env.example') }
  let(:output) { StringIO.new }
  let(:now) { Time.utc(2026, 1, 1, 12, 0, 0) }
  let(:client_uri) { 'http://localhost:4567' }

  before do
    File.write(example_env_path, example_env_template)
  end

  after do
    FileUtils.remove_entry(app_root)
  end

  it 'creates a local .env file with generated demo defaults when values are absent' do
    setup.run

    aggregate_failures do
      expect(File).to exist(env_path)
      expect(env_value('SESSION_SECRET')).not_to eq('your_session_secret_here')
      expect(OpenSSL::PKey.read(env_value('ASYMMETRIC_PRIVATE_KEY_PEM'))).to be_private
      expect(env_value('ASYMMETRIC_KID')).to start_with('safire-demo-')
      expect(env_value('UDAP_CLIENT_LOGO_URI')).to eq("#{client_uri}/safire-demo-logo.png")
      expect(env_value('UDAP_CLIENT_CERTIFICATIONS_FILE')).to eq('data/udap_self_signed_certification.jwt')
      expect(env_value('UDAP_REGISTRATION_SIGNING_ALGORITHM')).to eq('RS256')
    end
  end

  it 'generates a UDAP client certificate matching the generated private key and client URI' do
    setup.run

    key = OpenSSL::PKey.read(env_value('UDAP_CLIENT_PRIVATE_KEY_PEM'))
    cert = OpenSSL::X509::Certificate.new(env_value('UDAP_CLIENT_CERTIFICATE_CHAIN_PEM'))
    san = cert.extensions.find { |extension| extension.oid == 'subjectAltName' }

    aggregate_failures do
      expect(cert.check_private_key(key)).to be(true)
      expect(cert.subject.to_s).to include('Safire Demo UDAP Client')
      expect(san.value).to include("URI:#{client_uri}")
    end
  end

  it 'generates a compact JWS self-declaration certification file' do
    setup.run

    cert = OpenSSL::X509::Certificate.new(env_value('UDAP_CLIENT_CERTIFICATE_CHAIN_PEM'))
    payload, header = JWT.decode(
      certification_jwt,
      cert.public_key,
      true,
      algorithms: ['RS256'],
      verify_expiration: false
    )

    aggregate_failures do
      expect(header['x5c']).to contain_exactly(Base64.strict_encode64(cert.to_der))
      expect(payload).to include('iss' => client_uri, 'sub' => client_uri)
      expect(payload['certification_name']).to eq('Safire Demo Self-Declaration')
      expect(payload['certification_uris']).to include('https://www.example.com/udap/profiles/example-certification')
    end
  end

  it 'preserves existing nonblank environment values and certification files' do
    key = OpenSSL::PKey::RSA.generate(2048)
    cert = build_certificate(key, uri_san: 'http://localhost:9999')
    write_existing_env(key, cert)
    FileUtils.mkdir_p(File.join(app_root, 'data'))
    File.write(File.join(app_root, 'data/custom.jwt'), "existing.jwt\n")

    setup.run

    aggregate_failures do
      expect(env_value('SESSION_SECRET')).to eq('existing-session')
      expect(env_value('ASYMMETRIC_KID')).to eq('existing-kid')
      expect(env_value('UDAP_CLIENT_PRIVATE_KEY_PEM')).to eq(key.to_pem)
      expect(env_value('UDAP_CLIENT_CERTIFICATE_CHAIN_PEM')).to eq(cert.to_pem)
      expect(File.read(File.join(app_root, 'data/custom.jwt'))).to eq("existing.jwt\n")
    end
  end

  it 'parses single-quoted multiline dotenv values' do
    document = described_class::DotenvDocument.parse("KEY='line one\nline two'\n")

    expect(document.value('KEY')).to eq("line one\nline two")
  end

  it 'unescapes matching quote characters in quoted dotenv values' do
    document = described_class::DotenvDocument.parse(%(ONE='it\\'s fine'\nTWO="say \\"hi\\""\n))

    aggregate_failures do
      expect(document.value('ONE')).to eq("it's fine")
      expect(document.value('TWO')).to eq('say "hi"')
    end
  end

  it 'seeds an empty .env from the example template before filling values' do
    File.write(env_path, '')

    setup.run

    expect(File.read(env_path)).to include('UDAP_TRUST_ANCHORS_PEM=""')
  end

  it 'is idempotent after the initial local setup' do
    setup.run
    first_env = File.read(env_path)
    first_certification = certification_jwt
    output.truncate(0)
    output.rewind

    setup.run

    aggregate_failures do
      expect(File.read(env_path)).to eq(first_env)
      expect(certification_jwt).to eq(first_certification)
      expect(output.string).to include('Demo environment already configured.')
    end
  end

  def env_value(key)
    SafireDemoEnvSetup::DotenvDocument.parse(File.read(env_path)).value(key)
  end

  def certification_jwt
    path = File.join(app_root, env_value('UDAP_CLIENT_CERTIFICATIONS_FILE'))
    File.read(path).strip
  end

  def example_env_template
    <<~ENV
      SESSION_SECRET=your_session_secret_here
      ASYMMETRIC_PRIVATE_KEY_PEM="-----BEGIN RSA PRIVATE KEY-----
      ...your private key content here...
      -----END RSA PRIVATE KEY-----"
      ASYMMETRIC_KID=my-app-key-001
      UDAP_TRUST_ANCHORS_PEM=""
      UDAP_CRLS_PEM=""
      UDAP_VERIFY_CHAIN=""
      UDAP_CLIENT_NAME="Safire Demo App"
      UDAP_CLIENT_CONTACTS="mailto:admin@example.com"
      UDAP_CLIENT_LOGO_URI=""
      UDAP_CLIENT_CERTIFICATIONS_FILE=""
      UDAP_CLIENT_PRIVATE_KEY_PEM=""
      UDAP_CLIENT_CERTIFICATE_CHAIN_PEM=""
      UDAP_REGISTRATION_SIGNING_ALGORITHM=""
    ENV
  end

  def write_existing_env(key, cert)
    File.write(env_path, <<~ENV)
      SESSION_SECRET=existing-session
      ASYMMETRIC_KID=existing-kid
      UDAP_CLIENT_PRIVATE_KEY_PEM="#{key.to_pem}"
      UDAP_CLIENT_CERTIFICATE_CHAIN_PEM="#{cert.to_pem}"
      UDAP_CLIENT_CERTIFICATIONS_FILE=data/custom.jwt
    ENV
  end

  def build_certificate(key, uri_san:, serial: 1)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = serial
    cert.subject = OpenSSL::X509::Name.parse('/CN=Existing UDAP Client')
    cert.issuer = cert.subject
    cert.public_key = key.public_key
    cert.not_before = now - 300
    cert.not_after = now + 3600
    cert.add_extension(OpenSSL::X509::ExtensionFactory.new(cert, cert).create_extension('subjectAltName',
                                                                                        "URI:#{uri_san}", false))
    cert.sign(key, OpenSSL::Digest.new('SHA256'))
    cert
  end
end
