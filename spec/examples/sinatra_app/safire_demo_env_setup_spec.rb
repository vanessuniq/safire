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
      expect(file_mode(env_path)).to eq(0o600)
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

  it 'signs the generated self-declarations with the configured client identity' do
    setup.run

    cert = OpenSSL::X509::Certificate.new(env_value('UDAP_CLIENT_CERTIFICATE_CHAIN_PEM'))
    decoded = decoded_certifications(cert)
    payloads = decoded.map(&:first)

    aggregate_failures do
      expect(decoded.map(&:last).pluck('x5c')).to all(contain_exactly(Base64.strict_encode64(cert.to_der)))
      expect(payloads).to all(include('iss' => client_uri, 'sub' => client_uri))
      expect(payloads.pluck('certification_name')).to all(eq('Safire Demo Self-Declaration'))
      expect(payloads.pluck('certification_uris')).to all(
        include('https://www.example.com/udap/profiles/example-certification')
      )
      expect(file_mode(File.join(app_root, env_value('UDAP_CLIENT_CERTIFICATIONS_FILE')))).to eq(0o600)
    end
  end

  it 'generates STU2 self-declarations for both demo grant flows' do
    setup.run

    cert = OpenSSL::X509::Certificate.new(env_value('UDAP_CLIENT_CERTIFICATE_CHAIN_PEM'))
    payloads = decoded_certifications(cert).map(&:first)

    aggregate_failures do
      expect(payloads.pluck('grant_types')).to contain_exactly(
        ['client_credentials'],
        %w[authorization_code refresh_token]
      )
      expect(payloads.find { |payload| payload['grant_types'].include?('authorization_code') })
        .to include('response_types' => ['code'])
      expect(payloads.find { |payload| payload['grant_types'] == ['client_credentials'] })
        .not_to have_key('response_types')
    end
  end

  it 'replaces a legacy managed self-declaration with the current grant profiles' do
    setup.run
    write_legacy_managed_certification

    setup.run

    cert = OpenSSL::X509::Certificate.new(env_value('UDAP_CLIENT_CERTIFICATE_CHAIN_PEM'))
    payloads = decoded_certifications(cert).map(&:first)

    expect(payloads.pluck('grant_types')).to contain_exactly(
      ['client_credentials'],
      %w[authorization_code refresh_token]
    )
  end

  it 'corrects a permissive existing .env file mode' do
    File.write(env_path, "SESSION_SECRET=existing-session\n")
    File.chmod(0o644, env_path)

    setup.run

    expect(file_mode(env_path)).to eq(0o600)
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

  it 'does not create a missing caller-managed certification file' do
    key = OpenSSL::PKey::RSA.generate(2048)
    cert = build_certificate(key, uri_san: client_uri)
    custom_path = File.join(app_root, 'custom', 'certification.jwt')
    write_existing_env(key, cert, certifications_file: custom_path)

    expect { setup.run }
      .to raise_error(
        SafireDemoEnvSetup::SetupError,
        /must reference an existing non-empty file when set to a custom path/
      )
    expect(File).not_to exist(custom_path)
  end

  it 'does not create a certification file through a path escaping the app directory' do
    key = OpenSSL::PKey::RSA.generate(2048)
    cert = build_certificate(key, uri_san: client_uri)
    custom_path = File.join(app_root, '..', "#{File.basename(app_root)}-certification.jwt")
    write_existing_env(key, cert, certifications_file: custom_path)

    expect { setup.run }.to raise_error(SafireDemoEnvSetup::SetupError, /leave it blank to generate/)
    expect(File).not_to exist(File.expand_path(custom_path))
  end

  it 'does not replace an empty caller-managed certification file' do
    key = OpenSSL::PKey::RSA.generate(2048)
    cert = build_certificate(key, uri_san: client_uri)
    custom_path = File.join(app_root, 'custom.jwt')
    File.write(custom_path, '')
    write_existing_env(key, cert, certifications_file: custom_path)

    expect { setup.run }.to raise_error(SafireDemoEnvSetup::SetupError, /existing non-empty file/)
    expect(File.read(custom_path)).to be_empty
  end

  it 'rejects a caller-managed certification path that is not a regular file' do
    key = OpenSSL::PKey::RSA.generate(2048)
    cert = build_certificate(key, uri_san: client_uri)
    custom_path = File.join(app_root, 'certifications')
    FileUtils.mkdir_p(custom_path)
    write_existing_env(key, cert, certifications_file: custom_path)

    expect { setup.run }.to raise_error(SafireDemoEnvSetup::SetupError, /must reference a regular file/)
  end

  it 'rejects an unreadable caller-managed certification file' do
    key = OpenSSL::PKey::RSA.generate(2048)
    cert = build_certificate(key, uri_san: client_uri)
    custom_path = File.join(app_root, 'certification.jwt')
    File.write(custom_path, 'configured.jwt')
    write_existing_env(key, cert, certifications_file: custom_path)
    allow(File).to receive(:read).and_call_original
    allow(File).to receive(:read).with(custom_path).and_raise(Errno::EACCES)

    expect { setup.run }.to raise_error(SafireDemoEnvSetup::SetupError, /must reference a readable file/)
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

  it 'escapes backslashes when quoting generated dotenv values' do
    document = described_class::DotenvDocument.parse('')

    document.set('KEY', 'C:\demo\path')

    aggregate_failures do
      expect(document.to_s).to eq(%(KEY="C:\\\\demo\\\\path"\n))
      expect(document.value('KEY')).to eq('C:\demo\path')
    end
  end

  it 'selects an EC-compatible signing algorithm for preserved EC credentials' do
    key = OpenSSL::PKey::EC.generate('prime256v1')
    cert = build_certificate(key, uri_san: client_uri)
    write_existing_env(key, cert, algorithm: '', certifications_file: '')

    setup.run

    payload, header = decoded_certifications(cert, algorithm: 'ES256').first

    aggregate_failures do
      expect(env_value('UDAP_REGISTRATION_SIGNING_ALGORITHM')).to eq('ES256')
      expect(header['alg']).to eq('ES256')
      expect(payload).to include('iss' => client_uri)
    end
  end

  it 'uses an explicitly configured RSA-compatible signing algorithm for the certification JWT' do
    key = OpenSSL::PKey::RSA.generate(2048)
    cert = build_certificate(key, uri_san: client_uri)
    write_existing_env(key, cert, algorithm: 'RS384', certifications_file: '')

    setup.run

    _payload, header = decoded_certifications(cert, algorithm: 'RS384').first

    expect(header['alg']).to eq('RS384')
  end

  it 'fails clearly when UDAP signing credentials are only partially configured' do
    key = OpenSSL::PKey::RSA.generate(2048)
    File.write(env_path, %(UDAP_CLIENT_PRIVATE_KEY_PEM="#{key.to_pem}"\n))

    expect { setup.run }
      .to raise_error(SafireDemoEnvSetup::SetupError, /must be configured together/)
  end

  it 'fails clearly when preserved UDAP signing credentials do not match' do
    key = OpenSSL::PKey::RSA.generate(2048)
    other_key = OpenSSL::PKey::RSA.generate(2048)
    cert = build_certificate(other_key, uri_san: client_uri)
    write_existing_env(key, cert)

    expect { setup.run }
      .to raise_error(SafireDemoEnvSetup::SetupError, /does not match/)
  end

  it 'seeds an empty .env from the example template before filling values' do
    File.write(env_path, '')

    setup.run

    expect(File.read(env_path)).to include('UDAP_TRUST_ANCHORS_PEM=""')
  end

  it 'creates an environment without an example template' do
    FileUtils.rm_f(example_env_path)

    setup.run

    expect(env_value('SESSION_SECRET')).not_to be_empty
  end

  it 'rejects an invalid UDAP private key' do
    File.write(
      env_path,
      %(UDAP_CLIENT_PRIVATE_KEY_PEM="not-a-key"\nUDAP_CLIENT_CERTIFICATE_CHAIN_PEM="certificate"\n)
    )

    expect { setup.run }.to raise_error(SafireDemoEnvSetup::SetupError, /valid PEM private key/)
  end

  it 'rejects a public-only UDAP key' do
    key = OpenSSL::PKey::RSA.generate(2048)
    cert = build_certificate(key, uri_san: client_uri)
    File.write(
      env_path,
      [
        %(UDAP_CLIENT_PRIVATE_KEY_PEM="#{key.public_key.to_pem}"\n),
        %(UDAP_CLIENT_CERTIFICATE_CHAIN_PEM="#{cert.to_pem}"\n)
      ].join
    )

    expect { setup.run }.to raise_error(SafireDemoEnvSetup::SetupError, /must contain a PEM private key/)
  end

  it 'rejects an invalid UDAP certificate chain' do
    key = OpenSSL::PKey::RSA.generate(2048)
    invalid_cert = "-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----"
    File.write(
      env_path,
      %(UDAP_CLIENT_PRIVATE_KEY_PEM="#{key.to_pem}"\nUDAP_CLIENT_CERTIFICATE_CHAIN_PEM="#{invalid_cert}"\n)
    )

    expect { setup.run }.to raise_error(SafireDemoEnvSetup::SetupError, /valid PEM certificate chain/)
  end

  it 'rejects an incompatible explicit signing algorithm' do
    key = OpenSSL::PKey::RSA.generate(2048)
    cert = build_certificate(key, uri_san: client_uri)
    write_existing_env(key, cert, algorithm: 'ES256', certifications_file: '')

    expect { setup.run }.to raise_error(SafireDemoEnvSetup::SetupError, /is not compatible/)
  end

  it 'rejects unsupported private-key types when selecting a default algorithm' do
    key = OpenSSL::PKey::DSA.generate(1024)
    cert = build_certificate(key, uri_san: client_uri)
    write_existing_env(key, cert, algorithm: '', certifications_file: '')

    expect { setup.run }.to raise_error(SafireDemoEnvSetup::SetupError, /must be an RSA or NIST/)
  end

  it 'rejects unsupported private-key types with an explicit algorithm' do
    key = OpenSSL::PKey::DSA.generate(1024)
    cert = build_certificate(key, uri_san: client_uri)
    write_existing_env(key, cert, algorithm: 'RS256', certifications_file: '')

    expect { setup.run }.to raise_error(SafireDemoEnvSetup::SetupError, /must be an RSA or NIST/)
  end

  it 'rejects unsupported EC signing curves' do
    key = OpenSSL::PKey::EC.generate('secp521r1')
    cert = build_certificate(key, uri_san: client_uri)
    write_existing_env(key, cert, algorithm: '', certifications_file: '')

    expect { setup.run }.to raise_error(SafireDemoEnvSetup::SetupError, /unsupported EC curve/)
  end

  it 'is idempotent after the initial local setup' do
    setup.run
    first_env = File.read(env_path)
    first_certifications = certification_jwts
    output.truncate(0)
    output.rewind

    setup.run

    aggregate_failures do
      expect(File.read(env_path)).to eq(first_env)
      expect(certification_jwts).to eq(first_certifications)
      expect(output.string).to include('Demo environment already configured.')
    end
  end

  def env_value(key)
    SafireDemoEnvSetup::DotenvDocument.parse(File.read(env_path)).value(key)
  end

  def certification_jwts
    path = File.join(app_root, env_value('UDAP_CLIENT_CERTIFICATIONS_FILE'))
    File.read(path).split
  end

  def decoded_certifications(cert, algorithm: 'RS256')
    certification_jwts.map do |certification|
      JWT.decode(
        certification,
        cert.public_key,
        true,
        algorithms: [algorithm],
        verify_expiration: false
      )
    end
  end

  def write_legacy_managed_certification
    key = OpenSSL::PKey.read(env_value('UDAP_CLIENT_PRIVATE_KEY_PEM'))
    cert = OpenSSL::X509::Certificate.new(env_value('UDAP_CLIENT_CERTIFICATE_CHAIN_PEM'))
    payload = {
      'iss' => client_uri,
      'sub' => client_uri,
      'iat' => now.to_i,
      'exp' => now.to_i + (365 * 24 * 60 * 60),
      'jti' => 'legacy-certification',
      'certification_name' => 'Safire Demo Self-Declaration',
      'certification_uris' => ['https://www.example.com/udap/profiles/example-certification']
    }
    header = { 'x5c' => [Base64.strict_encode64(cert.to_der)] }
    path = File.join(app_root, env_value('UDAP_CLIENT_CERTIFICATIONS_FILE'))

    File.write(path, JWT.encode(payload, key, 'RS256', header))
  end

  def file_mode(path)
    File.stat(path).mode & 0o777
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

  def write_existing_env(key, cert, algorithm: nil, certifications_file: 'data/custom.jwt')
    lines = [
      'SESSION_SECRET=existing-session',
      'ASYMMETRIC_KID=existing-kid',
      %(UDAP_CLIENT_PRIVATE_KEY_PEM="#{key.to_pem}"),
      %(UDAP_CLIENT_CERTIFICATE_CHAIN_PEM="#{cert.to_pem}"),
      "UDAP_CLIENT_CERTIFICATIONS_FILE=#{certifications_file}"
    ]
    lines << %(UDAP_REGISTRATION_SIGNING_ALGORITHM="#{algorithm}") unless algorithm.nil?

    File.write(env_path, "#{lines.join("\n")}\n")
  end

  def build_certificate(key, uri_san:, serial: 1)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = serial
    cert.subject = OpenSSL::X509::Name.parse('/CN=Existing UDAP Client')
    cert.issuer = cert.subject
    cert.public_key = key.is_a?(OpenSSL::PKey::EC) ? key : key.public_key
    cert.not_before = now - 300
    cert.not_after = now + 3600
    cert.add_extension(OpenSSL::X509::ExtensionFactory.new(cert, cert).create_extension('subjectAltName',
                                                                                        "URI:#{uri_san}", false))
    cert.sign(key, OpenSSL::Digest.new('SHA256'))
    cert
  end
end
