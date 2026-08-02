# frozen_string_literal: true

require 'base64'
require 'fileutils'
require 'jwt'
require 'openssl'
require 'pathname'
require 'securerandom'
require 'time'

# Idempotently prepares ignored local environment files for the Sinatra demo.
class SafireDemoEnvSetup
  APP_ROOT = File.expand_path('..', __dir__)
  DEFAULT_ENV_PATH = File.join(APP_ROOT, '.env')
  DEFAULT_EXAMPLE_ENV_PATH = File.join(APP_ROOT, '.env.example')
  DEFAULT_CERTIFICATIONS_FILE = 'data/udap_self_signed_certification.jwt'
  DEFAULT_CLIENT_NAME = 'Safire Demo App'
  DEFAULT_CONTACTS = 'mailto:admin@example.com'
  DEFAULT_SIGNING_ALGORITHM = 'RS256'
  CERTIFICATION_URIS = ['https://www.example.com/udap/profiles/example-certification'].freeze
  PLACEHOLDER_SNIPPETS = [
    'your_session_secret_here',
    'my-app-key-001',
    '...your private key content here...',
    '...your key content...',
    '...your UDAP client private key content here...',
    '...your UDAP client leaf certificate...'
  ].freeze

  Assignment = Struct.new(:key, :raw)

  class DotenvDocument
    ASSIGNMENT_PATTERN = /\A\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=/

    def self.parse(text)
      new(parse_entries(text))
    end

    def self.parse_entries(text)
      lines = text.to_s.lines
      entries = []
      index = 0
      while index < lines.length
        entry, index = parse_entry(lines, index)
        entries << entry
      end
      entries
    end

    def self.parse_entry(lines, index)
      raw = lines[index].dup
      key = raw[ASSIGNMENT_PATTERN, 1]
      return [raw, index + 1] unless key

      quote = assignment_quote(raw)
      while quote && !closed_quote?(raw, quote) && index + 1 < lines.length
        index += 1
        raw << lines[index]
      end

      [Assignment.new(key, raw), index + 1]
    end

    def self.assignment_quote(raw)
      value = raw.split('=', 2).last.to_s.lstrip
      quote = value[0]
      %w[" '].include?(quote) ? quote : nil
    end

    def self.closed_quote?(raw, quote)
      raw.split('=', 2).last.to_s.lstrip[1..].to_s.match?(/(?<!\\)#{Regexp.escape(quote)}\s*(?:#.*)?\z/m)
    end

    def initialize(entries)
      @entries = entries
    end

    def value(key)
      entry = assignment_for(key)
      entry && self.class.unquote(entry.raw.split('=', 2).last.to_s)
    end

    def set(key, value)
      rendered = Assignment.new(key, "#{key}=#{self.class.quote(value)}\n")
      index = @entries.index { |entry| assignment_key(entry) == key }
      @entries.reject! { |entry| assignment_key(entry) == key }
      index ? @entries.insert(index, rendered) : append(rendered)
    end

    def to_s
      @entries.map { |entry| entry.is_a?(Assignment) ? entry.raw : entry }.join
    end

    def self.quote(value)
      value = value.to_s
      value = value.encode(Encoding::UTF_8)
      return value if value.match?(%r{\A[A-Za-z0-9_.:/@-]+\z})

      escaped = value.gsub('\\', '\\\\\\').gsub('"', '\"')
      "\"#{escaped}\""
    end

    def self.unquote(value)
      stripped = value.strip
      quote = surrounding_quote(stripped)
      return stripped unless quote

      body = stripped[1...-1].to_s
      body.gsub("\\#{quote}", quote).gsub('\\\\', '\\')
    end

    def self.quoted?(value)
      !surrounding_quote(value).nil?
    end

    def self.surrounding_quote(value)
      return unless value.length >= 2
      return value[0] if %w[" '].include?(value[0]) && value[-1] == value[0]

      nil
    end

    private

    def append(entry)
      @entries << "\n" unless @entries.empty? || @entries.last.to_s.end_with?("\n\n")
      @entries << entry
    end

    def assignment_for(key)
      @entries.find { |entry| assignment_key(entry) == key }
    end

    def assignment_key(entry)
      entry.is_a?(Assignment) ? entry.key : nil
    end
  end

  def initialize(app_root: APP_ROOT, env_path: File.join(app_root, '.env'),
                 example_env_path: File.join(app_root, '.env.example'),
                 output: $stdout, client_uri: nil, now: Time.now)
    @app_root = app_root
    @env_path = env_path
    @example_env_path = example_env_path
    @output = output
    @client_uri = client_uri || "http://localhost:#{ENV.fetch('PORT', '4567')}"
    @now = now
    @changed = []
  end

  def run
    @changed = []
    @client_certificate = nil
    document = DotenvDocument.parse(seed_env_content)
    prepare_environment(document)
    write_env(document)
    ensure_certification_file(document)
    report
  end

  private

  attr_reader :app_root, :env_path, :example_env_path, :output, :client_uri, :now

  def seed_env_content
    if File.exist?(env_path)
      content = File.read(env_path)
      return content unless content.empty?
    end

    return File.read(example_env_path) if File.exist?(example_env_path)

    "# Safire Demo App Environment Configuration\n"
  end

  def prepare_environment(document)
    (generated_environment_defaults(document) + static_environment_defaults).each do |key, generator|
      set_if_absent(document, key, &generator)
    end
  end

  def generated_environment_defaults(document)
    [
      ['SESSION_SECRET', -> { SecureRandom.hex(32) }],
      ['ASYMMETRIC_PRIVATE_KEY_PEM', -> { generate_rsa_key.to_pem }],
      ['ASYMMETRIC_KID', -> { "safire-demo-#{SecureRandom.hex(8)}" }],
      ['UDAP_CLIENT_PRIVATE_KEY_PEM', -> { generate_rsa_key.to_pem }],
      ['UDAP_CLIENT_CERTIFICATE_CHAIN_PEM', -> { client_certificate(document).to_pem }]
    ]
  end

  def static_environment_defaults
    [
      ['UDAP_CLIENT_NAME', -> { DEFAULT_CLIENT_NAME }],
      ['UDAP_CLIENT_CONTACTS', -> { DEFAULT_CONTACTS }],
      ['UDAP_CLIENT_LOGO_URI', -> { "#{client_uri}/safire-demo-logo.png" }],
      ['UDAP_REGISTRATION_SIGNING_ALGORITHM', -> { DEFAULT_SIGNING_ALGORITHM }],
      ['UDAP_CLIENT_CERTIFICATIONS_FILE', -> { DEFAULT_CERTIFICATIONS_FILE }]
    ]
  end

  def set_if_absent(document, key)
    return unless absent?(document.value(key))

    document.set(key, yield)
    @changed << key
  end

  def absent?(value)
    value.to_s.strip.empty? || PLACEHOLDER_SNIPPETS.any? { |snippet| value.include?(snippet) }
  end

  def generate_rsa_key
    OpenSSL::PKey::RSA.generate(2048)
  end

  def client_certificate(document)
    @client_certificate ||= begin
      key = OpenSSL::PKey.read(document.value('UDAP_CLIENT_PRIVATE_KEY_PEM'))
      build_client_certificate(key)
    end
  end

  def build_client_certificate(key)
    cert = OpenSSL::X509::Certificate.new
    assign_certificate_identity(cert, key)
    assign_certificate_validity(cert)
    add_certificate_extensions(cert)
    cert.sign(key, OpenSSL::Digest.new('SHA256'))
    cert
  end

  def assign_certificate_identity(cert, key)
    cert.version = 2
    cert.serial = SecureRandom.random_number(2**128)
    cert.subject = OpenSSL::X509::Name.parse('/CN=Safire Demo UDAP Client')
    cert.issuer = cert.subject
    cert.public_key = key.public_key
  end

  def assign_certificate_validity(cert)
    cert.not_before = now - 300
    cert.not_after = now + (365 * 24 * 60 * 60)
  end

  def add_certificate_extensions(cert)
    extension_factory = OpenSSL::X509::ExtensionFactory.new(cert, cert)
    cert.add_extension(extension_factory.create_extension('basicConstraints', 'CA:FALSE', true))
    cert.add_extension(extension_factory.create_extension('keyUsage', 'digitalSignature', true))
    cert.add_extension(extension_factory.create_extension('extendedKeyUsage', 'clientAuth', false))
    cert.add_extension(extension_factory.create_extension('subjectAltName', "URI:#{client_uri}", false))
  end

  def write_env(document)
    FileUtils.mkdir_p(File.dirname(env_path))
    File.write(env_path, document.to_s)
  end

  def ensure_certification_file(document)
    path = certification_file_path(document)
    return if File.exist?(path) && !File.read(path).strip.empty?

    FileUtils.mkdir_p(File.dirname(path))
    File.write(path, "#{certification_jwt(document)}\n")
    @changed << document.value('UDAP_CLIENT_CERTIFICATIONS_FILE')
  end

  def certification_file_path(document)
    path = document.value('UDAP_CLIENT_CERTIFICATIONS_FILE')
    return path if Pathname.new(path).absolute?

    File.expand_path(path, app_root)
  end

  def certification_jwt(document)
    key = OpenSSL::PKey.read(document.value('UDAP_CLIENT_PRIVATE_KEY_PEM'))
    cert = OpenSSL::X509::Certificate.new(document.value('UDAP_CLIENT_CERTIFICATE_CHAIN_PEM'))
    JWT.encode(certification_payload, key, DEFAULT_SIGNING_ALGORITHM, certification_header(cert))
  end

  def certification_header(cert)
    {
      'alg' => DEFAULT_SIGNING_ALGORITHM,
      'x5c' => [Base64.strict_encode64(cert.to_der)]
    }
  end

  def certification_payload
    timestamp = now.to_i
    {
      'iss' => client_uri,
      'sub' => client_uri,
      'iat' => timestamp,
      'exp' => timestamp + (365 * 24 * 60 * 60),
      'jti' => SecureRandom.uuid,
      'certification_name' => 'Safire Demo Self-Declaration',
      'certification_uris' => CERTIFICATION_URIS,
      'client_name' => DEFAULT_CLIENT_NAME,
      'client_uri' => client_uri,
      'contacts' => [DEFAULT_CONTACTS]
    }
  end

  def report
    if @changed.empty?
      output.puts 'Demo environment already configured.'
    else
      output.puts "Prepared demo environment: #{@changed.join(', ')}"
    end
  end
end

SafireDemoEnvSetup.new.run if $PROGRAM_NAME == __FILE__
