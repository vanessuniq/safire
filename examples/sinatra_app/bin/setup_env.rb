# frozen_string_literal: true

require 'base64'
require 'fileutils'
require 'jwt'
require 'openssl'
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
  PRIVATE_KEY_ENV = 'UDAP_CLIENT_PRIVATE_KEY_PEM'
  CERTIFICATE_CHAIN_ENV = 'UDAP_CLIENT_CERTIFICATE_CHAIN_PEM'
  SIGNING_ALGORITHM_ENV = 'UDAP_REGISTRATION_SIGNING_ALGORITHM'
  CERTIFICATIONS_FILE_ENV = 'UDAP_CLIENT_CERTIFICATIONS_FILE'
  CERTIFICATION_URIS = ['https://www.example.com/udap/profiles/example-certification'].freeze
  PLACEHOLDER_SNIPPETS = [
    'your_session_secret_here',
    'my-app-key-001',
    '...your private key content here...',
    '...your key content...',
    '...your UDAP client private key content here...',
    '...your UDAP client leaf certificate...'
  ].freeze
  PLACEHOLDER_PATTERN = Regexp.union(PLACEHOLDER_SNIPPETS).freeze
  CERTIFICATE_PATTERN = /-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/m
  DEFAULT_ALGORITHMS_BY_KEY = {
    rsa: DEFAULT_SIGNING_ALGORITHM,
    'prime256v1' => 'ES256',
    'secp256r1' => 'ES256',
    'secp384r1' => 'ES384'
  }.freeze
  COMPATIBLE_RSA_ALGORITHMS = %w[RS256 RS384].freeze
  SECURE_FILE_MODE = 0o600

  Assignment = Struct.new(:key, :raw)

  class SetupError < StandardError; end

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

      escaped = value.gsub(/[\\"]/) { |character| "\\#{character}" }
      "\"#{escaped}\""
    end

    def self.unquote(value)
      stripped = value.strip
      quote = surrounding_quote(stripped)
      return stripped unless quote

      body = stripped[1...-1].to_s
      body.gsub("\\#{quote}", quote).gsub('\\\\', '\\')
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
    @udap_private_key = nil
    @udap_leaf_certificate = nil
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
    generated_environment_defaults.each do |key, generator|
      set_if_absent(document, key, &generator)
    end

    prepare_udap_signing_identity(document)

    static_environment_defaults(document).each do |key, generator|
      set_if_absent(document, key, &generator)
    end

    validate_registration_signing_algorithm!(document)
  end

  def generated_environment_defaults
    [
      ['SESSION_SECRET', -> { SecureRandom.hex(32) }],
      ['ASYMMETRIC_PRIVATE_KEY_PEM', -> { generate_rsa_key.to_pem }],
      ['ASYMMETRIC_KID', -> { "safire-demo-#{SecureRandom.hex(8)}" }]
    ]
  end

  def prepare_udap_signing_identity(document)
    key_absent = absent?(document.value(PRIVATE_KEY_ENV))
    certificate_absent = absent?(document.value(CERTIFICATE_CHAIN_ENV))

    if key_absent && certificate_absent
      generate_udap_signing_pair(document)
    elsif key_absent || certificate_absent
      raise SetupError, "#{PRIVATE_KEY_ENV} and #{CERTIFICATE_CHAIN_ENV} must be configured together"
    else
      validate_udap_signing_pair!(document)
    end
  end

  def generate_udap_signing_pair(document)
    @udap_private_key = generate_rsa_key
    @udap_leaf_certificate = build_client_certificate(@udap_private_key)

    document.set(PRIVATE_KEY_ENV, @udap_private_key.to_pem)
    document.set(CERTIFICATE_CHAIN_ENV, @udap_leaf_certificate.to_pem)
    @changed << PRIVATE_KEY_ENV
    @changed << CERTIFICATE_CHAIN_ENV
  end

  def static_environment_defaults(document)
    [
      ['UDAP_CLIENT_NAME', -> { DEFAULT_CLIENT_NAME }],
      ['UDAP_CLIENT_CONTACTS', -> { DEFAULT_CONTACTS }],
      ['UDAP_CLIENT_LOGO_URI', -> { "#{client_uri}/safire-demo-logo.png" }],
      [SIGNING_ALGORITHM_ENV, -> { default_algorithm_for_key(udap_private_key(document)) }],
      [CERTIFICATIONS_FILE_ENV, -> { DEFAULT_CERTIFICATIONS_FILE }]
    ]
  end

  def set_if_absent(document, key)
    return unless absent?(document.value(key))

    document.set(key, yield)
    @changed << key
  end

  def absent?(value)
    string = value.to_s

    string.strip.empty? || PLACEHOLDER_PATTERN.match?(string)
  end

  def generate_rsa_key
    OpenSSL::PKey::RSA.generate(2048)
  end

  def validate_udap_signing_pair!(document)
    key = udap_private_key(document)
    cert = udap_leaf_certificate(document)
    return if cert.check_private_key(key)

    raise SetupError, "#{PRIVATE_KEY_ENV} does not match #{CERTIFICATE_CHAIN_ENV}"
  end

  def udap_private_key(document)
    @udap_private_key ||= parse_private_key(document.value(PRIVATE_KEY_ENV))
  end

  def parse_private_key(pem)
    key = OpenSSL::PKey.read(pem.to_s)
    return key if key.private?

    raise SetupError, "#{PRIVATE_KEY_ENV} must contain a PEM private key"
  rescue OpenSSL::PKey::PKeyError
    raise SetupError, "#{PRIVATE_KEY_ENV} must contain a valid PEM private key"
  end

  def udap_leaf_certificate(document)
    @udap_leaf_certificate ||= parse_leaf_certificate(document.value(CERTIFICATE_CHAIN_ENV))
  end

  def parse_leaf_certificate(pem)
    leaf_pem = pem.to_s[CERTIFICATE_PATTERN]
    raise SetupError, "#{CERTIFICATE_CHAIN_ENV} must contain at least one PEM certificate" unless leaf_pem

    OpenSSL::X509::Certificate.new(leaf_pem)
  rescue OpenSSL::X509::CertificateError
    raise SetupError, "#{CERTIFICATE_CHAIN_ENV} must contain a valid PEM certificate chain"
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
    secure_write(env_path, document.to_s)
  end

  def ensure_certification_file(document)
    path = certification_file_path(document)
    return if populated_certification_file?(path)

    unless path == managed_certification_file_path
      raise SetupError,
            "#{CERTIFICATIONS_FILE_ENV} must reference an existing non-empty file when set to a custom path; " \
            "leave it blank to generate #{DEFAULT_CERTIFICATIONS_FILE}"
    end

    FileUtils.mkdir_p(File.dirname(path))
    secure_write(path, "#{certification_jwt(document)}\n")
    @changed << document.value(CERTIFICATIONS_FILE_ENV)
  end

  def certification_file_path(document)
    File.expand_path(document.value(CERTIFICATIONS_FILE_ENV), app_root)
  end

  def managed_certification_file_path
    File.expand_path(DEFAULT_CERTIFICATIONS_FILE, app_root)
  end

  def populated_certification_file?(path)
    return false unless File.exist?(path)
    raise SetupError, "#{CERTIFICATIONS_FILE_ENV} must reference a regular file" unless File.file?(path)

    !File.read(path).strip.empty?
  rescue Errno::EACCES, Errno::ENOENT, Errno::ENOTDIR
    raise SetupError, "#{CERTIFICATIONS_FILE_ENV} must reference a readable file"
  end

  def certification_jwt(document)
    algorithm = registration_signing_algorithm(document)

    JWT.encode(
      certification_payload,
      udap_private_key(document),
      algorithm,
      certification_header(udap_leaf_certificate(document), algorithm)
    )
  end

  def certification_header(cert, algorithm)
    {
      'alg' => algorithm,
      'x5c' => [Base64.strict_encode64(cert.to_der)]
    }
  end

  def registration_signing_algorithm(document)
    document.value(SIGNING_ALGORITHM_ENV).to_s.strip
  end

  def validate_registration_signing_algorithm!(document)
    algorithm = registration_signing_algorithm(document)
    return if compatible_algorithms_for_key(udap_private_key(document)).include?(algorithm)

    raise SetupError, "#{SIGNING_ALGORITHM_ENV}=#{algorithm} is not compatible with #{PRIVATE_KEY_ENV}"
  end

  def default_algorithm_for_key(key)
    return DEFAULT_ALGORITHMS_BY_KEY.fetch(:rsa) if key.is_a?(OpenSSL::PKey::RSA)
    return algorithm_for_ec_key(key) if key.is_a?(OpenSSL::PKey::EC)

    raise SetupError, "#{PRIVATE_KEY_ENV} must be an RSA or NIST P-256/P-384 EC private key"
  end

  def compatible_algorithms_for_key(key)
    return COMPATIBLE_RSA_ALGORITHMS if key.is_a?(OpenSSL::PKey::RSA)
    return [algorithm_for_ec_key(key)] if key.is_a?(OpenSSL::PKey::EC)

    raise SetupError, "#{PRIVATE_KEY_ENV} must be an RSA or NIST P-256/P-384 EC private key"
  end

  def algorithm_for_ec_key(key)
    curve_name = key.group.curve_name
    DEFAULT_ALGORITHMS_BY_KEY.fetch(curve_name) do
      raise SetupError, "#{PRIVATE_KEY_ENV} uses unsupported EC curve #{curve_name.inspect}"
    end
  end

  def secure_write(path, content)
    directory = File.dirname(path)
    temp_path = File.join(directory, ".#{File.basename(path)}.tmp-#{Process.pid}-#{SecureRandom.hex(8)}")

    File.open(temp_path, File::WRONLY | File::CREAT | File::EXCL, SECURE_FILE_MODE) do |file|
      file.write(content)
      file.flush
      file.fsync
    end
    File.rename(temp_path, path)
    FileUtils.chmod(SECURE_FILE_MODE, path)
  ensure
    FileUtils.rm_f(temp_path) if temp_path && File.exist?(temp_path)
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

if $PROGRAM_NAME == __FILE__
  begin
    SafireDemoEnvSetup.new.run
  rescue SafireDemoEnvSetup::SetupError => e
    warn "Demo environment setup failed: #{e.message}"
    exit 1
  end
end
