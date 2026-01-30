# frozen_string_literal: true

require 'yaml'
require 'securerandom'
require 'fileutils'
require 'uri'

# Simple model for FHIR server configurations with YAML persistence
class FhirServer
  DATA_FILE = File.join(__dir__, '..', 'data', 'servers.yml')

  ATTRIBUTES = %i[id name base_url client_id client_secret scopes].freeze

  attr_accessor(*ATTRIBUTES)
  attr_reader :errors

  def initialize(attrs = {})
    ATTRIBUTES.each { |attr| send(:"#{attr}=", extract_attr(attrs, attr)) }
    @scopes ||= []
    @errors = []
  end

  def valid?
    @errors = []
    validate_presence
    validate_url_format
    validate_url_uniqueness
    @errors.empty?
  end

  # Save handles both create (new record) and update (existing record)
  def save
    @id ||= SecureRandom.uuid
    servers = self.class.load_all
    servers[@id] = to_hash
    self.class.save_all(servers)
    self
  end

  def destroy
    servers = self.class.load_all
    servers.delete(@id)
    self.class.save_all(servers)
  end

  def to_hash
    ATTRIBUTES.to_h { |attr| [attr.to_s, send(attr)] }
  end

  def confidential?
    !client_secret.to_s.empty?
  end

  def scopes_display
    scopes.is_a?(Array) ? scopes.join(', ') : scopes.to_s
  end

  class << self
    def all
      load_all.values.map { |attrs| new(attrs) }
    end

    def find(id)
      servers = load_all
      return nil unless servers[id]

      new(servers[id])
    end

    def find_by_base_url(url)
      normalized_url = normalize_url(url)

      # First try exact URL match
      exact_match = all.find { |s| normalize_url(s.base_url) == normalized_url }
      return exact_match if exact_match

      # Fallback: try matching by origin (scheme + host) for EHR launch where iss path may differ
      url_origin = extract_origin(url)
      all.find { |s| extract_origin(s.base_url) == url_origin } if url_origin
    end

    def load_all
      ensure_data_file
      YAML.load_file(DATA_FILE) || {}
    rescue Errno::ENOENT
      {}
    end

    def save_all(servers)
      ensure_data_dir
      File.write(DATA_FILE, servers.to_yaml)
    end

    private

    def normalize_url(url)
      url.to_s.strip.chomp('/')
    end

    def extract_origin(url)
      uri = URI.parse(url.to_s)
      return nil unless uri.host

      "#{uri.scheme}://#{uri.host}"
    rescue URI::InvalidURIError
      nil
    end

    def ensure_data_dir
      dir = File.dirname(DATA_FILE)
      FileUtils.mkdir_p(dir) unless File.directory?(dir)
    end

    def ensure_data_file
      ensure_data_dir
      File.write(DATA_FILE, {}.to_yaml) unless File.exist?(DATA_FILE)
    end
  end

  private

  def extract_attr(attrs, key)
    attrs[key] || attrs[key.to_s]
  end

  def validate_presence
    @errors << 'Name is required' if blank?(name)
    @errors << 'Base URL is required' if blank?(base_url)
    @errors << 'Client ID is required' if blank?(client_id)
  end

  def validate_url_format
    return if blank?(base_url)

    uri = URI.parse(base_url)
    @errors << 'Base URL must be a valid HTTP(S) URL' unless uri.is_a?(URI::HTTP)
  rescue URI::InvalidURIError
    @errors << 'Base URL is not a valid URL'
  end

  def validate_url_uniqueness
    return if blank?(base_url)

    existing = self.class.find_by_base_url(base_url)
    @errors << 'Base URL is already configured for another server' if existing && existing.id != @id
  end

  def blank?(value)
    value.to_s.strip.empty?
  end
end
