require 'openssl'
require 'securerandom'

module SafireCompliance
  # A throwaway self-signed TLS identity for +localhost+, generated in memory per run.
  #
  # Inferno's client suite requires registered redirect and launch URIs to use +https+, so the
  # harness app serves them over TLS. Only the harness user agent connects to that server, and it
  # trusts exactly this certificate. Nothing is written to disk.
  class TLSIdentity
    attr_reader :key, :certificate

    def initialize
      @key = OpenSSL::PKey::RSA.generate(2048)
      @certificate = build_certificate
    end

    # @return [OpenSSL::X509::Store] a store that trusts only this certificate
    def cert_store
      OpenSSL::X509::Store.new.tap { |store| store.add_cert(@certificate) }
    end

    # @return [OpenSSL::SSL::SSLContext] server context presenting this identity
    def server_context
      OpenSSL::SSL::SSLContext.new.tap do |ctx|
        ctx.cert = @certificate
        ctx.key = @key
      end
    end

    private

    def build_certificate
      cert = OpenSSL::X509::Certificate.new
      cert.version = 2
      cert.serial = SecureRandom.random_number(2**64)
      cert.subject = cert.issuer = OpenSSL::X509::Name.parse('/CN=localhost')
      cert.public_key = @key
      apply_validity(cert)
      add_extensions(cert)
      cert.sign(@key, OpenSSL::Digest.new('SHA256'))
      cert
    end

    def apply_validity(cert)
      cert.not_before = Time.now - 60
      cert.not_after = Time.now + 3600
    end

    def add_extensions(cert)
      ext = OpenSSL::X509::ExtensionFactory.new
      ext.subject_certificate = ext.issuer_certificate = cert
      cert.add_extension(ext.create_extension('basicConstraints', 'CA:TRUE', true))
      cert.add_extension(ext.create_extension('keyUsage', 'keyCertSign,digitalSignature,keyEncipherment', true))
      cert.add_extension(ext.create_extension('subjectAltName', 'DNS:localhost,IP:127.0.0.1'))
    end
  end
end
