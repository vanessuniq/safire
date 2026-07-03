module UdapCertificateHelpers
  def build_udap_certificate(key:, uri_san:, subject: '/CN=UDAP Client', issuer_cert: nil, issuer_key: nil,
                             not_before: Time.now - 60, not_after: Time.now + 3600, serial: 1)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = serial
    cert.subject = OpenSSL::X509::Name.parse(subject)
    cert.issuer = issuer_cert&.subject || cert.subject
    cert.public_key = key
    cert.not_before = not_before
    cert.not_after = not_after

    extension_factory = OpenSSL::X509::ExtensionFactory.new(issuer_cert || cert, cert)
    cert.add_extension(extension_factory.create_extension('subjectAltName', "URI:#{uri_san}", false)) if uri_san

    cert.sign(issuer_key || key, OpenSSL::Digest.new('SHA256'))
    cert
  end
end
