module UdapCertificateHelpers
  def build_udap_certificate(key:, uri_san:, subject: '/CN=UDAP Client', issuer_cert: nil, issuer_key: nil,
                             not_before: Time.now - 60, not_after: Time.now + 3600, serial: 1,
                             structural_san: false)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = serial
    cert.subject = OpenSSL::X509::Name.parse(subject)
    cert.issuer = issuer_cert&.subject || cert.subject
    cert.public_key = key
    cert.not_before = not_before
    cert.not_after = not_after

    extension_factory = OpenSSL::X509::ExtensionFactory.new(issuer_cert || cert, cert)
    if uri_san
      cert.add_extension(
        subject_alt_name_extension(extension_factory, uri_san, structural: structural_san)
      )
    end

    cert.sign(issuer_key || key, OpenSSL::Digest.new('SHA256'))
    cert
  end

  def uri_san_extension(uri)
    general_name = OpenSSL::ASN1::ASN1Data.new(uri, 6, :CONTEXT_SPECIFIC)
    general_names = OpenSSL::ASN1::Sequence([general_name])

    OpenSSL::X509::Extension.new('subjectAltName', general_names.to_der, false)
  end

  def subject_alt_name_extension(extension_factory, uri, structural:)
    return uri_san_extension(uri) if structural

    extension_factory.create_extension('subjectAltName', "URI:#{uri}", false)
  end
end
