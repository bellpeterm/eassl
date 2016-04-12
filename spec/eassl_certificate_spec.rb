require 'eassl'

RSpec.describe EaSSL, "#certificate" do
  context "given a valid CA" do
    
    before(:all) do
      @ca_path = File.join(File.dirname(__FILE__), '../test', 'CA')
      @ca = EaSSL::CertificateAuthority.load(:ca_path => @ca_path, :ca_password => '1234')
      @key = EaSSL::Key.new
      @name = EaSSL::CertificateName.new(:common_name => 'foo.bar.com')
    end

    it "creates a self-signed certificate" do
      csr  = EaSSL::SigningRequest.new(:name => @name, :key => @key)
      cert = EaSSL::Certificate.new(:signing_request => csr)

      expect(cert.subject.to_s).to eq csr.subject.to_s
      expect(cert.subject.to_s).to eq cert.issuer.to_s
    end
    
    it "creates a new certificate" do
      csr  = EaSSL::SigningRequest.new(:name => @name, :key => @key)
      cert = EaSSL::Certificate.new(:signing_request => csr)

      expect(cert.to_pem).to match (/BEGIN CERTIFICATE/)
    end
    
    it "creates a certifcate and signs with a CA cert" do
      csr = EaSSL::SigningRequest.new(:name => @name, :key => @key)
      cert = EaSSL::Certificate.new(:signing_request => csr, :ca_certificate => @ca.certificate)
      cert.sign(@ca.key)

      expect(cert.to_pem).to match (/BEGIN CERTIFICATE/)
      expect(cert.subject.to_s).to eq csr.subject.to_s
      expect(cert.issuer.to_s).to eq @ca.certificate.subject.to_s
    end

    it "sets usage for servers" do
      csr = EaSSL::SigningRequest.new(:name => @name, :key => @key)
      cert = EaSSL::Certificate.new(:signing_request => csr, :ca_certificate => @ca.certificate)
      cert.sign(@ca.key)
      ext_key_usage = cert.extensions.select {|e| e.oid == 'extendedKeyUsage' }.first

      expect(ext_key_usage.value).to eq "TLS Web Server Authentication"
    end

    it "sets usage for clients" do
      csr = EaSSL::SigningRequest.new(:name => @name, :key => @key)
      cert = EaSSL::Certificate.new(:type => 'client', :signing_request => csr, :ca_certificate => @ca.certificate)
      cert.sign(@ca.key)
      ext_key_usage = cert.extensions.select {|e| e.oid == 'extendedKeyUsage' }.first

      expect(ext_key_usage.value).to eq "TLS Web Client Authentication, E-mail Protection"
    end
    
    it "sets usage for peer-to-peer hosts" do
      csr = EaSSL::SigningRequest.new(:name => @name, :key => @key)
      cert = EaSSL::Certificate.new(:type => 'peer', :signing_request => csr, :ca_certificate => @ca.certificate)
      cert.sign(@ca.key)
      ext_key_usage = cert.extensions.select {|e| e.oid == 'extendedKeyUsage' }.first

      expect(ext_key_usage.value).to eq "TLS Web Server Authentication, TLS Web Client Authentication"
    end

    it "sets usage for custom hosts" do
      csr = EaSSL::SigningRequest.new(:name => @name, :key => @key, :extensions => [{:name => "extendedKeyUsage", :value => "clientAuth"}])
      cert = EaSSL::Certificate.new(:type => 'custom', :signing_request => csr, :ca_certificate => @ca.certificate)
      cert.sign(@ca.key)
      ext_key_usage = cert.extensions.select {|e| e.oid == 'extendedKeyUsage' }.first

      expect(ext_key_usage.value).to eq "TLS Web Client Authentication"
    end

    it "sets a subject alternative name" do
      csr = EaSSL::SigningRequest.new(:name => @name, :key => @key)
      cert = EaSSL::Certificate.new(:subject_alt_name => ['bar.com'], :signing_request => csr, :ca_certificate => @ca.certificate)
      cert.sign(@ca.key)
      ext_key_usage = cert.extensions.select {|e| e.oid == 'subjectAltName' }.first

      expect(ext_key_usage.value).to match "DNS:bar.com"
    end
    
    it "sets multiple subject alternative names" do
      csr = EaSSL::SigningRequest.new(:name => @name, :key => @key)
      cert = EaSSL::Certificate.new(:subject_alt_name => ['bar.com', 'foo.com'], :signing_request => csr, :ca_certificate => @ca.certificate)
      cert.sign(@ca.key)
      ext_key_usage = cert.extensions.select {|e| e.oid == 'subjectAltName' }.first

      expect(ext_key_usage.value).to match "DNS:bar.com"
      expect(ext_key_usage.value).to match "DNS:foo.com"
    end

    it "sets multiple subject alternative names with different types" do
      csr = EaSSL::SigningRequest.new(:name => @name, :key => @key)
      cert = EaSSL::Certificate.new(:subject_alt_name => ['bar.com', 'foo.com', {:name => "IP", :value => "127.0.0.1"}], :signing_request => csr, :ca_certificate => @ca.certificate)
      cert.sign(@ca.key)
      ext_key_usage = cert.extensions.select {|e| e.oid == 'subjectAltName' }.first

      expect(ext_key_usage.value).to match "DNS:bar.com"
      expect(ext_key_usage.value).to match "DNS:foo.com"
      expect(ext_key_usage.value).to match "IP Address:127.0.0.1"
    end

    it "loads and verifies a certificate fingerprint" do
      file = File.join(File.dirname(__FILE__), '../test', 'certificate.pem')
      cert = EaSSL::Certificate.load(file)

      expect(cert.sha1_fingerprint).to eq "55:27:E8:46:50:03:39:F4:A3:24:3D:88:57:BA:67:5C:F1:E8:84:1D"
    end

    it "verifies a given text certificate fingerprint" do
      cert_text = <<CERT
-----BEGIN CERTIFICATE-----
MIIDzzCCAzigAwIBAgIBAjANBgkqhkiG9w0BAQUFADA8MQswCQYDVQQGEwJVUzEO
MAwGA1UECgwFVmVuZGExEDAOBgNVBAsMB2F1dG8tQ0ExCzAJBgNVBAMMAkNBMB4X
DTExMTIwNzE5MTIxN1oXDTE2MTIwNTE5MTIxN1owgakxCzAJBgNVBAYTAlVTMRcw
FQYDVQQIEw5Ob3J0aCBDYXJvbGluYTEWMBQGA1UEBxMNRnVxdWF5IFZhcmluYTEY
MBYGA1UECgwPV2ViUG93ZXIgRGVzaWduMRUwEwYDVQQLDAxXZWIgU2VjdXJpdHkx
FDASBgNVBAMMC2Zvby5iYXIuY29tMSIwIAYJKoZIhvcNAQkBDBNlYXNzbEBydWJ5
Zm9yZ2Uub3JnMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyqWgYizb
EaafCYheeaTCGLK4FOq42e2CavOComQlWXEGR2YHYOL/cPK9Lpc+f/4qxse8SChx
1maDuUh+iT+fNa/jqbBExmK7h914mXW2pcZCfbboND0Va9wLm63HsMVwY2FGDC9P
Qh5hviVfIoGVbC2ZDI1pt98pexPsSOSHn2ch1q4s/9pfICnWN+KsEyNJuBwlo24t
Eg+zvnVE9w3YzlSQ7NCgPFf1aX2VBWZi50gbAwoxoKyrtZFQ/tIrF6WtMxYTpfYq
LYWLMsb9+xZHkhEc+XvvipD6Y25tlyDWoFOR3sy0B5SZGoik9ZD1bTCWHdEtNRzG
cRoChZSCv9+LeQIDAQABo4HuMIHrMAkGA1UdEwQCMAAwCwYDVR0PBAQDAgWgMB0G
A1UdDgQWBBT6dj30hJuziSwhPx9PnsTyGCi3BjATBgNVHSUEDDAKBggrBgEFBQcD
ATA3BglghkgBhvhCAQ0EKhYoUnVieS9PcGVuU1NML0VhU1NMIEdlbmVyYXRlZCBD
ZXJ0aWZpY2F0ZTBkBgNVHSMEXTBbgBT+n8Ml3oKlSBBaeaaDrWFS9THk5aFApD4w
PDELMAkGA1UEBhMCVVMxDjAMBgNVBAoMBVZlbmRhMRAwDgYDVQQLDAdhdXRvLUNB
MQswCQYDVQQDDAJDQYIBADANBgkqhkiG9w0BAQUFAAOBgQBjN8LEARLiWjxV0o6U
XSM4ubws0pAXya34TIAQnlDKEEssZ0i1IYyyqieCkdaH+n0wnhGLwGf21yyrqCLd
+nDavx/2EBrDcF0yE7aapzXcfeXZ2gZxkZycuwc8dKR6IEXLWrMYS7HKyT490G0R
XBbgCxQiIndLwRnNMavd+vx0Wg==
-----END CERTIFICATE-----
CERT
      cert = EaSSL::Certificate.new({}).load(cert_text)

      expect(cert.sha1_fingerprint).to eq "55:27:E8:46:50:03:39:F4:A3:24:3D:88:57:BA:67:5C:F1:E8:84:1D"
    end

    it "fails to load a non-existent file" do
      expect {key = EaSSL::Certificate.load('./foo')}.to raise_error(Errno::ENOENT)
    end
    
    it "fails to load a non-certificate file" do
      file = File.join(File.dirname(__FILE__), '..', 'Rakefile')
      expect {key = EaSSL::Certificate.load(file)}.to raise_error(RuntimeError)
    end
  end
end
