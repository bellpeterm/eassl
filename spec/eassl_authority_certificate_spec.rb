require 'eassl'

RSpec.describe EaSSL, "#certficate_authorities" do
  context "with no prior keys/certs" do

    before(:all) do
      @ca = EaSSL::CertificateAuthority.new
      @key = EaSSL::Key.new
      @name = EaSSL::CertificateName.new(
        :country => 'GB',
        :state => 'London',
        :city => 'London',
        :organization => 'Venda Ltd',
        :department => 'Development',
        :common_name => 'foo.bar.com',
        :email => 'dev@venda.com'
      )
    end

    it "creates a basic certificate authority" do
      expect(@ca.key.length).to eq 2048
      expect(@ca.certificate.subject.to_s).to eq "/CN=CA"
    end
    
    it "can properly sign a server certificate" do
      csr = EaSSL::SigningRequest.new(:name => @name, :key => @key)
      cert = @ca.create_certificate(csr)
      ext_key_usage = cert.extensions.select {|e| e.oid == 'extendedKeyUsage' }.first.value

      expect(cert.issuer.to_s).to eq "/CN=CA"
      expect(cert.subject.to_s).to eq "/C=GB/ST=London/L=London/O=Venda Ltd/OU=Development/CN=foo.bar.com/emailAddress=dev@venda.com"
      expect(ext_key_usage).to eq "TLS Web Server Authentication"
    end

    it "can properly sign a client certificate" do
      csr = EaSSL::SigningRequest.new(:name => @name, :key => @key)
      cert = @ca.create_certificate(csr, 'client')
      ext_key_usage = cert.extensions.select {|e| e.oid == 'extendedKeyUsage' }.first.value

      expect(cert.issuer.to_s).to eq "/CN=CA"
      expect(cert.subject.to_s).to eq "/C=GB/ST=London/L=London/O=Venda Ltd/OU=Development/CN=foo.bar.com/emailAddress=dev@venda.com"
      expect(ext_key_usage).to eq "TLS Web Client Authentication, E-mail Protection"
    end
    
    it "properly sets expiry on a certificate" do
      csr = EaSSL::SigningRequest.new(:name => @name, :key => @key)
      t = Time.now
      cert = @ca.create_certificate(csr, 'server', 10)
      ext_key_usage = cert.extensions.select {|e| e.oid == 'extendedKeyUsage' }.first.value
      
      expect(cert.ssl.not_after.to_i).to eq (t + (24 * 60 * 60 * 10)).to_i
    end

  end
  context "given certificate information but not keys/certs" do

    before(:all) do
      @ca = EaSSL::CertificateAuthority.new(:name => {
        :country => 'GB',
        :state => 'London',
        :city => 'London',
        :organization => 'Venda Ltd',
        :department => 'Development',
        :common_name => 'CA',
        :email => 'dev@venda.com'
      })
      @key = EaSSL::Key.new
      @name = EaSSL::CertificateName.new(
        :country => 'GB',
        :state => 'London',
        :city => 'London',
        :organization => 'Venda Ltd',
        :department => 'Development',
        :common_name => 'foo.bar.com',
        :email => 'dev@venda.com'
      )
    end

    it "creates a valid CA certificate" do
      expect(@ca.certificate.subject.to_s).to eq "/C=GB/ST=London/L=London/O=Venda Ltd/OU=Development/CN=CA/emailAddress=dev@venda.com"
      expect(@ca.key.length).to eq 2048
      expect(@ca.serial).to be_a EaSSL::Serial
    end

    it "can properly sign a server certificate" do
      csr = EaSSL::SigningRequest.new(:name => @name, :key => @key)
      cert = @ca.create_certificate(csr)
      ext_key_usage = cert.extensions.select {|e| e.oid == 'extendedKeyUsage' }.first.value

      expect(cert.issuer.to_s).to eq "/C=GB/ST=London/L=London/O=Venda Ltd/OU=Development/CN=CA/emailAddress=dev@venda.com"
      expect(cert.subject.to_s).to eq "/C=GB/ST=London/L=London/O=Venda Ltd/OU=Development/CN=foo.bar.com/emailAddress=dev@venda.com"
      expect(ext_key_usage).to eq "TLS Web Server Authentication"
    end

    it "can properly sign a client certificate" do
      csr = EaSSL::SigningRequest.new(:name => @name, :key => @key)
      cert = @ca.create_certificate(csr, 'client')
      ext_key_usage = cert.extensions.select {|e| e.oid == 'extendedKeyUsage' }.first.value

      expect(cert.issuer.to_s).to eq "/C=GB/ST=London/L=London/O=Venda Ltd/OU=Development/CN=CA/emailAddress=dev@venda.com"
      expect(cert.subject.to_s).to eq "/C=GB/ST=London/L=London/O=Venda Ltd/OU=Development/CN=foo.bar.com/emailAddress=dev@venda.com"
      expect(ext_key_usage).to eq "TLS Web Client Authentication, E-mail Protection"
    end
    
    it "properly sets expiry on a certificate" do
      csr = EaSSL::SigningRequest.new(:name => @name, :key => @key)
      t = Time.now
      cert = @ca.create_certificate(csr, 'server', 10)
      ext_key_usage = cert.extensions.select {|e| e.oid == 'extendedKeyUsage' }.first.value
      
      expect(cert.ssl.not_after.to_i).to eq (t + (24 * 60 * 60 * 10)).to_i
    end
  end
  
  context "with a certificate file, key, and serial" do

    before(:all) do
      @ca_path = File.join(File.dirname(__FILE__), '../test', 'CA')
      ::File.open(File.join(@ca_path, 'serial.txt'), 'w') { |f| f.write('000B')}
      @ca = EaSSL::CertificateAuthority.load(:ca_path => @ca_path, :ca_password => '1234')
      @key = EaSSL::Key.new
      @name = EaSSL::CertificateName.new(
        :country => 'GB',
        :state => 'London',
        :city => 'London',
        :organization => 'Venda Ltd',
        :department => 'Development',
        :common_name => 'foo.bar.com',
        :email => 'dev@venda.com'
      )
    end

    it "loads the CA certficate" do
      expect(@ca.certificate.subject.to_s).to eq "/C=US/O=Venda/OU=auto-CA/CN=CA"
      expect(@ca.key.length).to eq 1024
      expect(@ca.serial.next).to eq 11
    end
    
    it "can properly sign a server certificate" do
      csr = EaSSL::SigningRequest.new(:name => @name, :key => @key)
      cert = @ca.create_certificate(csr)
      ext_key_usage = cert.extensions.select {|e| e.oid == 'extendedKeyUsage' }.first.value

      expect(cert.issuer.to_s).to eq "/C=US/O=Venda/OU=auto-CA/CN=CA"
      expect(cert.subject.to_s).to eq "/C=GB/ST=London/L=London/O=Venda Ltd/OU=Development/CN=foo.bar.com/emailAddress=dev@venda.com"
      expect(ext_key_usage).to eq "TLS Web Server Authentication"
    end

    it "can properly sign a client certificate" do
      csr = EaSSL::SigningRequest.new(:name => @name, :key => @key)
      cert = @ca.create_certificate(csr, 'client')
      ext_key_usage = cert.extensions.select {|e| e.oid == 'extendedKeyUsage' }.first.value

      expect(cert.issuer.to_s).to eq "/C=US/O=Venda/OU=auto-CA/CN=CA"
      expect(cert.subject.to_s).to eq "/C=GB/ST=London/L=London/O=Venda Ltd/OU=Development/CN=foo.bar.com/emailAddress=dev@venda.com"
      expect(ext_key_usage).to eq "TLS Web Client Authentication, E-mail Protection"
    end
    
    it "properly sets expiry on a certificate" do
      csr = EaSSL::SigningRequest.new(:name => @name, :key => @key)
      t = Time.now
      cert = @ca.create_certificate(csr, 'server', 10)
      ext_key_usage = cert.extensions.select {|e| e.oid == 'extendedKeyUsage' }.first.value
      
      expect(cert.ssl.not_after.to_i).to eq (t + (24 * 60 * 60 * 10)).to_i
    end

    it "increments the serial after signing a certificate" do
      next_serial = @ca.serial.next
      csr = EaSSL::SigningRequest.new(:name => @name, :key => @key)
      cert = @ca.create_certificate(csr)
      
      expect(cert.serial.to_i).to eq next_serial
      expect(@ca.serial.next).to eq next_serial + 1
      
      ca = EaSSL::CertificateAuthority.load(:ca_path => @ca_path, :ca_password => '1234')
      expect(ca.serial.next).to eq next_serial + 1
    end

  end
end
