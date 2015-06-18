require 'eassl'

RSpec.describe EaSSL, "#key" do
  it "creates a new key" do
    key = EaSSL::Key.new
    expect(key.ssl).to be_a OpenSSL::PKey::RSA
  end

  it "creates a new private key" do
    key = EaSSL::Key.new
    expect(key.private_key).to be_a OpenSSL::PKey::RSA
  end

  it "creates a 2048-bit key by default" do
    key = EaSSL::Key.new
    expect(key.length).to eq 2048
  end

  it "creates a specified key size" do
    key = EaSSL::Key.new(:bits => 4096)
    expect(key.length).to eq 4096
  end

  it "creates a key with a default password" do
    key = EaSSL::Key.new
    enckey = key.to_pem
    key2 = OpenSSL::PKey::RSA::new(enckey, 'ssl_password')
    expect(key.ssl.to_s).to eq key2.to_s
  end

  it "creates a key with a specified password" do
    key = EaSSL::Key.new(:password => 'xyzzy')
    enckey = key.to_pem
    key2 = OpenSSL::PKey::RSA::new(enckey, 'xyzzy')
    expect(key.ssl.to_s).to eq key2.to_s
  end
  
  it "creates a formatted PEM string" do
    key = EaSSL::Key.new(:password => 'xyzzy')
    enckey = key.to_pem
    expect(enckey).to match 'BEGIN RSA PRIVATE KEY'
    expect(enckey).to match 'ENCRYPTED'
  end

  it "loads a key from string input" do
    key_text = <<KEY
-----BEGIN RSA PRIVATE KEY-----
MIGsAgEAAiEAy57X7ZFkqicM+Nb9kOjCBs0Fz3dc3F3nhqx9cDnwHaMCAwEAAQIh
ALOYKsOzVaJuRxbEKWpCob5hIpOCJqwmdA9cFbrEv9zhAhEA/B/sb8dzCvaFM/p5
Bt6Y7QIRAM7AD/gt+xiWUH8z+ra7js8CEQCXelqkofFloc1P+GnkjbLVAhAriPXT
5JrDCqPYpTFd2RCxAhEA+WMGuSLXT3xK5XP/LHIiVg==
-----END RSA PRIVATE KEY-----
KEY
    key = EaSSL::Key.new.load(key_text)
    expect(key.length).to eq 256
  end

  it "loads an encrypted key from string input" do
    key_text = <<KEY
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,95157FEDE26860DF

QtQcPFoYz58qBAE1BgrhZriIF8CFvMYgK5p92fSSHt9V2ySeEuBMwLJncp4tBJGG
IbjBVK9v4VB8NxrGoC7Qs/0JI5PkMVxwUIuzRC+KAXnImRaV258t+ydboYIwnsfl
2Do9eQonjPOWHvU1vWCQMXa/Jku9cqJnL3a7quZaGPHDW0ch/v2zPbF2LOFFJV8v
YvdYo7ml27+Zrr0rmnhF/XVtDwkQd/K0I3sXIr92fHk=
-----END RSA PRIVATE KEY-----
KEY
    key = EaSSL::Key.new.load(key_text, 'ssl_password')
    expect(key.length).to eq 256
  end

  it "loads a key from a file" do
    file = File.join(File.dirname(__FILE__), '../test', 'unencrypted_key.pem')
    key = EaSSL::Key.load(file)
    expect(key.length).to eq 256
  end

  it "loads an encrypted key from a file" do
    file = File.join(File.dirname(__FILE__), '../test', 'encrypted_key.pem')
    key = EaSSL::Key.load(file, 'ssl_password')
    expect(key.length).to eq 256
  end

  it "fails to load a non-existant file" do
    expect {key = EaSSL::Key.load('./foo')}.to raise_error(Errno::ENOENT)
  end
  
  it "fails to load an improper key file" do
    file = File.join(File.dirname(__FILE__), '..', 'Rakefile')
    expect {key = EaSSL::Key.load(file)}.to raise_error(RuntimeError)
  end
  

end