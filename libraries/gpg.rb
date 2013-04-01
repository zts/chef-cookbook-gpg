begin
  require 'gpgme'
rescue LoadError => e
  Chef::Log.warn("GPG library dependency 'gpgme' not loaded: #{e}")
end

# encrypt given data with public key(s) of recipients, returning
# ASCII-armored ciphertext
#
def gpg_encrypt(data, recipients)
  if recipients.nil?
    raise RuntimeError.new("No recipient specified for gpg_encrypt")
  end

  # Chef always uses root's GPG keyring.
  GPGME::Engine.home_dir='/root/.gnupg'

  if GPGME::Key.find(:public, recipients).empty?
    raise RuntimeError.new("gpg_encrypt couldn't find public keys for recipients: " + recipients)
  end

  begin
    crypto = GPGME::Crypto.new :armor => true
    data = crypto.encrypt(data, :recipients => recipients)
    data.read
  rescue
    Chef::Log.error "gpg_encrypt failed encrypting for recipients: " + recipients
    raise
  end

end
