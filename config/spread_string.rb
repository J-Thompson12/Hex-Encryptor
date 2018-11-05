require 'yaml'
require 'erb'
require 'openssl'
require 'base64'

def erb(file_name, template_name)
    template = ERB.new(File.open(template_name, "r:UTF-8", &:read), nil, "-")
    File.open(file_name, "w:UTF-8") { |file| file.write(template.result(binding)) }
end

def encrypt(data)
    cipher = OpenSSL::Cipher.new("AES-256-CBC")
    cipher.encrypt
    cipher.iv = "thisistheivsanditworks"
    cipher.key = "thisisthekeyanditworksthisisthekeyanditworks"
    encrypted = cipher.update(data) + cipher.final
    enc = Base64.strict_encode64(encrypted)
end

def spread(text)
    test = Random.new(12345)
    4.times do
        test.rand(1..4)

    end

    erb('../src/strings.h', "strings.h.erb")
end

cipher = OpenSSL::Cipher.new("AES-256-CBC")
@enc_iv= cipher.random_iv
@enc_key= cipher.random_key
@strings_hash = YAML.load_file('secrets.yaml')
#@strings_hash.each { |k, v| @strings_hash[k] = splitbeg(v) }