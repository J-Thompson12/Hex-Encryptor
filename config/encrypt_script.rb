require 'yaml'
require 'erb'
require 'openssl'
require 'base64'

#places key, iv, and encrypted strings into c++ files
def erb(file_name, template_name)
    template = ERB.new(File.open(template_name, "r:UTF-8", &:read), nil, "-")
    File.open(file_name, "w:UTF-8") { |file| file.write(template.result(binding)) }
end

#encrypt using openssl AES 256 CBC and base64 encode into a string
def encrypt(data)
    cipher = OpenSSL::Cipher.new("AES-256-CBC")
    cipher.encrypt
    cipher.iv = @enc_iv
    cipher.key = @enc_key
    encrypted = cipher.update(data) + cipher.final
    enc = Base64.strict_encode64(encrypted)
end

#obfuscate the key and iv 2 times just to make it a little harder
def xor(input)
    key = 128
    output = input.split(//).collect {|e| [e.unpack('C').first ^ (key & 0xFF)].pack('C') }.join
    output = output.split(//).collect {|e| [e.unpack('C').first ^ (key - 27 & 0xFF)].pack('C') }.join
    Base64.strict_encode64(output)
end


cipher = OpenSSL::Cipher.new("AES-256-CBC")
@enc_iv= cipher.random_iv
@enc_key= cipher.random_key
@strings_hash = YAML.load_file('secrets.yaml')
@strings_hash.each { |k, v| @strings_hash[k] = encrypt(v) }

@enc_iv = xor(@enc_iv)
@enc_key = xor(@enc_key)

erb('../src/strings.h', "strings.h.erb")
erb('../src/strings.cpp', "strings.cpp.erb")

