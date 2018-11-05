openssl s_client -servername httpbin.org -connect httpbin.org:443 < /dev/null | sed -n "/-----BEGIN/,/-----END/p" > httpbin.org.pem
openssl x509 -in httpbin.org.pem -pubkey -noout > httpbin.org.pubkey.pem
openssl asn1parse -noout -inform pem -in httpbin.org.pubkey.pem -out httpbin.org.pubkey.der
openssl dgst -sha256 -binary httpbin.org.pubkey.der | openssl base64
