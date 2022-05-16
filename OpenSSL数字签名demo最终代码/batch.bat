openssl genrsa -des3 -out private.key 2048
openssl rsa -in private.key -pubout -out public.key
openssl req -new -key private.key -out cert.csr
openssl req -new -x509 -key private.key -out cacert.pem -days 365
openssl x509 -in cacert.pem -outform DER -out gg1.der