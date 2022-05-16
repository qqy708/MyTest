openssl genrsa -des3 -out private.key 2048
openssl rsa -in private.key -pubout -out public.key
openssl req -new -key private.key -out cert.csr
openssl x509 -req -CA ticpsh.crt -CAkey ticpsh.key -in cert.csr -outform DER -out TICPSH.der -days 365 -CAcreateserial -extfile ticpsh.ext