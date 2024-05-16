 generate a simple openssl server for testing:
   1) generate a private key
   openssl genrsa -out server.key 1024
   2) generate a self signed cert
   openssl req -new -key server.key -x509 -days 3653 -out server.crt
      enter fields...
   3) generate the pem file
   cat server.key server.crt >server.pem
   openssl s_server  (listens on 4433/tcp)


