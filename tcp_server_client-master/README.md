
### Install repo
git clone https://github.com/BEPb/tcp_server_client
or
git -c http.sslVerify=false clone https://github.com/BEPb/tcp_server_client

### Compilation server for send msg
cd tcp_server_client/for_msg

Server side: 
```commandline
gcc server.c -o server 
./server
```

Client side: 
first specify the server IP address in the client file, by default local 127.0.0.1 is registered

```commandline
gcc client.c -o client 
./client
```
### Openssl (ssl/tls)
Run:
bin/server
bin/client

Make the project:
./gen_key
./compile

Debug:
./info

