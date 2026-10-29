# Heartbleed + Zeroization demo

A simple client-server application to illustrate the need for zeroization.

```
# Compile
gcc server.c -o server
gcc client.c -o client

# Start the server
./server

# Send messages in the client
./client 6hello     # Server responds with 6hello
#Server reply length: 6
#3668656c6c6f
./client 3hello     # Server responds with 3he (truncated)
#Server reply length: 3
#366865
./client 100hello   # Server responds with stack contents
                    # The secret key a5a5a5... will be visible
#Server reply length: 150
#31353068656c6c6f000000000000000000000000000000000000000000000000684db44ae95a000000f703f3bca98ad7e0164b8ffc7f00009324b44ae95a00000000000000000000000000000300000002001b58000000000000000000000000a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5c0174b8ffc7f000000f703f3bca98ad780174b8ffc7f
```
