### Ongoing work

This project implements a client (who performs homomorphic add & multiplication) and a server (who performs bootstrapping).  

Whenever a bootstrapping is needed (i.e. the noise exceeds a threshold, which can be estimated using the evaluation key), the ciphertext is sent to the server. The server will decrypt it and re-encrypt it (equivalent to a bootstrapping), and send it to the client. The project uses socket communication between the client and server.   

As the first step before the communication, the server needs to get the homomorphic encryption key configuration, and the private key (after a remote attestation is performed and the key agreement is established).

### Future work

Support more HME schemes, at least supporting one GPU-based HME scheme implementation

### In progress

* After ``decrease_noise`` when the ciphertext is transferred back to the client, the client cannot load it successfully.  
**Need to make sure the ``decrease_noise`` finishes correctly.**

* Even if ``decrease_noise`` is not called, the client & server channel sometimes terminate unexpectly.

* Possible crashes when the data trasfered through socket communication is incorrect. (rare cases)
```
new client accpeted
command is: 0, buffer length: 144
loop finished.
command is: 2, buffer length: 524365
loop finished.
command is: 1, buffer length: 262185
loop finished.
command is: 3, buffer length: 786541
loop finished.
command is: 47800, buffer length: -1534722048
*** buffer overflow detected ***: ./App terminated
```
