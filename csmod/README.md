This project implements a client (who performs homomorphic add & multiplication) and a server (who performs bootstrapping).  

Whenever a bootstrapping is needed (i.e. the noise exceeds a threshold, which can be estimated using the evaluation key), the ciphertext is sent to the server. The server will decrypt it and re-encrypt it (equivalent to a bootstrapping), and send it to the client. The project uses socket communication between the client and server.   

As the first step before the communication, the server needs to get the homomorphic encryption key configuration, and the private key (after a remote attestation is performed and the key agreement is established).

### Future work

Support more HME schemes, at least supporting one GPU-based HME scheme implementation

### Status
- [X] Communication established.
- [X] Data transfer success.
- [X] Encryption configuration transfer success.
- [X] Decrease_noise   
After ``decrease_noise`` when the ciphertext is transferred back to the client, the client cannot load it successfully.(_fixed_) 
- [X] Ciphertext after noise decrease sent back to client

### Missing
- [ ] Scheduling multiple client requests
- [ ] Bug fix
  - Even if ``decrease_noise`` is not called, the client & server channel sometimes terminate unexpectly.
  - Possible crashes when the data trasfered through socket communication is incorrect. (rare cases)   
    Temporarily fixed by ingoring buffer length (<0 or > length)
