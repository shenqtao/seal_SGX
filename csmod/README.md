This project implements a client (who performs homomorphic add & multiplication) and a server (who performs bootstrapping).  

Whenever a bootstrapping is needed (i.e. the noise exceeds a threshold, which can be estimated using the evaluation key), the ciphertext is sent to the server. The server will decrypt it and re-encrypt it (equivalent to a bootstrapping), and send it to the client. The project uses socket communication between the client and server.   

As the first step before the communication, the server needs to get the homomorphic encryption key configuration, and the private key (after a remote attestation is performed and the key agreement is established).

### Status
- [X] Communication established.
- [X] Data transfer success.
- [X] Encryption configuration transfer success.
- [X] Decrease_noise   
After ``decrease_noise`` when the ciphertext is transferred back to the client, the client cannot load it successfully.(_fixed_) 
- [X] Ciphertext after noise decrease sent back to client
- [X] Multiple clients support
  - Needs to bind the keys to each client
  
### Missing
- [ ] Scheduling multiple client requests
  - A simple scheduling method
    - The server maintains a task queue with priorities
    - The client sents the current distance to the threshold after each (or several) homomorphic computation(s)
    - The server decides which client can send the ciphertext for bootstrapping
- [ ] Bug fix
  - Even if ``decrease_noise`` is not called, the client & server channel sometimes terminate unexpectly.
  - Possible crashes when the data trasfered through socket communication is incorrect. (rare cases)   
    Temporarily fixed by ingnoring buffer length is < 0 or > length

### Future work
- Support more HME schemes, at least one GPU-based HME scheme implementation
