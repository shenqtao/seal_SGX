### Ongoing work

This project implements a client (who performs homomorphic add & multiplication) and a server (who performs bootstrapping). Whenever a bootstrapping is needed (i.e. the noise exceeds a threshold, which can be estimated using the evaluation key), the ciphertext is sent to the server. The server will decrypt it and re-encrypt it (equivalent to a bootstrapping), and send it to the client. The project uses socket communication between the client and server. Before the communication, the server needs to get the homomorphic encryption key configuration, and the private key after a remote attestation is performed.

### Future work

Support more HME schemes, at least supporting one GPU-based HME scheme implementation
