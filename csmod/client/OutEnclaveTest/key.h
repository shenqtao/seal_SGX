#ifndef KEY_H
#define KEY_H

void generate_key();
void get_public_key(char* public_key_buffer,size_t len);
void get_secret_key(char* secret_key_buffer,size_t len);

#endif