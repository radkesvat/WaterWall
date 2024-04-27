#ifndef CACERT_H
#define CACERT_H

// i don't have time to impleme... nah i just don't trust the user trusted certs :)
// that also makes it much harder for the bad users to steal encrypted configs

extern unsigned char cacert_bytes[];
extern unsigned int  cacert_len;

#endif // CACERT_H
