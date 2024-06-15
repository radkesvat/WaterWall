#ifndef CACERT_H
#define CACERT_H

/*
    Currently, waterwall uses its own CA and dose not trust user trusted certs
    this also makes it much harder for the bad users to steal encrypted configs (IMO)

    todo (hash verify), in order to make it even harder, do some hash verify of bytes
*/


extern unsigned char cacert_bytes[];
extern unsigned int  cacert_len;

#endif // CACERT_H
