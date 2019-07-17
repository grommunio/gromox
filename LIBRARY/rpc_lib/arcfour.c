#include "arcfour.h"
#include <stdint.h>

/* initialise the arcfour sbox with key */
void arcfour_init(ARCFOUR_STATE *pstate, const DATA_BLOB *pkey) 
{
	int i;
	uint8_t tc;
	uint8_t j = 0;
	
	for (i=0; i<sizeof(pstate->sbox); i++) {
		pstate->sbox[i] = (uint8_t)i;
	}
	
	for (i=0; i<sizeof(pstate->sbox); i++) {
		j += (pstate->sbox[i] + pkey->data[i%pkey->length]);
		
		tc = pstate->sbox[i];
		pstate->sbox[i] = pstate->sbox[j];
		pstate->sbox[j] = tc;
	}
	pstate->index_i = 0;
	pstate->index_j = 0;
}

void arcfour_destroy(ARCFOUR_STATE *pstate)
{
	/* do nothing */
}

/* crypt the data with arcfour */
void arcfour_crypt_sbox(ARCFOUR_STATE *pstate, uint8_t *pdata, int len) 
{
	int i;
	uint8_t t;
	uint8_t tc;
	
	for (i=0; i<len; i++) {
		
		pstate->index_i++;
		pstate->index_j += pstate->sbox[pstate->index_i];

		tc = pstate->sbox[pstate->index_i];
		pstate->sbox[pstate->index_i] = pstate->sbox[pstate->index_j];
		pstate->sbox[pstate->index_j] = tc;
		
		t = pstate->sbox[pstate->index_i] + pstate->sbox[pstate->index_j];
		pdata[i] = pdata[i] ^ pstate->sbox[t];
	}
}

/* arcfour encryption with a blob key */
void arcfour_crypt_blob(uint8_t *pdata, int len, const DATA_BLOB *pkey) 
{
	ARCFOUR_STATE state;
	
	arcfour_init(&state, pkey);
	arcfour_crypt_sbox(&state, pdata, len);
	arcfour_destroy(&state);
}

/*
  a variant that assumes a 16 byte key. This should be removed
  when the last user is gone
*/
void arcfour_crypt(uint8_t *pdata, const uint8_t keystr[16], int len)
{
	DATA_BLOB key;

	key.data = (uint8_t*)keystr;
	key.length = 16;
	
	arcfour_crypt_blob(pdata, len, &key);
	
}


