// SPDX-License-Identifier: GPL-3.0-or-later
/*
   Unix SMB/CIFS implementation.

   An implementation of the arcfour algorithm

   Copyright (C) Andrew Tridgell 1998

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#include <cstdint>
#include <gromox/arcfour.hpp>

/* initialise the arcfour sbox with key */
void arcfour_init(ARCFOUR_STATE *pstate, const uint8_t *keydata, size_t keylen)
{
	uint8_t tc;
	uint8_t j = 0;
	
	for (size_t i = 0; i < sizeof(pstate->sbox); ++i)
		pstate->sbox[i] = (uint8_t)i;
	for (size_t i = 0; i < sizeof(pstate->sbox); ++i) {
		j += pstate->sbox[i] + keydata[i%keylen];
		tc = pstate->sbox[i];
		pstate->sbox[i] = pstate->sbox[j];
		pstate->sbox[j] = tc;
	}
	pstate->index_i = 0;
	pstate->index_j = 0;
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

void arcfour_crypt(uint8_t *pdata, const uint8_t keystr[16], int len)
{
	ARCFOUR_STATE state;
	arcfour_init(&state, keystr, 16);
	arcfour_crypt_sbox(&state, pdata, len);
}
