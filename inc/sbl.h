#ifndef __SBL_H__
#define __SBL_H__
/*
Example of simple boot loader suitable for BRP
Allows to download arbitrary code and execute it
Expect that RX/TX functions are defined before including this file:
    void     brp_tx(brp_tx_t dat);
    brp_rx_t brp_rx(void);
where brp_tx_t and brp_rx_t are an integer type of 8, 16 or 32 bits.
*/

#include <stdint.h>

static void sbl_tx32(uint32_t dat32){
    brp_tx_t*dat = (brp_tx_t*)&dat32;
    for(unsigned int i=0;i<sizeof(uint32_t);i+=sizeof(brp_tx_t)){
        brp_tx(*dat++);
    }
}
static uint32_t sbl_rx32(void){
    uint32_t out32;
    brp_rx_t*out = (brp_rx_t*)&out32;
    for(unsigned int i=0;i<sizeof(uint32_t);i+=sizeof(brp_rx_t)){
        *out++=brp_rx();
    }
    return out32;
}
static void sbl_main(void){
	while(1){
        //get number of 32 bits data words to receive
		uint32_t nwords = sbl_rx32();

        //get load address
		uint32_t *loadaddr = (uint32_t *)(intptr_t)sbl_rx32();

        //get data words
		for(unsigned int i=0;i<nwords;i++){
			loadaddr[i]=sbl_rx32();
		}

        //get run address
		uint32_t *runaddr = (uint32_t *)(intptr_t)sbl_rx32();
		patch_t patch=(patch_t)runaddr;

        //launch patch
		uint32_t status=patch();

        //if patch returns, send its return value and wait for next patch
		sbl_tx32(status);
	}
}

#endif
