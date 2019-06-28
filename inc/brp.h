#ifndef __BRP_H__
#define __BRP_H__

/*
Expects the following definitions:
types:
    brp_tx_t
    brp_rx_t
functions:
    void brp_tx(brp_tx_t)
    brp_rx_t brp_rx(void)
*/

#ifndef BRP_FUNC
#define BRP_FUNC
#endif

#ifndef __SHA256_H__
#define SHA256_FUNC BRP_FUNC
#define SHA256_ONLY_BE
#include "sha256.h"
#endif

#ifndef __BRP_DATA_H__
#include "brp_data.h"
#endif

typedef uint32_t (*patch_t)(void);
BRP_FUNC static uint32_t brp_main(uint8_t red_buf[64]){
    uint8_t *brp_apw=red_buf;
    for(unsigned int i=0;i<32;i+=sizeof(brp_rx_t)){
        brp_rx_t rxdat=brp_rx();
        const uint8_t *const rxdat8=(const uint8_t *const)&rxdat;
        unsigned int offset=2*i;
        for(unsigned int j=0;j<sizeof(brp_rx_t);j++){
            brp_apw[offset+2*j]=BRP_APW_EVEN;
            brp_apw[offset+2*j+1]=rxdat8[j];
        }
    }
    sha256_sum(brp_apw,64,brp_ram_patch);
    uint8_t *brp_otp_state = brp_ram_patch;
    for(unsigned int i=1;i<BRP_BLOCKS;i++){
        sha256_sum(brp_otp_state,32,brp_otp_state+32);
        brp_otp_state+=32;
    }
    uint8_t *digest=red_buf;
    sha256_sum(brp_otp_state,32,digest);
    //password check happens here
    //order of data in BRP_DIGEST is not the same as in digest, so we need 2 memcmp
    unsigned int half=sizeof(BRP_DIGEST)/2;
    const uint8_t *const digest0 = digest;
    const uint8_t *const digest1 = digest+half;
    const uint8_t *const BRP_DIGEST0 = BRP_DIGEST+half;
    const uint8_t *const BRP_DIGEST1 = BRP_DIGEST;
    if(memcmp(digest0,BRP_DIGEST0,half)){return 1;}
    if(memcmp(digest1,BRP_DIGEST1,half)){return 1;}
    brp_enable_ram_patch();
    for(unsigned int i=0;i<sizeof(BRP_ROM);i++){
        brp_ram_patch[i]^=BRP_ROM[i];
    }
    patch_t patch=(patch_t)(intptr_t)brp_ram_patch;
    #ifdef BRP_DO_NOT_EXECUTE_PATCH
    uint32_t status=0;
    (void)patch;
    #else
    uint32_t status=patch();
    #endif
    return status;
}

#endif
