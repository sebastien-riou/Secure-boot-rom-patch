#ifndef __BRP_H__
#define __BRP_H__

#define SHA256_ONLY_BE
#include "sha256.h"
#include "brp_data.h"

typedef uint32_t (*patch_t)(void);
static uint32_t brp_main(void){
    uint8_t buf[64];
    uint8_t *brp_apw=buf;
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
    uint8_t *digest=buf;
    sha256_sum(brp_otp_state,32,digest);
    //password check happens here
    if(memcmp(digest,BRP_DIGEST,sizeof(BRP_DIGEST))){return 1;} 
    brp_enable_ram_patch();
    for(unsigned int i=0;i<sizeof(BRP_ROM);i++){
        brp_ram_patch[i]^=BRP_ROM[i];
    }
    patch_t patch=(patch_t)brp_ram_patch;
    #ifdef BRP_DO_NOT_EXECUTE_PATCH
    uint32_t status=0;
    (void)patch;
    #else
    uint32_t status=patch();
    #endif
    return status;
}

#endif
