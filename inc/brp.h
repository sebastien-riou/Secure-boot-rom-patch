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
#define SHA256_BE
#include "sha256.h"
#endif

#ifndef __BRP_DATA_H__
#include "brp_data.h"
#endif

typedef uint32_t (*patch_t)(void);

BRP_FUNC static void brp_otp_gen(uint8_t*const state,const uint8_t*const cst,uint8_t*dst){
    sha256_sum(state,32,state);
    for(unsigned int i=0;i<32/BRP_OTP_EXP;i++){
        uint8_t t=0xFF;
        for(unsigned int j=0;j<BRP_OTP_EXP;j++){
            unsigned int lsb = (j+1)==BRP_OTP_EXP ? 0 : 1;//1 except at last iteration
            t &= (state[i*BRP_OTP_EXP+j] ^ cst[i*BRP_OTP_EXP+j]) | lsb;
        }
        dst[i]=t;
    }
}

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
    sha256_sum(red_buf,64,red_buf);
    uint8_t *brp_patch = brp_ram_patch;
    const uint8_t *brp_rom = BRP_ROM;
    for(unsigned int i=0;i<BRP_BLOCKS*BRP_OTP_EXP;i++){
        brp_otp_gen(red_buf,brp_rom,brp_patch);
        brp_patch+=32/BRP_OTP_EXP;
        brp_rom+=32;
    }
    uint8_t *digest=red_buf;
    sha256_sum(red_buf,32,red_buf);
    //password check happens here
    if(memcmp(digest,BRP_DIGEST,sizeof(BRP_DIGEST))){return 1;}
    brp_enable_ram_patch();
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
