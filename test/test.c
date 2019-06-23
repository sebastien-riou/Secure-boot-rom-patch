#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

//include this to get BRP_BLOCKS defined
#include "brp_data.h"

//customization
uint8_t brp_ram_patch[BRP_BLOCKS*32];
typedef uint32_t brp_rx_t;

const brp_rx_t* brp_rx_dat;
static brp_rx_t brp_rx(void){
    return *brp_rx_dat++;
}
static void brp_enable_ram_patch(void){}
#define BRP_DO_NOT_EXECUTE_PATCH

//include ref implementation
#include "brp.h"

//include the secret data for verification purposes
#include "brp_apw.h"

#include "bytes_utils.h"

//not needed, stuff included to check that it compiles
typedef uint32_t brp_tx_t;
static void brp_tx(brp_tx_t dat){
    printf("brp_tx %x\n",dat);
}
#include "sbl.h"

int main(int argc, char*argv[]){
    (void)bytes_utils_remove_unused_warnings;
    (void)sbl_main;

    //test ref implementation

    brp_rx_dat=(const brp_rx_t*const)BRP_APW_odd;
    int status=0;
    uint8_t red_buf[64];
    if(brp_main(red_buf)){
        printf("ERROR: brp_main fails with expected password\n");
        status|=1;
    }else{
        if(memcmp(brp_ram_patch,BRP,sizeof(BRP))){
            printf("ERROR: BRP mismatch\n");
            println_bytes("brp_ram_patch=",brp_ram_patch,sizeof(BRP));
            println_bytes("BRP          =",BRP,sizeof(BRP));
            status|=1;
        }
    }
    for(unsigned int i=0;i<sizeof(BRP_APW_odd);i++){//for each byte
        for(unsigned int j=0;j<8;j++){//for each bit
            uint8_t incorrect[sizeof(BRP_APW_odd)];
            memcpy(incorrect,BRP_APW_odd,sizeof(BRP_APW_odd));
            incorrect[i]^=1<<j;
            brp_rx_dat=(const brp_rx_t*const)incorrect;
            if(0==brp_main(red_buf)){
                printf("ERROR: brp_main succeed with incorrect password (byte %u, bit %u)\n",i,j);
                status|=2;
            }
        }
    }

    //generate debug info

    uint8_t RAM_PATCH_AREA[BRP_BLOCKS*32];

    uint8_t brp_apw[64];
    for(unsigned int i=0;i<32;i++){
        brp_apw[2*i]=BRP_APW_EVEN;
        brp_apw[2*i+1]=BRP_APW_odd[i];
    }
    if(memcmp(brp_apw,BRP_APW,sizeof(BRP_APW))){
        printf("ERROR: BRP_APW mismatch\n");
        println_bytes("brp_apw=",brp_apw,sizeof(BRP_APW));
        println_bytes("BRP_APW=",BRP_APW,sizeof(BRP_APW));
        return 1;
    }
    sha256_sum(brp_apw,64,RAM_PATCH_AREA);
    uint8_t *brp_otp_state = RAM_PATCH_AREA;
    for(unsigned int i=1;i<BRP_BLOCKS;i++){
        sha256_sum(brp_otp_state,32,brp_otp_state+32);
        brp_otp_state+=32;
    }
    if(memcmp(RAM_PATCH_AREA,BRP_OTP,sizeof(BRP_OTP))){
        printf("ERROR: BRP_OTP mismatch\n");
        for(unsigned int i=0;i<BRP_BLOCKS;i++){
            printf("block %u\n",i);
            println_bytes("RAM       =",RAM_PATCH_AREA+32*i,32);
            println_bytes("BRP_OTP   =",BRP_OTP+32*i,32);
        }
        return 2;
    }
    uint8_t digest[32];
    sha256_sum(brp_otp_state,32,digest);
    if(memcmp(digest,BRP_DIGEST,sizeof(BRP_DIGEST))){
        printf("ERROR: BRP_DIGEST mismatch\n");
        println_bytes("digest    =",digest,sizeof(BRP_DIGEST));
        println_bytes("BRP_DIGEST=",BRP_DIGEST,sizeof(BRP_DIGEST));
        return 3;
    }
    for(unsigned int i=0;i<sizeof(BRP_ROM);i++){
        RAM_PATCH_AREA[i]^=BRP_ROM[i];
        printf("%02X ",RAM_PATCH_AREA[i]);
    }
    printf("\n");
    if(memcmp(RAM_PATCH_AREA,BRP,sizeof(BRP))){
        printf("ERROR: BRP mismatch\n");
        println_bytes("RAM       =",RAM_PATCH_AREA,sizeof(BRP));
        println_bytes("BRP       =",BRP,sizeof(BRP));
        return 4;
    }
    if(0==status){
        printf("\nTEST SUCCESFULL\n");
    }
    return status;
}
