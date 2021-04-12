#include <string.h>
#include <conio.h>
#include <time.h>
#include <cbm.h>

#define uint8_t unsigned char
#define uint16_t unsigned int
#define uint32_t unsigned long

#include "sha2.h"

/* user interface */

uint8_t demo_mode = 0;

uint8_t hexdigits[16] = { "0123456789abcdef" };

void hexdumpdigit(uint8_t c) {
        uint8_t c1 = c & 0x0F;
        uint8_t c2 = (c >> 4) & 0x0F;
        cputc(hexdigits[c2]);
        cputc(hexdigits[c1]);
}

void dump16bytes(const char *data) {
    uint8_t i;
    for (i=0;i<16;i++) {
        hexdumpdigit(data[i]);
    }
}

void dump_block(const char *block) {
    textcolor(COLOR_GRAY3);
    // 80 bytes = 5*16
    gotoxy(4,6); dump16bytes(block);
    gotoxy(4,7); dump16bytes(block+16);
    gotoxy(4,8); dump16bytes(block+32);
    gotoxy(4,9); dump16bytes(block+48);
    gotoxy(4,10); dump16bytes(block+64);
}

void dump_target(const char *target) {
    textcolor(COLOR_GRAY3);
    // 32 bytes = 2*16
    gotoxy(4,13); dump16bytes(target);
    gotoxy(4,14); dump16bytes(target+16);
}

void color_hex(uint16_t offs, const uint8_t color) {
    COLOR_RAM[0+offs] = color;
    COLOR_RAM[1+offs] = color;
}

void dump_hash(const char *hash, const char *target) {
    uint8_t color = COLOR_LIGHTGREEN;
    uint8_t i;
    uint16_t j, k;
    textcolor(COLOR_GRAY3);
    // 32 bytes = 2*16
    gotoxy(4,19); dump16bytes(hash);
    gotoxy(4,20); dump16bytes(hash+16);
    //
    j = 19*40+4; k = 13*40+4;
    for (i=0;i<32;i++) {
        if (i==16) {
            // row 2
            j = 20*40+4; k = 14*40+4;
        }
        if (hash[i]<=target[i]) {
            color = COLOR_LIGHTGREEN;
            color_hex(j, color); j = j + 2;
            color_hex(k, color); k = k + 2;
            if (hash[i]<target[i]) { break; }; // no need to check further
        } else {
            color = COLOR_LIGHTRED;
            color_hex(j, color); j = j + 2;
            color_hex(k, color); k = k + 2;
            break; // no need to check further
        }
    }
}

void print_status(const char *status) {
    textcolor(COLOR_LIGHTBLUE);
    cclearxy(9,3,40-11);
    cputsxy(9,3,status);
}

void print_result(const char *result, uint8_t good) {
    if (good) {
        textcolor(COLOR_LIGHTGREEN);
    } else {
        textcolor(COLOR_LIGHTRED);
    }
    cclearxy(9,22,40-11);
    cputsxy(9,22,result);
}

void print_nonce(uint32_t nonce) {
    uint8_t *noncebytes;
    textcolor(COLOR_LIGHTGREEN);
    noncebytes = (uint8_t*)&nonce;
    gotoxy(8,16);
    hexdumpdigit(noncebytes[3]);
    hexdumpdigit(noncebytes[2]);
    hexdumpdigit(noncebytes[1]);
    hexdumpdigit(noncebytes[0]);
}

#define SCREEN_RAM       ((unsigned char*)0x0400)

void setup_screen(void) {
    // designed with http://petscii.krissz.hu/
    clrscr();
    bordercolor(COLOR_BLACK);
    bgcolor(COLOR_BLACK);
    textcolor(COLOR_GRAY1);
    // frames
    cvlinexy(0,1,22);
    cvlinexy(39,1,22);
    chlinexy(0,0,40);
    chlinexy(0,2,40);
    chlinexy(0,4,40);
    chlinexy(0,11,40);
    chlinexy(0,15,40);
    chlinexy(0,17,40);
    chlinexy(0,21,40);
    chlinexy(0,23,40);
    // corners, put directly into screen RAM because cputc will translate these codes into ASCII letters
    SCREEN_RAM[0]=112;
    SCREEN_RAM[39]=110;
    SCREEN_RAM[23*40]=109;
    SCREEN_RAM[23*40+39]=125;
    // ties
    SCREEN_RAM[2*40]=107;   SCREEN_RAM[2*40+39]=115;
    SCREEN_RAM[4*40]=107;   SCREEN_RAM[4*40+39]=115;
    SCREEN_RAM[11*40]=107;  SCREEN_RAM[11*40+39]=115;
    SCREEN_RAM[15*40]=107;  SCREEN_RAM[15*40+39]=115;
    SCREEN_RAM[17*40]=107;  SCREEN_RAM[17*40+39]=115;
    SCREEN_RAM[21*40]=107;  SCREEN_RAM[21*40+39]=115;
    // labels
    textcolor(COLOR_CYAN);
    cputsxy(2,1,"Bitcoin Miner 64 v1.0 ");
    textcolor(COLOR_GRAY3);
    cputs("by ");
    textcolor(COLOR_GREEN);
    cputs("YTM/Elysium");
    textcolor(COLOR_WHITE);
    cputsxy(1,3,"STATUS:");
    cputsxy(1,5,"BLOCK:");
    cputsxy(1,12,"TARGET:");
    cputsxy(1,16,"NONCE:");
    cputsxy(1,18,"LAST HASH:");
    cputsxy(28,18,"TIME:");
    cputsxy(1,22,"RESULT:");
    // hex guides
    textcolor(COLOR_GRAY2);
    cputsxy(1,6,"00:"); cputsxy(36,6,":0f");
    cputsxy(1,7,"10:"); cputsxy(36,7,":1f");
    cputsxy(1,8,"20:"); cputsxy(36,8,":2f");
    cputsxy(1,9,"30:"); cputsxy(36,9,":3f");
    cputsxy(1,10,"40:"); cputsxy(36,10,":4f");
    cputsxy(1,13,"00:"); cputsxy(36,13,":0f");
    cputsxy(1,14,"10:"); cputsxy(36,14,":1f");
    cputsxy(1,19,"00:"); cputsxy(36,19,":0f");
    cputsxy(1,20,"10:"); cputsxy(36,20,":1f");
}

/* communication */

uint8_t _io_in, _io_out;

const char ser_params[] = { 0x08, 0x00 };

void sb(uint8_t c) {
    if (demo_mode) return;
    cbm_k_ckout(2);
    cbm_k_chrout(c);
    cbm_k_ckout(3);
    cbm_k_chkin(2);
}

uint8_t receive_byte_nonblock(void) {
    if (demo_mode) return 0;
    cbm_k_chkin(2);
    return cbm_k_getin();
}

void receive_bytes(uint8_t *buf, uint8_t len) {
    uint8_t i;
    uint8_t c;
    if (demo_mode) return;
    cbm_k_chkin(2);
    for(i = 0; i < len; i++) {
    c = cbm_k_chrin();
    if (c==1) {
        c = cbm_k_chrin();
        --c;
    }
    buf[i] = c;
    }
}

const uint8_t CMD_BLOCK_HEADER = 0x41;
const uint8_t CMD_TARGET = 0x42;
const uint8_t CMD_NEW_BLOCK = 0x43;
const uint8_t CMD_STATUS = 0x44;
const uint8_t CMD_NONCE = 0x45;
const uint8_t RESP_WAIT_CMD = 0x61;
const uint8_t RESP_WAIT_DATA = 0x62;
const uint8_t RESP_SUCCESS = 0x63;
const uint8_t RESP_FAIL = 0x64;

void wait_byte(const uint8_t b) {
    uint8_t c = 0;
    if (demo_mode) return;
    cbm_k_chkin(2);
    while (b!=cbm_k_chrin()) { };
}

void receive_block_data(uint8_t *block_header, uint8_t *target, uint32_t *nonce) {
    print_status("Receiving block...");
    wait_byte(CMD_BLOCK_HEADER);
    receive_bytes(block_header, 76);
    print_status("Receiving target...");
    wait_byte(CMD_TARGET);
    receive_bytes(target, 32);
    print_status("Receiving nonce...");
    wait_byte(CMD_NONCE);
    receive_bytes((uint8_t*)nonce, 4);
}

uint8_t mine_nonce(uint8_t *block_header, uint8_t *target, uint32_t *nonce_out) {
    uint32_t nonce;
    uint8_t *noncebytes;
    uint8_t i;
    uint8_t hash_rev[32];
    uint8_t hash2[32];
    uint8_t hash[32];
    // stats
    clock_t t;
    uint32_t sec;
    uint16_t sec10;

    nonce = *nonce_out;
    noncebytes = (uint8_t*)&nonce;
    while(1) {

        // Append nonce to block
        memcpy(&block_header[76], &nonce, 4);

        // UI
        print_nonce(nonce);
        t = clock();
        print_status("Hashing first time...");
        calc_sha_256(hash2, block_header, 80);
        print_status("Hashing second time...");
        calc_sha_256(hash_rev, hash2, 32);
        //
        for(i=0; i < 32; i++) {
            hash[31-i] = hash_rev[i];
        }
        // stats
        t = clock() - t;
        sec = (t * 10) / CLK_TCK;
        sec10 = sec % 10;
        sec /= 10;
        // display timer
        textcolor(COLOR_LIGHTGREEN);
        gotoxy(34,18);
        cprintf ("%lu.%us", sec, sec10);
        // display result
        dump_hash(hash, target);

        // check & summary
        for(i=0; i < 32; i++) {
            if(hash[i] < target[i]) {
                print_result("Success!", 1);
                *nonce_out = nonce;
                return 0;
            } else if(hash[i] > target[i]) {
                sb(RESP_FAIL);
                print_result("Failed, trying next one...", 0);
                // Increase nonce
                nonce++;
                break;
            }
        }

        // Check if we need to receive a new block.
        if(receive_byte_nonblock() == CMD_NEW_BLOCK) {
            print_status("New data block!");
            return 1;
        }
    }
}

void miner(void) {
    uint8_t block_header[80];
    uint8_t target[32];
    uint8_t mine_result;
    uint32_t nonce;
    uint8_t data[4];
    uint8_t i;

    memset(block_header, 0, 80);
    memset(target, 0, 32);

    while(1) {
        setup_screen();
        print_status("Waiting for data");
        sb(RESP_WAIT_CMD);
        receive_block_data(block_header, target, &nonce);
        dump_block(block_header);
        dump_target(target);

        /*
        memset(target, 0xff, 32);
        target[0]=0;
        target[1]=0x7f;
        nonce = 0x50;
        */

        mine_result = mine_nonce(block_header, target, &nonce);

    // Indicate success to host
        if(mine_result == 0) {
            print_status("Sending correct nonce...");
            sb(RESP_SUCCESS);
            wait_byte(CMD_STATUS);
            // send nonce over.
            memcpy(data, &nonce, 4);
            for(i=0; i < 4; i++) {
                sb(data[i]);
            }
            print_status("Block done");
            while (1) { __asm__("inc $d020"); }
        }
    }
}

void miner_demo(void) {
    uint8_t block_header[80];
    uint8_t target[32];
    uint8_t mine_result;
    uint32_t nonce;

    memset(block_header, 0, 80);
    memset(target, 0xff, 32);
    target[0]=0;
    target[1]=0x7f;

    while(1) {
        setup_screen();
        dump_block(block_header);
        dump_target(target);
        mine_result = mine_nonce(block_header, target, &nonce);
        if(mine_result == 0) {
            print_status("Sending correct nonce...");
            print_status("Block done");
            while (1) { __asm__("inc $d020"); }
        }
    }
}

void main(void) {

uint8_t c;

    clrscr();
    bordercolor(COLOR_BLACK);
    bgcolor(COLOR_BLACK);
    textcolor(COLOR_GRAY1);
    cputsxy(0,0,"Bitcoin Miner 64 by YTM/Elysium");
    cputsxy(1,2,"Press 'd' for demo mode.");
    cputsxy(1,3,"Wait until successful nonce $0000019b");
    cputsxy(1,4,"(about 31 minutes)");
    cputsxy(1,7,"Otherwise:");
    cputsxy(1,8,"1. Setup 1200 baud 8N1 RS232 connection");
    cputsxy(1,9,"2. Start ntgbtminer on the remote end");
    cputsxy(1,10,"Press any other key to continue");
    cputsxy(0,23,"Inspired by stacksmasher's GameBoy miner");

    // use this time to generate right rotation lookup data for sha2.c
    generate_rot_tables();

    c = cgetc();
    if (c=='d' || c=='D') {
        miner_demo();
        return;
    }

    // open RS232 link 1200,8N1
    cbm_k_setlfs(2,2,0);
    cbm_k_setnam(ser_params);
    cbm_k_open();

    // sync, flush input until non-zero value arrives, ignore that value too
    cbm_k_chkin(2);
    _io_in = cbm_k_chrin(); // ignore first byte, server will sync by sending 0s and 255
    while (_io_in==0) {
        _io_in = cbm_k_chrin();
    }

    // start work
    miner();
    return;
}
