#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sha1.h"
#include "arc4.h"

unsigned char* flash;
unsigned char* ecc;
unsigned char* boot_blk;
unsigned char* ldr_d;
unsigned char* ldr_e;
unsigned char* ldr_c;
unsigned char bl_key[0x10];
unsigned char bl_string[0x20];
unsigned char ldr_b_key[0x10];
unsigned char zero_key[0x10];
unsigned char ldr_bb_key[0x10];
unsigned char ldr_d_key[0x10];
unsigned char ldr_e_key[0x10];
unsigned char ldr_c_key[0x10];    
unsigned char hmac[0x40];
unsigned char sha[0x40];
unsigned char ecc_hash[0x10];
unsigned char new_ecc[0x10];


int i=0;
int f_sz;
int f_pgs;
int x=0;
int y=0;
int ldr_b_start;
int ldr_b_end;
int ldr_bb_start;
int ldr_bb_end;
int ldr_d_start;
int ldr_d_end;
int ldr_e_start;
int ldr_e_end;
int ldr_c_end;
int boot_blk_sz;
int sfc;


int hex2data(unsigned char *data, const unsigned char *hexstring, unsigned int len)
{
    unsigned const char *pos = hexstring;
    char *endptr;
    size_t count = 0;

    if ((hexstring[0] == '\0') || (strlen(hexstring) % 2))
    {
        //hexstring contains no data
        //or hexstring has an odd length
        return -1;
    }

    for(count = 0; count < len; count++)
    {
        char buf[5] = {'0', 'x', pos[0], pos[1], 0};
        data[count] = strtol(buf, &endptr, 0);
        pos += 2 * sizeof(char);

        if (endptr[0] != '\0')
        {
            //non-hexadecimal character encountered
            return -1;
        }

    }
    
    return 0;
}

int getFileSize(FILE* fptr)
{
    int len;
    if(fptr == NULL)
    {
        return 0;
    }
    fseek(fptr, 0 , SEEK_END);
    len = ftell(fptr);
    rewind (fptr);
    return len;
}

void dump_buffer_hex(char* filename, void* buffer, int size)
{
    FILE* fptr;
    printf("writing 0x%x bytes to %s...", size, filename);
    if((buffer != NULL)&&(filename != NULL)&&(size != 0))
    {
        fptr = fopen(filename, "wb");
        if(fptr != NULL)
        {
            fwrite(buffer, size, 1, fptr);
            fclose(fptr);
        }
        else
        {
            printf("ERROR! Could not open file for writing!\n");
            return;
        }
    }
    else
    {
        printf("ERROR! Invalid args supplied to dump function!\n");
        return;
    }
    printf("done!\n");
}

unsigned char* readFileToBuf(char* fname, int* len)
{
    FILE* fin;
    unsigned char* buf = NULL;
    fin = fopen(fname, "rb");
    if(fin != NULL)
    {
        int sz = getFileSize(fin);
        printf("loading file %s 0x%x bytes...", fname, sz);
        buf = (unsigned char*)malloc(sz);
        if(buf != NULL)
        {
            fread(buf, sz, 1, fin);
            if(len != NULL)
                *len = sz;
            printf("done!\n");
        }
        else
            printf("failed to allocate 0x%x bytes!\n", sz);
        fclose(fin);
    }
    return buf;
}

unsigned int getBeU32(void* prt)
{
	unsigned char* ptr = (unsigned char*)prt;
	unsigned int ret = (ptr[0]&0xFF)<<24;
	ret |= (ptr[1]&0xFF)<<16;
	ret |= (ptr[2]&0xFF)<<8;
	ret |= ptr[3]&0xFF;
	return ret;
}	

unsigned long long getBeU64(void* prt)
{
	unsigned char* ptr = (unsigned char*)prt;
	unsigned long long res = getBeU32(ptr);
	res = res << 32;
	res |= (getBeU32(ptr+4)&0xFFFFFFFF);
	return res;
}    

void get_sha(unsigned char* data_buff, int data_sz, unsigned char* hash_buff)
{
    sha1_context ctx;
    sha1_init( &ctx );
    sha1_starts( &ctx);
    sha1_update( &ctx, data_buff, data_sz );
    sha1_finish( &ctx, hash_buff); 
    sha1_free( &ctx );
    return;
}

void get_sha_hmac(unsigned char* key_buff, int key_sz, unsigned char* data_buff, int data_sz, unsigned char* hash_buff)
{
    sha1_context ctx;
    sha1_init( &ctx );
    sha1_hmac_starts( &ctx, key_buff, key_sz );
    sha1_hmac_update( &ctx, data_buff, data_sz );
    sha1_hmac_finish( &ctx, hash_buff); 
    sha1_free( &ctx );
    return;
}

void get_sha_hmac_ldr_bb(unsigned char* key_buff, int key_sz, unsigned char* data_buff, int data_sz, unsigned char* hash_buff)
{
    sha1_context ctx;
    sha1_init( &ctx );
    sha1_hmac_starts( &ctx, key_buff, key_sz );
    sha1_hmac_update( &ctx, data_buff, data_sz );
    sha1_hmac_update( &ctx, zero_key, 0x10);
    sha1_hmac_finish( &ctx, hash_buff); 
    sha1_free( &ctx );
    return;
}

void crypt_ldr(unsigned char* key, int key_sz, int data_sz, unsigned char* in, unsigned char* out)
{
    arc4_context ctx1;
    arc4_init( &ctx1);
    arc4_setup( &ctx1, key, key_sz);
    arc4_crypt( &ctx1, data_sz, in, out);
    arc4_free( &ctx1 );
    return;
}

unsigned int getPageEcc(unsigned char* datc, unsigned char* spare)
{
    unsigned int i=0, val=0, v=0;
    unsigned int* data = (unsigned int*) datc;
    for (i = 0; i < 0x1066; i++)
    {
        if (!(i & 31))
        {
            if (i == 0x1000)
                data = (unsigned int*)spare;
            v = ~*data++; // byte order: LE 
        }
        val ^= v & 1;
        v>>=1;
        if (val & 1)
            val ^= 0x6954559;
        val >>= 1;
    }
    return ~val;
}

void fixPageEcc(unsigned char* datc, unsigned char* spare)
{
    unsigned int val=getPageEcc(datc, spare);
    spare[12] = (spare[12]&0x3F)+((val << 6) & 0xC0);
    spare[13] = (val >> 2) & 0xFF;
    spare[14] = (val >> 10) & 0xFF;
    spare[15] = (val >> 18) & 0xFF;
    return;
}

void fixFuses()
{
    int patch_slot_start;
    int patch_slot_sz;
    int vfuse_start;
    int rows=0;
    int rowplus=0;
	int ctr=0;	
	unsigned char new_addr[4];
	unsigned long long testfuse;
    unsigned long long fuse;
   
    patch_slot_start=getBeU32(&flash[0xc]);
    patch_slot_sz=getBeU32(&flash[0x70]);
    vfuse_start=patch_slot_start+patch_slot_sz;
    
	testfuse=getBeU64(&flash[vfuse_start]);
	if(testfuse != 0xc0ffffffffffffff && ctr != f_sz){
		while(testfuse != 0xc0ffffffffffffff){
			testfuse=getBeU64(&flash[ctr]);
			ctr=ctr+4;}
			
		printf("Virtaul Fuses Found At 0x%X\n:", ctr-4);
		ctr=ctr-4;
		new_addr[0]=ctr-patch_slot_start >>24;
		new_addr[1]=ctr-patch_slot_start <<8 >>24;
		new_addr[2]=ctr-patch_slot_start <<16 >>24;
		new_addr[3]=ctr-patch_slot_start <<24 >>24;
		memcpy(&flash[0x70], new_addr, 4);}

	//	else{
	//		printf("Could not Find Virtual Fuses Make Sure You Built a Gitch2m Image");
	//		}
		patch_slot_sz=getBeU32(&flash[0x70]);
		vfuse_start=patch_slot_start+patch_slot_sz;
	
	memset(&flash[vfuse_start+56], 0, 40);
    
    printf("Virtual Fuses Set To:\n");    
    while(rows != 12)
    {
       fuse=getBeU64(&flash[vfuse_start+rowplus]);
       printf("Fuseset %02d: %016llX\n", rows, fuse);
       rows=rows+1;
       rowplus=rowplus+8;         
    }  
    return;  
}

void getLdrHdrs()
{
    ldr_b_start=getBeU32(&flash[0x8]);
    ldr_b_end=getBeU32(&flash[ldr_b_start+0xc]);
    
    ldr_bb_start=ldr_b_start+ldr_b_end;
    ldr_bb_end=getBeU32(&flash[ldr_bb_start+0xc]); 

    ldr_d_start=ldr_bb_start+ldr_bb_end;
    ldr_d_end=getBeU32(&flash[ldr_d_start+0xc]); 

    ldr_e_start=ldr_d_start+ldr_d_end;
    ldr_e_end=getBeU32(&flash[ldr_e_start+0xc]);

    return;
}

void getLdrKeysRetail()
{
    get_sha_hmac(bl_key, 0x10, &flash[ldr_b_start+0x10], 0x10, hmac);
    memcpy(ldr_b_key, hmac, 0x10);
    memset(hmac, 0, 0x40);

    memset(zero_key, 0, 0x10);
    get_sha_hmac_ldr_bb(ldr_b_key, 0x10, &flash[ldr_bb_start+0x10], 0x10, hmac);
    memcpy(ldr_bb_key, hmac, 0x10);
    memset(hmac, 0, 0x40);

    get_sha_hmac(ldr_bb_key, 0x10, &flash[ldr_d_start+0x10], 0x10, hmac);
    memcpy(ldr_d_key, hmac, 0x10);
    memset(hmac, 0, 0x40);

    get_sha_hmac(ldr_d_key, 0x10, &flash[ldr_e_start+0x10], 0x10, hmac);
    memcpy(ldr_e_key, hmac, 0x10);
    memset(hmac, 0, 0x40);
    
    return;
}

void decryptLdrs()
{
    //crypt_ldr(ldr_b_key, 0x10, ldr_b_end-0x20, &flash[ldr_b_start+0x20], &flash[ldr_b_start+0x20]);
    //crypt_ldr(ldr_bb_key, 0x10, ldr_bb_end-0x20, &flash[ldr_bb_start+0x20], &flash[ldr_bb_start+0x20]);
    crypt_ldr(ldr_d_key, 0x10, ldr_d_end-0x20, &flash[ldr_d_start+0x20], &flash[ldr_d_start+0x20]);
    crypt_ldr(ldr_e_key, 0x10, ldr_e_end-0x20, &flash[ldr_e_start+0x20], &flash[ldr_e_start+0x20]);
    return;
}

void getLdrKeysDevkit()
{
    get_sha_hmac(zero_key, 0x10, &ldr_c[0x10], 0x10, hmac);
    memcpy(ldr_c_key, hmac, 0x10);
    memset(hmac, 0, 0x40);    

    get_sha_hmac(ldr_c_key, 0x10, &ldr_d[0x10], 0x10, hmac);
    memcpy(ldr_d_key, hmac, 0x10);
    memset(hmac, 0, 0x40);

    get_sha_hmac(ldr_d_key, 0x10, &ldr_e[0x10], 0x10, hmac);
    memcpy(ldr_e_key, hmac, 0x10);
    memset(hmac, 0, 0x40);
    
    return;    
}

void encryptLdrs()
{
  crypt_ldr(ldr_c_key, 0x10, ldr_c_end-0x20, &ldr_c[0x20], &ldr_c[0x20]);
  crypt_ldr(ldr_d_key, 0x10, ldr_d_end-0x20, &ldr_d[0x20], &ldr_d[0x20]);
  crypt_ldr(ldr_e_key, 0x10, ldr_e_end-0x20, &ldr_e[0x20], &ldr_e[0x20]);
  return;    
}

void buildBootBlk()
{
    boot_blk_sz=ldr_b_end+ldr_bb_end+ldr_c_end+ldr_d_end+ldr_e_end;    
    boot_blk=malloc(boot_blk_sz);
    memcpy(boot_blk, &flash[ldr_b_start], ldr_b_end+ldr_bb_end);
    memcpy(&boot_blk[ldr_b_end+ldr_bb_end], ldr_c, ldr_c_end);
    memcpy(&boot_blk[ldr_b_end+ldr_bb_end+ldr_c_end], ldr_d, ldr_d_end);
    memcpy(&boot_blk[ldr_b_end+ldr_bb_end+ldr_c_end+ldr_d_end], ldr_e, ldr_e_end);
    memcpy(&flash[ldr_b_start], boot_blk, boot_blk_sz);
    return;    
}    


int main (int argc, char** argv)
// usage
{
    if(argc!=4){
		printf("\nUsage: XDKbuild v0.05b [input image file] [1bl_key] [sc_file]\n");
        printf("By Xvistaman2005\n");
		exit(0);
	}
// flash file vars    
    
	printf("XDKbuild v0.05b By Xvistaman2005\n");
	
//open the flash file and unecc image
    FILE* f;
    f=fopen(argv[1], "rb");
    
    if(f==NULL) {
    printf("Could not open input image file\n");
    exit(0);}    

    fseek(f, 0, SEEK_END);
    f_sz= ftell(f);
    rewind(f);


    f_pgs=f_sz/528;
    flash=malloc(f_sz);
    ecc=malloc(f_sz);
	memset(ecc, 0x0, f_sz);

	if(f_sz==50331648){
		fread(flash, f_sz, 0x01, f);}

    else if (f_sz==17301504||f_sz==69206016){
	while(i != f_sz){
        fread(&flash[x], 512, 0x01, f);
        fread(&ecc[y], 16, 0x01, f);
        i=i+528;
        x=x+512;
        y=y+16; }
	}	
	
	else{
		printf("Image Does Not Seem To Be A Valid Size For A Xbox360 Image\n");
		printf("Valid Sizes Are 17301504=16mb nand, 69206016==Big Block Image 256mb/512mb, 50331648=Corona 4Gb eMMC\n");
		exit(0);
		}
	
	fclose(f);
	printf("Reading Image File %s\n", argv[1]);
	
// test ecc bytes for v1 or v2	
	if(ecc[0x210] == 0x01){
		printf("Image Type: Small Block On Small Block Controller\n\n");
		sfc=1;}

	if(ecc[0x211] == 0x01){
		printf("Image Type: Small Block On Big Block Controller\n");
		sfc=2;}
		
	if(ecc[0x1010]==0xff&& ecc[0x1011]==0x01 ){
		printf("Image Type: Big Block On Big Block Controller\n");
		sfc=3;}
			
	if(f_sz==50331648){
		printf("Image Type: eMMC Controller\n");
		sfc=4;
	}		
		

//get keys from command line and conver then to hex data
    sscanf(argv[2], "%s", bl_string);
    hex2data(bl_key, bl_string, 0x20);
	printf("Setting 1BL key as: %s\n", argv[2]);

//get loction of all ldrs in flash
    getLdrHdrs();
	printf("Locating Bootloaders\n");

//setup buffers for decrypted ldrs
    ldr_d=malloc(ldr_d_end);
    ldr_e=malloc(ldr_e_end);

 // create all ldr keys to crpyt ldrs with   
    getLdrKeysRetail();
	printf("Calculating Retail Decryption Keys\n");
	
//read in the sc file from the file name on the cmd line    
    FILE* scf;
    scf=fopen(argv[3], "rb");

	if(scf==NULL) {
    printf("Could not open SC bootloader file\n");
    exit(0);} 

    fseek(scf, 0, SEEK_END);
    ldr_c_end= ftell(scf);
    rewind(scf);

//setup sc buffer
    ldr_c=malloc(ldr_c_end);
    fread(ldr_c, ldr_c_end, 0x01, scf);
    fclose(scf);
	printf("Reading SC Bootloader File: %s\n", argv[3]);

//decrypt the ldrs
    decryptLdrs();
	printf("Decrypting Bootloaders\n");

//copy the decrpyted SD SE to there own buffers for crypto
    memcpy(ldr_d, &flash[ldr_d_start], ldr_d_end);
    memcpy(ldr_e, &flash[ldr_e_start], ldr_e_end); 

//setup devkit crpyto keys for SC SD SE ldrs
    getLdrKeysDevkit();
	printf("Calculating Devkit Encryption Keys\n");	

//encrypt the ldrs with devkit crypto keys
    encryptLdrs();
	printf("Encrypting Bootloaders\n");	

//create new ldr chain    
    buildBootBlk();
	printf("Building New Devkit Bootchain\n");	


//set vufses cf ldv to 0x0 and print the vfuses
    fixFuses();
//	dump_buffer_hex("ecc.bin", ecc, y);
//fix up the ecc bytes ad readd to image

int ii=0;
int xx=0;
int yy=16;
unsigned int sha_exp=0x9D0AC37B;
unsigned int sha_calc;
unsigned int blk_num_a=0;
unsigned int blk_num_b=0;
unsigned int pg_ctr=0;
unsigned int blk_ctr_b=0; 
unsigned int out_sz=0; 
    FILE* ff;
    ff=fopen(argv[1], "r+b");
   
    if(f==NULL) {
    printf("Could not open output image file\n");
    exit(0);} 

	if(sfc==4){
		fwrite(&flash[xx], f_sz, 1, ff);
	}
	
	else{
	
	while(out_sz != 1310720)
    {
    get_sha(&flash[xx], 512, sha);
    memcpy(ecc_hash, sha, 0x10); 
    sha_calc=getBeU32(&ecc_hash[0x0]);
 //   blk_num=getBeU32(&ecc[yy]);
//    blk_num=blk_num>>16;
    if(sha_calc != sha_exp){
    //    printf("Checking ECC Spare At Block Nmber %X\n",blk_num_a);
        memset(new_ecc, 0x0, 16);
	
		if(sfc==1||sfc==2){
		
		if(pg_ctr==32){
			blk_num_a++;
			pg_ctr=0;}
		
		if(blk_num_a==0xff){
			blk_num_b++;
			blk_num_a=0;}
		}
		
		if(sfc==3){
		
		if(pg_ctr==256){
			blk_num_a++;
			pg_ctr=0;}
		}
		
		if(sfc==1){
		new_ecc[0]=blk_num_a;
		new_ecc[1]=blk_num_b;
		new_ecc[5]=0xff;}
		
		if(sfc==2){
		new_ecc[1]=blk_num_a;
		new_ecc[2]=blk_num_b;
		new_ecc[5]=0xff;}
		
		if(sfc==3){
		new_ecc[0]=0xff;
		new_ecc[1]=blk_num_a;}
			
		fixPageEcc(&flash[xx], new_ecc);
        fwrite(&flash[xx], 512, 1, ff);
        fwrite(&new_ecc, 16, 1, ff);
        pg_ctr++;
        xx=xx+512;
        yy=yy+16;
		out_sz=out_sz+512;}
   
   else {
    //    printf("Empty Page Found In Image Skipping ECC Check at Block Number\n", blk_num_a);    
        fwrite(&flash[xx], 512, 1, ff);
        memset(new_ecc, 0xff, 16);
		fwrite(new_ecc, 16, 1, ff);
        
		if(sfc==1||sfc==2){
		
		if(pg_ctr==32){
			blk_num_a++;
			pg_ctr=0;}
		
		if(blk_num_a==0xff){
			blk_num_b++;
			blk_num_a=0;}
		}	
		
		if(sfc==3){
		
		if(pg_ctr==256){
			blk_num_a++;
			pg_ctr=0;}
		}
		
		pg_ctr++;
        xx=xx+512;
        yy=yy+16;
		out_sz=out_sz+512;}
    }}

    printf("Writing Final Image To File: %s\n", argv[1]);

    fclose(ff);
    
	free (flash);
	free (ecc);
	free (boot_blk);
	free (ldr_d);
	free (ldr_e);
	free (ldr_c);
		
    return 0; 
}
