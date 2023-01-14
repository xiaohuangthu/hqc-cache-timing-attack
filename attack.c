#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <assert.h>
#include <time.h>
#include <mastik/fr.h>
#include <mastik/low.h>
#include <mastik/util.h>
#include <stdlib.h>
#include <sys/stat.h>	/* mkdir */
#include <time.h>		/* time_t, struct tm, time, localtime, strftime */
#include <string.h>

#include <api.h>
#include <parameters.h>
#include <vector.h>
#include <shake_ds.h>
#include <shake_prng.h>
#include<code.h>
#include <hqc.h>
#include<gf2x.h>

#include <parsing.h>

#include <fips202.h>

#define RESET   "\033[0m"
#define RED     "\033[31m"      /* Red */
#define GREEN   "\033[32m"      /* Green */

#define ENTROPY_BYTES 			100
#define PERSONALIZATION_BYTES 	100
int cnt_query=0;
int y_range[46]={0};
int x_range[46]={0};

FILE *f1;
uint64_t x[VEC_N_SIZE_64] = {0};
uint32_t y[PARAM_OMEGA] = {0};

uint32_t x_coordinate[PARAM_OMEGA] = {0};
uint32_t y_coordinate[PARAM_OMEGA] = {0};
int recovered_bloc=0;
int correct_guess=0;
void hqc_pke_encrypt_fake(uint64_t *u, uint64_t *v, uint64_t *m, unsigned char *theta, const unsigned char *pk, uint64_t r1[VEC_N_SIZE_64], uint64_t e[VEC_N_SIZE_64]) {
    seedexpander_state seedexpander;
    uint64_t h[VEC_N_SIZE_64] = {0};
    uint64_t s[VEC_N_SIZE_64] = {0};

    uint32_t r2[PARAM_OMEGA_R] = {0};

    uint64_t tmp1[VEC_N_SIZE_64] = {0};
    uint64_t tmp2[VEC_N_SIZE_64] = {0};
    
    

    // Create seed_expander from theta
    seedexpander_init(&seedexpander, theta, SEED_BYTES);

    // Retrieve h and s from public key
    hqc_public_key_from_string(h, s, pk);

    // Generate r1, r2 and e
    vect_set_random_fixed_weight(&seedexpander, r1, PARAM_OMEGA_R);
    vect_set_random_fixed_weight_by_coordinates(&seedexpander, r2, PARAM_OMEGA_R);
    vect_set_random_fixed_weight(&seedexpander, e, PARAM_OMEGA_E);

    // Compute u = r1 + r2.h
    vect_mul(u, r2, h, PARAM_OMEGA_R, &seedexpander);
    vect_add(u, r1, u, VEC_N_SIZE_64);

    // Compute v = m.G by encoding the message
    code_encode(v, m);
    vect_resize(tmp1, PARAM_N, v, PARAM_N1N2);

    // Compute v = m.G + s.r2 + e
    vect_mul(tmp2, r2, s, PARAM_OMEGA_R, &seedexpander);
    vect_add(tmp2, e, tmp2, VEC_N_SIZE_64);
    vect_add(tmp2, tmp1, tmp2, VEC_N_SIZE_64);
    vect_resize(v, PARAM_N1N2, tmp2, PARAM_N);

    #ifdef VERBOSE
        printf("\n\nh: "); vect_print(h, VEC_N_SIZE_BYTES);
        printf("\n\ns: "); vect_print(s, VEC_N_SIZE_BYTES);
        printf("\n\nr1: "); vect_print(r1, VEC_N_SIZE_BYTES);
        printf("\n\nr2: "); vect_print_sparse(r2, PARAM_OMEGA_R);
        printf("\n\ne: "); vect_print(e, VEC_N_SIZE_BYTES);
        printf("\n\ntmp2: "); vect_print(tmp2, VEC_N_SIZE_BYTES);

        printf("\n\nu: "); vect_print(u, VEC_N_SIZE_BYTES);
        printf("\n\nv: "); vect_print(v, VEC_N1N2_SIZE_BYTES);
    #endif
}

int crypto_kem_dec_fake(unsigned char *ss, const unsigned char *ct, const unsigned char *sk, uint64_t r1[VEC_N_SIZE_64], uint64_t e[VEC_N_SIZE_64]) {
    #ifdef VERBOSE
        printf("\n\n\n\n### DECAPS ###");
    #endif
    
    for(int i=0;i<VEC_N_SIZE_64;i++)
    {
    	r1[i]=0;
    	e[i]=0;
    }

    uint8_t result;
    uint64_t u[VEC_N_SIZE_64] = {0};
    uint64_t v[VEC_N1N2_SIZE_64] = {0};
    uint8_t d[SHAKE256_512_BYTES] = {0};
    uint8_t pk[PUBLIC_KEY_BYTES] = {0};
    uint64_t m[VEC_K_SIZE_64] = {0};
    uint8_t theta[SHAKE256_512_BYTES] = {0};
    uint64_t u2[VEC_N_SIZE_64] = {0};
    uint64_t v2[VEC_N1N2_SIZE_64] = {0};
    uint8_t d2[SHAKE256_512_BYTES] = {0};
    uint8_t mc[VEC_K_SIZE_BYTES + VEC_N_SIZE_BYTES + VEC_N1N2_SIZE_BYTES] = {0};
    shake256incctx shake256state;

    // Retrieving u, v and d from ciphertext
    hqc_ciphertext_from_string(u, v , d, ct);

    // Retrieving pk from sk
    memcpy(pk, sk + SEED_BYTES, PUBLIC_KEY_BYTES);

    // Decryting
    hqc_pke_decrypt(m, u, v, sk);
    


    // Computing theta
    shake256_512_ds(&shake256state, theta, (uint8_t*) m, VEC_K_SIZE_BYTES, G_FCT_DOMAIN);

    // Encrypting m'
    hqc_pke_encrypt_fake(u2, v2, m, theta, pk, r1, e);

    // Computing d'
    shake256_512_ds(&shake256state, d2, (uint8_t *) m, VEC_K_SIZE_BYTES, H_FCT_DOMAIN);

    // Computing shared secret
    memcpy(mc, m, VEC_K_SIZE_BYTES);
    memcpy(mc + VEC_K_SIZE_BYTES, u, VEC_N_SIZE_BYTES);
    memcpy(mc + VEC_K_SIZE_BYTES + VEC_N_SIZE_BYTES, v, VEC_N1N2_SIZE_BYTES);
    shake256_512_ds(&shake256state, ss, mc, VEC_K_SIZE_BYTES + VEC_N_SIZE_BYTES + VEC_N1N2_SIZE_BYTES, K_FCT_DOMAIN);

    // Abort if c != c' or d != d'
    result = vect_compare((uint8_t *)u, (uint8_t *)u2, VEC_N_SIZE_BYTES);
    result |= vect_compare((uint8_t *)v, (uint8_t *)v2, VEC_N1N2_SIZE_BYTES);
    result |= vect_compare(d, d2, SHAKE256_512_BYTES);

    result = (uint8_t) (-((int16_t) result) >> 15);

    for (size_t i = 0 ; i < SHARED_SECRET_BYTES ; i++) {
        ss[i] &= ~result;
    }

    #ifdef VERBOSE
        printf("\n\npk: "); for(int i = 0 ; i < PUBLIC_KEY_BYTES ; ++i) printf("%02x", pk[i]);
        printf("\n\nsk: "); for(int i = 0 ; i < SECRET_KEY_BYTES ; ++i) printf("%02x", sk[i]);
        printf("\n\nciphertext: "); for(int i = 0 ; i < CIPHERTEXT_BYTES ; ++i) printf("%02x", ct[i]);
        printf("\n\nm: "); vect_print(m, VEC_K_SIZE_BYTES);
        printf("\n\ntheta: "); for(int i = 0 ; i < SHAKE256_512_BYTES ; ++i) printf("%02x", theta[i]);
        printf("\n\n\n# Checking Ciphertext- Begin #");
        printf("\n\nu2: "); vect_print(u2, VEC_N_SIZE_BYTES);
        printf("\n\nv2: "); vect_print(v2, VEC_N1N2_SIZE_BYTES);
        printf("\n\nd2: "); for(int i = 0 ; i < SHAKE256_512_BYTES ; ++i) printf("%02x", d2[i]);
        printf("\n\n# Checking Ciphertext - End #\n");
    #endif

    return -(result & 1);
}

void indicator(uint64_t r1[VEC_N_SIZE_64], uint64_t e[VEC_N_SIZE_64], int fr_r1[35], int fr_e[35])
{
	int flag=0;
	

	for(int i=0;i<35;i++)
	{
		flag=0;
		for(int j=0;j<8;j++)
		{
			if((8*i+j)<277)
			{
				if(r1[8*i+j]!=0)
				{
					flag=1;
					break;
				}
			}
		}
		
		if(flag==0)
		{
			fr_r1[i]=0;
		}
		else
		{
			fr_r1[i]=1;
		}
	}

	for(int i=0;i<35;i++)
	{
		flag=0;
		for(int j=0;j<8;j++)
		{
			if((8*i+j)<277)
			{
				if(e[8*i+j]!=0)
				{
					flag=1;
					break;
				}
			}
		}
		if(flag==1)
		{
			fr_e[i]=1;
		}
		else
		{
			fr_e[i]=0;
		}
	}
}

int equal(int tmp_fr_r1[35], int tmp1_fr_r1[35], int tmp_fr_e[35], int tmp1_fr_e[35])
{
	if((memcmp(tmp_fr_r1, tmp1_fr_r1, 140)==0)&(memcmp(tmp_fr_e, tmp1_fr_e, 140)==0))
	{
		return 1;
	}
	else
	{
		return 0;
	}
}
int HW(uint64_t b)
{
	int tmp = 0;
	for (int i = 0; i < 64; i++)
	{
		if (((b >> i) & 0x1) == 1)
		{
			tmp++;
		}
	}
	return tmp;
}

void random384(int weight, uint64_t mask[6])
{
	for(int i=0;i<weight;i++)
	{
		int tmp=rand()%384;
		
		while(((mask[tmp/64]>>(tmp%64))&0x1)==1)
		{
			tmp=rand()%384;
		}
		mask[tmp/64]= mask[tmp/64] ^ (((uint64_t)1)<< (tmp%64));
		
	}
}

int HW8(unsigned char b)
{
	int tmp = 0;
	for (int i = 0; i < 8; i++)
	{
		if (((b >> i) & 0x1) == 1)
		{
			tmp++;
		}
	}
	return tmp;
}
static inline uint64_t rotl64 (uint64_t n, unsigned int c)
{
  const unsigned int mask = (8*sizeof(n) - 1);  // assumes width is a power of 2.

  // assert ( (c<=mask) &&"rotate by type width or more");
  c &= mask;
  return (n<<c) | (n>>( (-c)&mask ));
}
void sample(uint64_t tmp_v1[VEC_N1N2_SIZE_64], uint64_t tmp1_r1[VEC_N_SIZE_64], uint32_t tmp1_r2[PARAM_OMEGA_R],  uint64_t tmp1_e[VEC_N_SIZE_64])
{
	for(int i=0;i<VEC_N_SIZE_64;i++)
	{
		tmp1_r1[i]=0;
		tmp1_e[i]=0;
	}
	uint64_t m1[2]={0};
	code_decode(m1,tmp_v1);
	uint8_t theta[SHAKE256_512_BYTES] = {0};
				
	// Computing theta
	seedexpander_state seedexpander;
	shake256incctx shake256state;
	shake256_512_ds(&shake256state, theta, (uint8_t*) m1, VEC_K_SIZE_BYTES, G_FCT_DOMAIN);
	seedexpander_init(&seedexpander, theta, SEED_BYTES);
	vect_set_random_fixed_weight(&seedexpander, tmp1_r1, PARAM_OMEGA_R);
	vect_set_random_fixed_weight_by_coordinates(&seedexpander, tmp1_r2, PARAM_OMEGA_R);
	vect_set_random_fixed_weight(&seedexpander, tmp1_e, PARAM_OMEGA_E);
}
void injectblock(uint64_t *word, int bit)
{
	uint64_t tmp[VEC_N1_SIZE_64] = {0};

    reed_muller_decode(tmp, word);
    
    int cnt=0;
    while(1)
    {
    	cnt++;
    	uint64_t mask[6]={0}, tmp_word[VEC_N1N2_SIZE_64]={0};
    	uint64_t tmp1[VEC_N1_SIZE_64]={0}, tmp2[VEC_N1_SIZE_64]={0};
    	//memcpy(tmp_word, word, 48);
    	
    	random384(bit, mask);
    	
    	for(int i=0;i<6;i++)
    	{
    		tmp_word[i]=word[i]^mask[i];
    	}
    	
    	reed_muller_decode(tmp1, tmp_word);
    	
    	if(tmp1[0]==tmp[0])
    	{
    		continue;
    	}
    	
    	int flag=0;
    	
    	for(int i=0;i<384;i++)
		{
			
			uint64_t tmp_word1[VEC_N1N2_SIZE_64]={0};
			memcpy(tmp_word1, tmp_word, 48);
			
			tmp_word1[i/64]=tmp_word1[i/64] ^ (((uint64_t)1)<< (i%64));
			
			reed_muller_decode(tmp2, tmp_word1);
			
			if(tmp1[0]!=tmp2[0])
			{
				flag=1;
				break;
			}
		}
		
		if(flag==1)
		{
			continue;
		}
    	for(int i=0;i<384;i++)
		{
			for(int j=i+1;j<384;j++)
			{
					uint64_t tmp_word1[VEC_N1N2_SIZE_64]={0};
					memcpy(tmp_word1, tmp_word, 48);
					
					tmp_word1[i/64]=tmp_word1[i/64] ^ (((uint64_t)1)<< (i%64));
					
					tmp_word1[j/64]=tmp_word1[j/64] ^ (((uint64_t)1)<< (j%64));
					
					
					reed_muller_decode(tmp2, tmp_word1);
					
					if(tmp1[0]!=tmp2[0])
					{
						flag=1;
						break;
					}
			}
			
			if(flag==1)
			{
				break;
			}
		}
		
		if(flag==0)
		{
			memcpy(word, tmp_word, 48);
			break;
		}
    }
    
    
    
}

void injectblock1(uint64_t *word, int bit)
{
	uint64_t tmp[VEC_N1_SIZE_64] = {0};

    reed_muller_decode(tmp, word);
    
    while(1)
    {
    	uint64_t mask[6]={0}, tmp_word[VEC_N1N2_SIZE_64]={0};
    	uint64_t tmp1[VEC_N1_SIZE_64]={0};
    	
    	random384(bit, mask);
    	
    	for(int i=0;i<6;i++)
    	{
    		tmp_word[i]=word[i]^mask[i];
    	}
    	
    	reed_muller_decode(tmp1, tmp_word);
    	
    	if(tmp1[0]!=tmp[0])
    	{
    		memcpy(word, tmp_word, 48);
			break;
    	}
    }
}
int prcd(uint64_t m[2], uint64_t v[VEC_N1N2_SIZE_64], int position)
{
	int cnt=0;
	while(cnt<200)
	{
		cnt++;
		uint64_t tmp_v[VEC_N1N2_SIZE_64]={0};
		memcpy(tmp_v, v, 8*VEC_N1N2_SIZE_64);
		uint64_t mask[6]={0};
		
		random384(200, mask);
		
		for(int j=0;j<6;j++)
		{
			tmp_v[position*6+j]= tmp_v[position*6+j]^ mask[j];
		}
		
		uint64_t m1[2]={0};
		code_decode(m1,tmp_v);
		
		if((m1[0]!=m[0])||(m1[0]!=m[0]))
		{
			return 0;
		}
	
	}
	return 1;
}
void injecterror(uint64_t m[2], uint64_t u[VEC_N_SIZE_64], uint64_t v[VEC_N1N2_SIZE_64], uint64_t tmp_v[VEC_N1N2_SIZE_64], unsigned char sk[SECRET_KEY_BYTES], uint8_t d[SHAKE256_512_BYTES], int index_start, int *index_nr, int index[46], int fr_r1[35],  int fr_e[35])
{   

	memcpy(tmp_v, v, 8*VEC_N1N2_SIZE_64);
	int tmp=index_start;
	*index_nr=0;
	while(1)
	{
		int flag=prcd(m,tmp_v, tmp);
		
		if(flag==1)
		{
			uint64_t word[VEC_N1N2_SIZE_64]={0};
			for(int j=0;j<6;j++)
			{
				word[j]=tmp_v[tmp*6+j];
			}
			injectblock(word, 200);
			for(int j=0;j<6;j++)
			{
				tmp_v[tmp*6+j]= word[j];
			}
			//printf("%d is finished\n", tmp);
			
			index[*index_nr]=tmp;
			*index_nr=*index_nr+1;
			tmp=tmp+1;
			
		}
		else
		{
			break;
		}
		
	}
}
int inject_guessed_block(uint64_t m[2], uint64_t u[VEC_N_SIZE_64], uint64_t tmp_v[VEC_N1N2_SIZE_64], unsigned char sk[SECRET_KEY_BYTES], uint8_t d[SHAKE256_512_BYTES], int position, int fr_r1[35],  int fr_e[35], int tmp_fr_r1[35], int tmp_fr_e[35])
{
	uint64_t tmp1_r1[VEC_N_SIZE_64] = {0};
    uint64_t tmp1_e[VEC_N_SIZE_64] = {0};
    unsigned char ss[SHARED_SECRET_BYTES]={0};
    int cnt=0;
	while(cnt<600)
	{
		cnt++;
		uint64_t tmp_v1[VEC_N1N2_SIZE_64];
		memcpy(tmp_v1, tmp_v, 8*VEC_N1N2_SIZE_64);
		
		//random384(200, mask);
		
		uint64_t word[VEC_N1N2_SIZE_64]={0};
		for(int j=0;j<6;j++)
		{
			word[j]=tmp_v1[position*6+j];
		}
		injectblock1(word, 150);
		for(int j=0;j<6;j++)
		{
			tmp_v1[position*6+j]= word[j];
		}
		
		
		unsigned char tmp_ct[CIPHERTEXT_BYTES]={0};
	
		hqc_ciphertext_to_string(tmp_ct, u, tmp_v1, d);
		crypto_kem_dec_fake(ss, tmp_ct, sk, tmp1_r1, tmp1_e);
		indicator(tmp1_r1, tmp1_e, tmp_fr_r1, tmp_fr_e);
		cnt_query++;

		uint64_t m1[2]={0};
		code_decode(m1,tmp_v1);
		
		if(equal(fr_r1, tmp_fr_r1, fr_e, tmp_fr_e)==1)//'1'
		{
			if((m1[0]!=m[0])||(m1[1]!=m[1]))
			{	
				memcpy(tmp_v, tmp_v1, 8*VEC_N1N2_SIZE_64);
				return 1;
			}
			
		}
		
		if(equal(fr_r1, tmp_fr_r1, fr_e, tmp_fr_e)==0)//'0'
		{
			if((m1[0]==m[0])&&(m1[1]==m[1]))
			{
				memcpy(tmp_v, tmp_v1, 8*VEC_N1N2_SIZE_64);
				return 2;
			}
			
		}
	}

	return 3;
}
int inject_guessed_block_x(uint64_t m[2], uint64_t u[VEC_N_SIZE_64], uint64_t tmp_v[VEC_N1N2_SIZE_64], uint64_t s[VEC_N1N2_SIZE_64], unsigned char sk[SECRET_KEY_BYTES], uint8_t d[SHAKE256_512_BYTES], int position, int fr_r1[35],  int fr_e[35], int tmp_fr_r1[35], int tmp_fr_e[35])
{
	uint64_t tmp1_r1[VEC_N_SIZE_64] = {0};
    uint64_t tmp1_e[VEC_N_SIZE_64] = {0};
    unsigned char ss[SHARED_SECRET_BYTES]={0};
    int cnt=0;
	while(cnt<600)
	{
		cnt++;
		uint64_t tmp_v1[VEC_N1N2_SIZE_64];
		memcpy(tmp_v1, tmp_v, 8*VEC_N1N2_SIZE_64);
		
		//random384(200, mask);
		
		uint64_t word[VEC_N1N2_SIZE_64]={0};
		for(int j=0;j<6;j++)
		{
			word[j]=tmp_v1[position*6+j];
		}
		injectblock1(word, 150);
		for(int j=0;j<6;j++)
		{
			tmp_v1[position*6+j]= word[j];
		}
		
		uint64_t m1[2]={0};
		code_decode(m1,tmp_v1);
		
		
		unsigned char tmp_ct[CIPHERTEXT_BYTES]={0};
		for(int j=0;j<VEC_N1N2_SIZE_64;j++)
		{
			tmp_v1[j]=tmp_v1[j]^s[j];
		}
	
		hqc_ciphertext_to_string(tmp_ct, u, tmp_v1, d);
		crypto_kem_dec_fake(ss, tmp_ct, sk, tmp1_r1, tmp1_e);
		indicator(tmp1_r1, tmp1_e, tmp_fr_r1, tmp_fr_e);
		cnt_query++;
		
		if(equal(fr_r1, tmp_fr_r1, fr_e, tmp_fr_e)==1)//'1'
		{
			if((m1[0]!=m[0])||(m1[1]!=m[1]))
			{
				for(int j=0;j<VEC_N1N2_SIZE_64;j++)
				{
					tmp_v1[j]=tmp_v1[j]^s[j];
				}	
				memcpy(tmp_v, tmp_v1, 8*VEC_N1N2_SIZE_64);
				return 1;
			}
			
		}
		
		if(equal(fr_r1, tmp_fr_r1, fr_e, tmp_fr_e)==0)//'0'
		{
			if((m1[0]==m[0])&&(m1[1]==m[1]))
			{
				for(int j=0;j<VEC_N1N2_SIZE_64;j++)
				{
					tmp_v1[j]=tmp_v1[j]^s[j];
				}
				
				memcpy(tmp_v, tmp_v1, 8*VEC_N1N2_SIZE_64);
				return 2;
			}
			
		}
	}

	return 3;
}

void guessing(int flag, int position, uint64_t tmp_v1[VEC_N1N2_SIZE_64], uint64_t m[2], uint8_t d[SHAKE256_512_BYTES], unsigned char sk[SECRET_KEY_BYTES], int tmp_fr_r1[35], int tmp_fr_e[35], int vote[384])
{
	
	if(flag==1)
	{
		
		for(int i=0;i<6;i++)
		{
			for(int j=0;j<64;j++)
			{
				uint64_t tmp_v2[VEC_N1N2_SIZE_64]={0};
				
				
				memcpy(tmp_v2, tmp_v1, sizeof(tmp_v2));
				
				tmp_v2[6*position+i]=tmp_v2[6*position+i]^(((uint64_t)1)<<j);
				
				
				
				
				uint64_t m1[2]={0};
				code_decode(m1,tmp_v2);

				if((m1[0]==m[0])&&(m1[1]==m[1]))
				{
					vote[64*i+j]++;
				}
					
			}
		}
	}
	else
	{
		
    	
		for(int i=0;i<6;i++)
		{
			for(int j=0;j<64;j++)
			{		
				uint64_t tmp_v2[VEC_N1N2_SIZE_64]={0};
		
				uint64_t tmp1_r1[VEC_N_SIZE_64] = {0};
				uint32_t tmp1_r2[VEC_N_SIZE_64] = {0};
				uint64_t tmp1_e[VEC_N_SIZE_64] = {0};
				int tmp1_fr_r1[35]={0}, tmp1_fr_e[35]={0};
    	
				memcpy(tmp_v2, tmp_v1, sizeof(tmp_v2));
				
				tmp_v2[6*position+i]=tmp_v2[6*position+i]^(((uint64_t)1)<<j);
				
				
				

				uint64_t m1[2]={0};
				code_decode(m1,tmp_v2);
				
				uint8_t theta[SHAKE256_512_BYTES] = {0};
				
				// Computing theta
				seedexpander_state seedexpander;
				shake256incctx shake256state;
				shake256_512_ds(&shake256state, theta, (uint8_t*) m1, VEC_K_SIZE_BYTES, G_FCT_DOMAIN);
				seedexpander_init(&seedexpander, theta, SEED_BYTES);
				vect_set_random_fixed_weight(&seedexpander, tmp1_r1, PARAM_OMEGA_R);
				vect_set_random_fixed_weight_by_coordinates(&seedexpander, tmp1_r2, PARAM_OMEGA_R);
				vect_set_random_fixed_weight(&seedexpander, tmp1_e, PARAM_OMEGA_E);
				
				
				indicator(tmp1_r1, tmp1_e, tmp1_fr_r1, tmp1_fr_e);
				
				if(equal(tmp_fr_r1, tmp1_fr_r1, tmp_fr_e, tmp1_fr_e)==1)
				{
					vote[64*i+j]++;
				}	
			}
		}
	}
}

int inarray(int a, int index[46], int index_nr)
{
	
	for(int i=0;i<index_nr;i++)
	{
		if(index[i]==a)
		{
			return 1;
		}
	}
	return 0;
}
void keyrecover(uint64_t m[2], unsigned char pk[PUBLIC_KEY_BYTES],	unsigned char sk[SECRET_KEY_BYTES], uint64_t u[VEC_N_SIZE_64], uint64_t v[VEC_N1N2_SIZE_64], uint8_t d[SHAKE256_512_BYTES], uint64_t v1[VEC_N1N2_SIZE_64],  uint64_t v2[VEC_N1N2_SIZE_64])
{
	uint64_t tmp_v[VEC_N1N2_SIZE_64]={0};
	memcpy(tmp_v, v, sizeof(tmp_v));
	
	
	int fr_r1[35]={0}, fr_e[35]={0};
	
	//unsigned char tmp_ct[CIPHERTEXT_BYTES]={0};
	unsigned char ss[SHARED_SECRET_BYTES]={0}, ct[CIPHERTEXT_BYTES]={0};

    
    uint64_t r1[VEC_N_SIZE_64] = {0};
    
    uint64_t e[VEC_N_SIZE_64] = {0};
    
    //uint64_t tmp_r1[VEC_N_SIZE_64] = {0};

    //uint64_t tmp_e[VEC_N_SIZE_64] = {0};
	
	hqc_ciphertext_to_string(ct, u, v, d);
	crypto_kem_dec_fake(ss, ct, sk, r1, e);
	indicator(r1, e, fr_r1, fr_e);

	//injecterror(m, u, v, tmp_v, sk, d, index_start, index1_nr, index1, fr_r1,  fr_e);
	//memcpy(v1, tmp_v, sizeof(tmp_v));
	
	for(int i=15;i<46;i++)
	{
			int vote[384]={0};
			printf("We are guessing the %d-th block\n", i);
			int flag;
			for(int j=0;j<10;j++)
			{
				uint64_t tmp_v1[VEC_N1N2_SIZE_64]={0};
				memcpy(tmp_v1, v1, 8*VEC_N1N2_SIZE_64);
				int tmp_fr_r1[35]={0}, tmp_fr_e[35]={0};
				flag=inject_guessed_block(m, u, tmp_v1, sk, d, i, fr_r1,  fr_e, tmp_fr_r1,  tmp_fr_e);
				
				if(flag==3)
				{
					break;
				}
				//printf("Guessing starts!\n");
				
				guessing(flag, i, tmp_v1, m, d, sk, tmp_fr_r1, tmp_fr_e, vote);
				
				
			}
			if(flag==3)
			{
				printf("0 block\n");
				recovered_bloc++;
				if(y_range[i]==0)
				{
					correct_guess++;
				}
			}
			else
			{
				//int flag_guessed=0, num_guessed=0;
				for(int j=0;j<384;j++)
				{
					if(vote[j]==10)
					{
						printf("%d=1 \n", 384*i+j);
						recovered_bloc++;
						//num_guessed++;
						int tmp_index=384*i+j;
						
						if(y_range[i]==1)
						{
							for(int k=0;k<66;k++)
							{
								if(y_coordinate[k]==tmp_index)
								{
									correct_guess++;
									//flag_guessed=1;
								}
							}
						}
					}
					
				}
				/*if((flag_guessed==1)&&(num_guessed>1))
				{
					correct_guess=correct_guess-1;
				}*/
			}
			
	}
	
	
	
	for(int i=0;i<15;i++)
	{

				int vote[384]={0};
				//printf("We are guessing the %d-th block\n", i);
				int flag;
				for(int j=0;j<10;j++)
				{
					uint64_t tmp_v1[VEC_N1N2_SIZE_64]={0};
					memcpy(tmp_v1, v2, 8*VEC_N1N2_SIZE_64);
					int tmp_fr_r1[35]={0}, tmp_fr_e[35]={0};
					flag=inject_guessed_block(m, u, tmp_v1, sk, d, i, fr_r1,  fr_e, tmp_fr_r1,  tmp_fr_e);
					
					if(flag==3)
					{
						break;
					}
					//printf("Guessing starts!\n");
					
					guessing(flag, i, tmp_v1, m, d, sk, tmp_fr_r1, tmp_fr_e, vote);
					
					
				}
				if(flag==3)
				{
					//printf("0 block\n");
					recovered_bloc++;
					if(y_range[i]==0)
					{
						correct_guess++;
					}
				}
				else
				{
					//int flag_guessed=0, num_guessed=0;
					for(int j=0;j<384;j++)
					{
						if(vote[j]==10)
						{
							//printf("%d=1\n", 384*i+j);
							recovered_bloc++;
							//num_guessed++;
							int tmp_index=384*i+j;
							
							if(y_range[i]==1)
							{
								for(int k=0;k<66;k++)
								{
									if(y_coordinate[k]==tmp_index)
									{
										correct_guess++;
										//flag_guessed=1;
									}
								}
							}
						}
						
					}
					/*if((flag_guessed==1)&&(num_guessed>1))
					{
						correct_guess=correct_guess-1;
					}*/
				}


	}
  	

}
void keyrecover_x(uint64_t m[2], unsigned char pk[PUBLIC_KEY_BYTES],	unsigned char sk[SECRET_KEY_BYTES], uint64_t u[VEC_N_SIZE_64], uint64_t v[VEC_N1N2_SIZE_64], uint64_t s[VEC_N1N2_SIZE_64], uint8_t d[SHAKE256_512_BYTES], uint64_t v1[VEC_N1N2_SIZE_64],  uint64_t v2[VEC_N1N2_SIZE_64])
{
	uint64_t tmp_v[VEC_N1N2_SIZE_64]={0};
	
	
	
	int fr_r1[35]={0}, fr_e[35]={0};
	
	//unsigned char tmp_ct[CIPHERTEXT_BYTES]={0};
	unsigned char ss[SHARED_SECRET_BYTES]={0}, ct[CIPHERTEXT_BYTES]={0};

    
    uint64_t r1[VEC_N_SIZE_64] = {0};
    
    uint64_t e[VEC_N_SIZE_64] = {0};
    
    uint64_t v_s[VEC_N1N2_SIZE_64] = {0};
    
    for(int i=0;i<VEC_N1N2_SIZE_64;i++)
    {
    	v_s[i]=v[i]^s[i];
    }
	
	hqc_ciphertext_to_string(ct, u, v_s, d);
	crypto_kem_dec_fake(ss, ct, sk, r1, e);
	indicator(r1, e, fr_r1, fr_e);
	
	//int guessed_nr=0;
	memcpy(tmp_v, v1, sizeof(tmp_v));
	//injecterror(m, u, v, tmp_v, sk, d, index_start, &index_nr, index, fr_r1,  fr_e);
	
	
	for(int i=15;i<46;i++)
	{
			int vote[384]={0};
			//printf("We are guessing the %d-th block\n", i);
			int flag;
			for(int j=0;j<10;j++)
			{
				uint64_t tmp_v1[VEC_N1N2_SIZE_64]={0};
				memcpy(tmp_v1, tmp_v, 8*VEC_N1N2_SIZE_64);
				int tmp_fr_r1[35]={0}, tmp_fr_e[35]={0};
				flag=inject_guessed_block_x(m, u, tmp_v1, s, sk, d, i, fr_r1,  fr_e, tmp_fr_r1,  tmp_fr_e);
				
				if(flag==3)
				{
					
					break;
				}
				//printf("Guessing starts!\n");
				
				guessing(flag, i, tmp_v1, m, d, sk, tmp_fr_r1, tmp_fr_e, vote);
				
				
			}
			if(flag==3)
			{
				recovered_bloc++;
				if(x_range[i]==0)
				{
					correct_guess++;
				}
				//printf("0 block\n");
			}
			else
			{
				//int flag_guessed=0, num_guessed=0;
				for(int j=0;j<384;j++)
				{
					if(vote[j]==10)
					{
						//printf("%d=1\n", 384*i+j);
						recovered_bloc++;
						//num_guessed++;
						int tmp_index=384*i+j;
						
						if(x_range[i]==1)
						{
							for(int k=0;k<66;k++)
							{
								if(x_coordinate[k]==tmp_index)
								{
									correct_guess++;
								}
							}
						}
					}
					
				}
				/*if((flag_guessed==1)&&(num_guessed>1))
				{
					correct_guess=correct_guess-1;
				}*/
			}
			
			//guessed[guessed_nr]=i;
			//guessed_nr++;
	}
	
	memcpy(tmp_v, v2, sizeof(tmp_v));
	//injecterror(m, u, v, tmp_v, sk, d, index_start, &index_nr, index, fr_r1,  fr_e);
	for(int i=0;i<15;i++)
	{
				int vote[384]={0};
				//printf("We are guessing the %d-th block\n", i);
				int flag;
				for(int j=0;j<10;j++)
				{
					uint64_t tmp_v1[VEC_N1N2_SIZE_64]={0};
					memcpy(tmp_v1, tmp_v, 8*VEC_N1N2_SIZE_64);
					int tmp_fr_r1[35]={0}, tmp_fr_e[35]={0};
					flag=inject_guessed_block_x(m, u, tmp_v1, s, sk, d, i, fr_r1,  fr_e, tmp_fr_r1,  tmp_fr_e);
					
					if(flag==3)
					{
						break;
					}
					//printf("Guessing starts!\n");
					
					guessing(flag, i,  tmp_v1, m, d, sk, tmp_fr_r1, tmp_fr_e, vote);
					
					
				}
				if(flag==3)
				{
					recovered_bloc++;
					if(x_range[i]==0)
					{
						correct_guess++;
					}
					//printf("0 block\n");
				}
				else
				{
					//int flag_guessed=0, num_guessed=0;
					for(int j=0;j<384;j++)
					{
						if(vote[j]==10)
						{
							//printf("%d=1\n", 384*i+j);
							recovered_bloc++;
							//num_guessed++;
							int tmp_index=384*i+j;
							
							if(x_range[i]==1)
							{
								for(int k=0;k<66;k++)
								{
									if(x_coordinate[k]==tmp_index)
									{
										correct_guess++;
										//flag_guessed=1;
									}
								}
							}
						}
						
					}
					/*if((flag_guessed==1)&&(num_guessed>1))
					{
						correct_guess=correct_guess-1;
					}*/
				}
				
				//guessed[guessed_nr]=i;
				//guessed_nr++;
	}
	

  	

}
int main()
{

	/** ENCRYPT **/

	
	srand(time(NULL));
	uint64_t m[2]={0};
	uint64_t u[VEC_N_SIZE_64]={0};
	uint64_t v[VEC_N1N2_SIZE_64] = {0};
	uint8_t d[SHAKE256_512_BYTES] = {0};

	
	


	//read from "v.txt"
	FILE *f;
	f=fopen("ivc.txt","r");
	
	for(int i=0;i<VEC_N1N2_SIZE_64;i++)
	{
		fscanf(f,"%lu",&v[i]);
	}
	//printf("\n");
	fclose(f);
	
	u[0]=1;
	code_decode(m, v);
	
	
	unsigned char pk[PUBLIC_KEY_BYTES];
	unsigned char sk[SECRET_KEY_BYTES];
    
    uint8_t entropy_input[ENTROPY_BYTES];
	uint8_t personalization_string[PERSONALIZATION_BYTES];
	
	shake_prng_init(
		entropy_input,
		personalization_string,
		(uint32_t) ENTROPY_BYTES,
		(uint32_t) PERSONALIZATION_BYTES);
		
	crypto_kem_keypair(pk, sk);
	crypto_kem_keypair(pk, sk);
	hqc_secret_key_from_string(x, y, pk, sk);
	
	//printf("x:\n");
	int tmp_cnt=0;
	for(int i=0;i<VEC_N_SIZE_64;i++)
  	{
  		for(int j=0;j<64;j++)
  		{
  			int tmp= (x[i]>>j)&0x1;
  			if(tmp==1)
  			{
  				x_coordinate[tmp_cnt]=64*i+j;
  				tmp_cnt++;
  				tmp=(64*i+j)/384;
  				
  				x_range[tmp]++;
  			}
  		}
  		
  	}
  	
  	/*for(int i=0;i<46;i++)
  	{
  		printf("[%d, %d],\t", i, x_range[i]);
  	}
  	printf("\n");*/
	
	//printf("y:\n");
	for(int i=0;i<66;i++)
  	{
  		int tmp=y[i]/384;
  		y_range[tmp]++;
  	}
  	
  	/*for(int i=0;i<46;i++)
  	{
  		printf("[%d, %d],\t", i, y_range[i]);
  	}
  	printf("\n");*/
  	
	
	
	memcpy(y_coordinate, y, sizeof(y));
	
	
	
	uint64_t h[VEC_N_SIZE_64] = {0};
    uint64_t s[VEC_N_SIZE_64] = {0};
    uint64_t v_s[VEC_N1N2_SIZE_64] = {0}, v1[VEC_N1N2_SIZE_64] = {0}, v2[VEC_N1N2_SIZE_64] = {0};
	uint64_t tmp_s[VEC_N1N2_SIZE_64] = {0};
	
	
	printf("Recover y:\n");
	
	f=fopen("ec1.txt","r");
	
	for(int i=0;i<VEC_N1N2_SIZE_64;i++)
	{
		fscanf(f,"%lu",&v1[i]);
	}
	printf("\n");
	fclose(f);
	
	f=fopen("ec2.txt","r");
	
	for(int i=0;i<VEC_N1N2_SIZE_64;i++)
	{
		fscanf(f,"%lu",&v2[i]);
	}
	//printf("\n");
	fclose(f);
	
	
	keyrecover(m, pk,	sk, u, v, d, v1, v2);	
	
    // Retrieve h and s from public key
    hqc_public_key_from_string(h, s, pk);	
	vect_resize(tmp_s, PARAM_N1N2, s, PARAM_N);
	memcpy(u, h, sizeof(h));
	
	for(int i=0;i<VEC_N1N2_SIZE_64;i++)
	{
		v_s[i]=v_s[i]^tmp_s[i];
	}
	
	printf("Recover x:\n");
	keyrecover_x(m, pk,	sk, u, v, v_s, d, v1, v2);
	
	printf("%d, %d\n", correct_guess, recovered_bloc);
	printf("%d\n", cnt_query);
}
