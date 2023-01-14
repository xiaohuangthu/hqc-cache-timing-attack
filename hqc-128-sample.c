/**
 * @file kem.c
 * @brief Implementation of api.h
 */
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <stdio.h>

#include <api.h>
#include <parameters.h>
#include <vector.h>
#include<code.h>
#include <shake_ds.h>
#include <shake_prng.h>

//#include <fips202.h>
//gcc -g -pedantic -Wall -I../Mastik -I../hqc-128/src/ -I../hqc-128/lib/fips202 -c hqc-128-sample.c  -o sample.o
//gcc -g -pedantic -Wall -I../Mastik -I../hqc-128/src/ -I../hqc-128/lib/fips202 -o sample sample.o ../hqc-128/bin/build/kem.o ../hqc-128/bin/build/hqc.o ../hqc-128/bin/build/parsing.o ../hqc-128/bin/build/code.o ../hqc-128/bin/build/reed_solomon.o ../hqc-128/bin/build/reed_muller.o ../hqc-128/bin/build/gf.o ../hqc-128/bin/build/gf2x.o ../hqc-128/bin/build/vector.o ../hqc-128/bin/build/shake_ds.o ../hqc-128/bin/build/shake_prng.o ../hqc-128/bin/build/fips202.o -L../Mastik/src/ -lmastik


uint64_t rand_uint64_slow(void) {
  uint64_t r = 0;
  for (int i=0; i<64; i++) {
    r = r*2 + rand()%2;
  }
  return r;
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
    printf("%d\t",cnt);
    
    
}
void injecterror(uint64_t m[2],uint64_t v[VEC_N1N2_SIZE_64], uint64_t tmp_v[VEC_N1N2_SIZE_64], int index_start)
{   

	memcpy(tmp_v, v, 8*VEC_N1N2_SIZE_64);
	

	for(int i=index_start;i<index_start+15;i++)
	{
		uint64_t word[VEC_N1N2_SIZE_64]={0};
		for(int j=0;j<6;j++)
		{
			word[j]=tmp_v[i*6+j];
		}
		injectblock(word, 200);
		for(int j=0;j<6;j++)
		{
			tmp_v[i*6+j]= word[j];
		}
		//printf("%d is finished\n", tmp);
		
		
	}

		

}

int main(){
	srand(time(NULL));
	
	unsigned char pk[2249]={0}, sk[2289]={0}, ct[4481]={0}, ss[64]={0};
	uint64_t m[2] = {0};
	
	
	
	
	
	crypto_kem_keypair(pk, sk);
	
	FILE * f1;
  	f1 = fopen ("pk.txt","w");
  	
  	for(int i=0;i<2249;i++)
  	{
  		fprintf (f1, "%d\t",pk[i]);
  	}
  	fclose(f1);
  	
  	f1 = fopen ("sk.txt","w");
  	
  	for(int i=0;i<2289;i++)
  	{
  		fprintf (f1, "%d\t",sk[i]);
  	}
  	fclose(f1);

	int cnt=70, min=70;
	
	int cnt_basis=0;
	while(min>50)
	{
		cnt_basis++;
		int indictor[70]={0};
			uint8_t theta[64] = {0};
			uint64_t r1[VEC_N_SIZE_64] __attribute__ ((aligned (64))) = {0};
			uint32_t r2[PARAM_OMEGA_R] __attribute__ ((aligned (64))) = {0};
			uint64_t e[VEC_N_SIZE_64] __attribute__ ((aligned (64))) = {0};
		m[0]=rand_uint64_slow();
		m[1]=rand_uint64_slow();
		shake256incctx shake256state;
		
		// Computing m
		//vect_set_random_from_prng(m);

		// Computing theta
		shake256_512_ds(&shake256state, theta, (uint8_t*) m, VEC_K_SIZE_BYTES, G_FCT_DOMAIN);
		
		// Begin encrypting m
		seedexpander_state seedexpander;
		// Create seed_expander from theta
		seedexpander_init(&seedexpander, theta, SEED_BYTES);
		
		// Generate r1, r2 and e
		vect_set_random_fixed_weight(&seedexpander, r1, PARAM_OMEGA_R);
		vect_set_random_fixed_weight_by_coordinates(&seedexpander, r2, PARAM_OMEGA_R);
		vect_set_random_fixed_weight(&seedexpander, e, PARAM_OMEGA_E);
		
		int flag;
		
	 	cnt=0;
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
			
			if(flag==1)
			{
				cnt++;
				indictor[i]=1;
			}
			else
			{
				indictor[i]=0;
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
				cnt++;
				indictor[i+35]=1;
			}
			else
			{
				indictor[i+35]=0;
			}
		}
		if(min>cnt)
		{
			min=cnt;
		}
	}
	printf("%d\t",cnt_basis);
	
	f1 = fopen ("m.txt","w");
	for(int i=0;i<2;i++)
  	{
  		fprintf (f1, "%lu\n",m[i]);
  		//printf ("%lu\n",m[i]);
  	}
  	fclose(f1);
    
    
    uint64_t v[VEC_N1N2_SIZE_64]={0}, tmp_v[VEC_N1N2_SIZE_64]={0};
	uint64_t u[VEC_N_SIZE_64]={0};
	
	
	// Compute v = m.G by encoding the message
    code_encode(v, m);
    
    f1=fopen("ivc.txt","w");
	
	for(int i=0;i<VEC_N1N2_SIZE_64;i++)
	{
		fprintf(f1,"%lu\n",v[i]);
	}
	//printf("\n");
	fclose(f1);
	
	int index_nr=0, index[46]={0};
	injecterror(m,v, tmp_v, 0);
	
	f1=fopen("ec1.txt","w");
	
	for(int i=0;i<VEC_N1N2_SIZE_64;i++)
	{
		fprintf(f1,"%lu\n",tmp_v[i]);
	}
	//printf("\n");
	fclose(f1);
	
	for(int i=0;i<VEC_N1N2_SIZE_64;i++)
	{
		tmp_v[i]=0;
	}
	
	index_nr=0;
	injecterror(m,v, tmp_v, 15);
	printf("\n");
	f1=fopen("ec2.txt","w");
	
	for(int i=0;i<VEC_N1N2_SIZE_64;i++)
	{
		fprintf(f1,"%lu\n",tmp_v[i]);
	}
	//printf("\n");
	fclose(f1);
	
	return 0;
}
