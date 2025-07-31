#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<immintrin.h>
#include<stdint.h>
#include<time.h>
#include<emmintrin.h>
#include<math.h>
#include <iostream>
#include <random>
#include <vector>
#include <cstdint>
#include <algorithm>
#include <chrono>
#include <atomic>
#include <unordered_map>
#include <xmmintrin.h> 
#include <unordered_set>
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")


#define test_number 50
#define N ((unsigned)(pow(2, 13.51) + 0.5))  //2^13.51
 

#define N0 0xFF000000
#define N1 0x00FF0000
#define N2 0x0000FF00
#define N3 0x000000FF


#define MAX_NUM 65535
unsigned long long repeat_pair;
const size_t SEQUENCE_LEN = static_cast<size_t>(std::sqrt(N));  

void generateSequence(std::vector<uint8_t>& output) {
	output.resize(SEQUENCE_LEN);  

	unsigned seed = static_cast<unsigned>(
		std::chrono::system_clock::now().time_since_epoch().count()
		);
	std::mt19937 engine(seed);  

	std::vector<uint8_t> pool(255);
	for (uint8_t i = 0; i < 255; ++i) {
		pool[i] = i + 1;  
	}

	for (size_t i = 0; i < SEQUENCE_LEN; ++i) {
		std::uniform_int_distribution<size_t> dist(i, 254);
		size_t j = dist(engine);
		std::swap(pool[i], pool[j]);
		output[i] = pool[i];
	}
}





void pp(__m128i* x)
{
	char a[16];
	memcpy(a, x, 16);
	unsigned t;
	for (t = 0; t < 16; t++)
	{
		printf("%02x", a[t] & 0xff);
		if (t == 3 || t == 7 || t == 11)
			printf(", ");
	}
	printf("\n");
}

bool is_equal(__m128i a, __m128i b) {
	__m128i neq = _mm_xor_si128(a, b);       
	return _mm_test_all_zeros(neq, neq);    
}


void encrypt(__m128i plain, __m128i key[6], __m128i* cipher)   
{
	unsigned k;
	__m128i plain0;
	memcpy(&plain0, &plain, sizeof(__m128i));
	plain0 = _mm_xor_si128(plain0, key[0]);

	for (k = 1; k < 5; k++)
	{
		*cipher = _mm_aesenc_si128(plain0, key[k]);
		memcpy(&plain0, cipher, sizeof(__m128i));
	}
	*cipher = _mm_aesenclast_si128(plain0, key[5]);
}








int main()
{
	unsigned i, j0, j1,j2,j3;
	uint8_t w;

	time_t starttime, endtime;
	__m128i plain, dif, cipher;
	__m128i plain1, plain2, plain3;
	__m128i invmask0, invmask1, invmask2, invmask3;
	__m128i inv0, inv1, inv2, inv3;
	__m128i key[6];

	uint32_t index0, index1, index2, index3;
	char con[test_number] = { 0 };
	uint8_t count = 0;
	std::vector<uint8_t> zero,five,ten,fifteen;

	uint32_t* Tab1, * Tab2, * Tab3, * Tab0;
	Tab0 = (uint32_t*)malloc(sizeof(uint32_t) * 32768); //2^10
	Tab1 = (uint32_t*)malloc(sizeof(uint32_t) * 32768); //2^10
	Tab2 = (uint32_t*)malloc(sizeof(uint32_t) * 32768); //2^10
	Tab3 = (uint32_t*)malloc(sizeof(uint32_t) * 32768); //2^10
	uint32_t m0, m1, m2, m3;
	uint32_t b, c;

	invmask0 = _mm_set_epi32(N2, N1, N0, N3);  //nonzero in the 0-th inverse diagonal
	invmask1 = _mm_set_epi32(N1, N0, N3, N2); //nonzero in the 1-th inverse diagonal
	invmask2 = _mm_set_epi32(N0, N3, N2, N1); //nonzero in the 2-th inverse diagonal
	invmask3 = _mm_set_epi32(N3, N2, N1, N0); //nonzero in the 3-th inverse diagonal

	std::unordered_map<uint32_t, std::vector<uint16_t>> Hash0;
	std::unordered_map<uint32_t, std::vector<uint16_t>> Hash1;
	std::unordered_map<uint32_t, std::vector<uint16_t>> Hash2;
	std::unordered_map<uint32_t, std::vector<uint16_t>> Hash3;

	for (w = 0; w < 6; w++)   //round keys
	{
		if (BCryptGenRandom(
			NULL,
			(PUCHAR)&key[w],
			sizeof(key[w]),
			BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
			fprintf(stderr, "BCryptGenRandom failed\n");
			return 1;
		}
	}

	starttime = time(NULL);
	for (i = 0; i < test_number; i++)
	{
		if (BCryptGenRandom(
			NULL,
			(PUCHAR)&plain,
			sizeof(plain),
			BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
			fprintf(stderr, "BCryptGenRandom failed\n");
			return 1;
		}  //choose a plaintext structure randomly


		generateSequence(zero);
		generateSequence(five);
		generateSequence(ten);
		generateSequence(fifteen);

		m0 = 0;
		m1 = 0;
		m2 = 0;
		m3 = 0;

		//repeat_pair = 0;
		for (j0 = 0; j0 < SEQUENCE_LEN; j0++)    //fix byte five
		{
			for (j1 = 0; j1 < SEQUENCE_LEN; j1++)   //fix byte fifteen
			{
				memcpy(&plain1, &plain, sizeof(__m128i));
				dif = _mm_set_epi8(fifteen[j1], 0, 0, 0, 0, 0, 0, 0, 0, 0, five[j0], 0, 0, 0, 0, 0);
				plain1 = _mm_xor_si128(plain1, dif);               


				for (j2 = 0; j2 < SEQUENCE_LEN; j2++)   //byte 0
				{
					for (j3 = 0; j3 < SEQUENCE_LEN; j3++)   //byte 10
					{
						memcpy(&plain2, &plain1, sizeof(__m128i));
						dif = _mm_set_epi8(0, 0, 0, 0, 0, ten[j3], 0, 0, 0, 0, 0, 0, 0, 0, 0, zero[j2]);
						plain2 = _mm_xor_si128(plain2, dif);
						memcpy(&plain3, &plain2, sizeof(__m128i));

						encrypt(plain3, key, &cipher);
						inv0 = _mm_and_si128(cipher, invmask0);
						inv1 = _mm_and_si128(cipher, invmask1);
						inv2 = _mm_and_si128(cipher, invmask2);
						inv3 = _mm_and_si128(cipher, invmask3);

						index0 = (unsigned)(_mm_extract_epi32(inv0, 0) ^ _mm_extract_epi32(inv0, 1) ^ _mm_extract_epi32(inv0, 2) ^ _mm_extract_epi32(inv0, 3));
						index1 = (unsigned)(_mm_extract_epi32(inv1, 0) ^ _mm_extract_epi32(inv1, 1) ^ _mm_extract_epi32(inv1, 2) ^ _mm_extract_epi32(inv1, 3));
						index2 = (unsigned)(_mm_extract_epi32(inv2, 0) ^ _mm_extract_epi32(inv2, 1) ^ _mm_extract_epi32(inv2, 2) ^ _mm_extract_epi32(inv2, 3));
						index3 = (unsigned)(_mm_extract_epi32(inv3, 0) ^ _mm_extract_epi32(inv3, 1) ^ _mm_extract_epi32(inv3, 2) ^ _mm_extract_epi32(inv3, 3));

						Hash0[index0].push_back((j2 << 8) ^ j3);
						Hash1[index1].push_back((j2 << 8) ^ j3);
						Hash2[index2].push_back((j2 << 8) ^ j3);
						Hash3[index3].push_back((j2 << 8) ^ j3);
					}
				}

				for (const auto& kv : Hash0) {
					const std::vector<uint16_t>& vec0 = kv.second;

					if (vec0.size() >= 2) {
						for (b = 0; b < vec0.size() - 1; b++) {
							for (c = b + 1; c < vec0.size(); c++) {
								{
									Tab0[m0] = (vec0[b] << 16) ^ vec0[c];
									m0++;

								}
							}
						}
					}
				}


				for (const auto& kv : Hash1) {
					const std::vector<uint16_t>& vec1 = kv.second;

					if (vec1.size() >= 2) {
						for (b = 0; b < vec1.size() - 1; b++) {
							for (c = b + 1; c < vec1.size(); c++) {
								{
									Tab1[m1] = (vec1[b] << 16) ^ vec1[c];
									m1++;

								}
							}
						}
					}
				}


				for (const auto& kv : Hash2) {
					const std::vector<uint16_t>& vec2 = kv.second;

					if (vec2.size() >= 2) {
						for (b = 0; b < vec2.size() - 1; b++) {
							for (c = b + 1; c < vec2.size(); c++) {
								{
									Tab2[m2] = (vec2[b] << 16) ^ vec2[c];
									m2++;

								}
							}
						}
					}
				}

				for (const auto& kv : Hash3) {
					const std::vector<uint16_t>& vec3 = kv.second;

					if (vec3.size() >= 2) {
						for (b = 0; b < vec3.size() - 1; b++) {
							for (c = b + 1; c < vec3.size(); c++) {
								{
									Tab3[m3] = (vec3[b] << 16) ^ vec3[c];
									m3++;

								}
							}
						}
					}
				}

				for (auto& kv : Hash0) {
					kv.second.clear();  
				}
				Hash0.clear();          
				for (auto& kv : Hash1) {
					kv.second.clear();  
				}
				Hash1.clear();          
				for (auto& kv : Hash2) {
					kv.second.clear();  
				}
				Hash2.clear();         
				for (auto& kv : Hash3) {
					kv.second.clear(); 
				}
				Hash3.clear();        

			}
		}
		
		

		for (b = 0; b < m0 - 1; b++)
		{
			for (c = b + 1; c < m0; c++)
			{
				if(Tab0[b]== Tab0[c])
				{
					con[i] = 1;
					break;
				}
			}
			if (con[i] >0)
				break;
		}



		for (b = 0; b < m1 - 1; b++)
		{
			for (c = b + 1; c < m1; c++)
			{
				if (Tab1[b] == Tab1[c])
				{
					con[i] = 1;
					break;
				}
			}
			if (con[i] > 0)
				break;
		}
		


		for (b = 0; b < m2 - 1; b++)
		{
			for (c = b + 1; c < m2; c++)
			{
				if (Tab2[b] == Tab2[c])
				{
					con[i] = 1;
					break;
				}
			}
			if (con[i] > 0)
				break;
		}

		for (b = 0; b < m3 - 1; b++)
		{
			for (c = b + 1; c < m3; c++)
			{
				if (Tab3[b] == Tab3[c])
				{
					con[i] = 1;
					break;
				}
			}
			if (con[i] > 0)
				break;
		}


		if (con[i] > 0)
		{
			count++;
		}
		//printf("i=%d,repeat pairs=%d\n", i,repeat_pair);
	}
	printf("there are %d experiments in total, where %d results is 5-round AES\n\n", test_number, count);
	endtime = time(NULL);
	printf("time=%f\n", difftime(endtime, starttime));
	return count;

}





