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



#define test_number 50
#define N 11586  //2^13.5
 

#define N0 0xFF000000
#define N1 0x00FF0000
#define N2 0x0000FF00
#define N3 0x000000FF




__m128i generate_fast_random_128bit() {
	std::random_device rd; 
	std::mt19937_64 gen(rd());
	uint64_t lo = gen(), hi = gen();
	return _mm_set_epi64x(hi, lo);  // SSE4.1
}






void fill_uniform_unique(std::vector<uint16_t>& arr) {
	static_assert(N > 0 && N < 65536, "N must be in 1~65535");
	constexpr uint32_t MAX_U16 = 65535;

	static std::atomic<uint64_t> counter(0);
	uint64_t seed = []() {
		auto now = std::chrono::high_resolution_clock::now();
		auto time_seed = now.time_since_epoch().count();
		uint64_t dev_urandom_seed = []() {
			if (std::random_device().entropy() > 0) {
				return static_cast<uint64_t>(std::random_device{}());
			}
			return 0ULL;
		}();
		return time_seed ^ dev_urandom_seed ^ counter.fetch_add(1);
	}();

	std::mt19937_64 gen(seed);

	std::unordered_set<uint16_t> unique_set;
	unique_set.reserve(N);
	std::uniform_int_distribution<uint16_t> dist(1, MAX_U16);

	while (unique_set.size() < N) {
		unique_set.insert(dist(gen));
	}

	arr.assign(unique_set.begin(), unique_set.end());
	std::shuffle(arr.begin(), arr.end(), gen);
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

bool judge_zero(__m128i x, __m128i y, __m128i z, __m128i w)   //judge whether (x,y) and (z,w) are the same in the 0-th and 10-th bytes
{
	if ((is_equal(x, z) == 1 && is_equal(y, w) == 1) || (is_equal(x, w) == 1 && is_equal(y, z) == 1))
		return 0;
	__m128i mask;
	__m128i x1, y1, z1, w1;
	mask = _mm_set_epi32(0, 0x00ff0000, 0, 0x000000ff);   //nonzero in the 0-th and 10-th bytes
	x1 = _mm_and_si128(x, mask);
	y1 = _mm_and_si128(y, mask);
	z1 = _mm_and_si128(z, mask);
	w1 = _mm_and_si128(w, mask);

	if ((is_equal(x1, z1) == 1 && is_equal(y1, w1) == 1) || (is_equal(x1, w1) == 1 && is_equal(y1, z1) == 1))
	{
		return 1;
	}
	else
		return 0;
}


void encrypt(__m128i plain, __m128i key[6], __m128i* cipher)   //5-round encryption
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
	unsigned i, j0, j1;
	uint8_t w;
	unsigned long long repeat_pair;
	time_t starttime, endtime;
	__m128i plain, dif, cipher;
	__m128i plain1, plain2, plain3, plain4;
	__m128i invmask0, invmask1, invmask2, invmask3;
	__m128i inv0, inv1, inv2, inv3;
	__m128i key[6];

	uint32_t index0, index1, index2, index3;
	char con[test_number] = { 0 };
	uint8_t count = 0;
	std::vector<uint16_t> ZT;
	std::vector<uint16_t> FF;

	__m128i* Tab1, * Tab2, * Tab3, * Tab0;
	Tab0 = (__m128i*)malloc(sizeof(__m128i) * 32768); //2^10
	Tab1 = (__m128i*)malloc(sizeof(__m128i) * 32768); //2^10
	Tab2 = (__m128i*)malloc(sizeof(__m128i) * 32768); //2^10
	Tab3 = (__m128i*)malloc(sizeof(__m128i) * 32768); //2^10
	uint32_t m0, m1, m2, m3;
	uint32_t b, c;

	invmask0 = _mm_set_epi32(N2, N1, N0, N3);  //nonzero in the 0-th inverse diagonal
	invmask1 = _mm_set_epi32(N1, N0, N3, N2);  //nonzero in the 1-th inverse diagonal
	invmask2 = _mm_set_epi32(N0, N3, N2, N1);  //nonzero in the 2-th inverse diagonal
	invmask3 = _mm_set_epi32(N3, N2, N1, N0);  //nonzero in the 3-th inverse diagonal


	starttime = time(NULL);
	for (i = 0; i < test_number; i++)
	{

		for (w = 0; w < 6; w++)  
		{
			key[w] = generate_fast_random_128bit();
		}

		plain= generate_fast_random_128bit();  //choose a plaintext structure randomly


		fill_uniform_unique(FF);
		fill_uniform_unique(ZT);


		m0 = 0;
		m1 = 0;
		m2 = 0;
		m3 = 0;

		repeat_pair = 0;

		std::unordered_map<uint32_t, std::vector<__m128i>> Hash0;
		std::unordered_map<uint32_t, std::vector<__m128i>> Hash1;
		std::unordered_map<uint32_t, std::vector<__m128i>> Hash2;
		std::unordered_map<uint32_t, std::vector<__m128i>> Hash3;

		for (j1 = 0; j1 < N; j1++)
		{
			memcpy(&plain1, &plain, sizeof(__m128i));
			dif = _mm_set_epi16((FF[j1] & 0x00ff) << 8, 0, 0, 0, 0, FF[j1] & 0xff00, 0, 0);

			plain1 = _mm_xor_si128(plain1, dif);               //each element in A1


			for (j0 = 0; j0 < N; j0++)
			{
				memcpy(&plain2, &plain1, sizeof(__m128i));
				dif = _mm_set_epi16(0, 0, (ZT[j0] >> 8) & 0x00ff, 0, 0, 0, 0, ZT[j0] & 0x00ff);

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

				Hash0[index0].push_back(plain2);
				Hash1[index1].push_back(plain2);
				Hash2[index2].push_back(plain2);
				Hash3[index3].push_back(plain2);
			}

			for (const auto& kv : Hash0) {
				const std::vector<__m128i>& vec0 = kv.second;  

				if (vec0.size() >= 2) {
					for (size_t b = 0; b < vec0.size(); ++b) {
						for (size_t c = b + 1; c < vec0.size(); ++c) {
							if (is_equal(vec0[b], vec0[c]) == 1)
							{
								repeat_pair++;
							}
							else
							{
								Tab0[2 * m0] = vec0[b];
								Tab0[2 * m0+1] = vec0[c];
								m0++;
							}

						}
					}
				}
			}

			for (const auto& kv : Hash1) {
				const std::vector<__m128i>& vec1 = kv.second;  

				if (vec1.size() >= 2) {
					for (size_t b = 0; b < vec1.size(); ++b) {
						for (size_t c = b + 1; c < vec1.size(); ++c) {
							if (is_equal(vec1[b], vec1[c]) == 1)
							{
								repeat_pair++;
							}
							else
							{
								Tab1[2 * m1] = vec1[b];
								Tab1[2 * m1 + 1] = vec1[c];
								m1++;
							}

						}
					}
				}
			}

			for (const auto& kv : Hash2) {
				const std::vector<__m128i>& vec2 = kv.second;  

				if (vec2.size() >= 2) {
					for (size_t b = 0; b < vec2.size(); ++b) {
						for (size_t c = b + 1; c < vec2.size(); ++c) {
							if (is_equal(vec2[b], vec2[c]) == 1)
							{
								repeat_pair++;
							}
							else
							{
								Tab2[2 * m2] = vec2[b];
								Tab2[2 * m2 + 1] = vec2[c];
								m2++;
							}

						}
					}
				}
			}

			for (const auto& kv : Hash3) {
				const std::vector<__m128i>& vec3 = kv.second;  

				if (vec3.size() >= 2) {
					for (size_t b = 0; b < vec3.size(); ++b) {
						for (size_t c = b + 1; c < vec3.size(); ++c) {
							if (is_equal(vec3[b], vec3[c]) == 1)
							{
								repeat_pair++;
							}
							else
							{
								Tab3[2 * m3] = vec3[b];
								Tab3[2 * m3 + 1] = vec3[c];
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
		
		FF.clear();
		ZT.clear();

		for (b = 0; b < m0 - 1; b++)
		{
			for (c = b + 1; c < m0; c++)
			{
				plain1 = Tab0[2 * b];
				plain2 = Tab0[2 * b + 1];
				plain3 = Tab0[2 * c];
				plain4 = Tab0[2 * c + 1];

				if (judge_zero(plain1, plain2, plain3, plain4) == 1)
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
				plain1 = Tab1[2 * b];
				plain2 = Tab1[2 * b + 1];
				plain3 = Tab1[2 * c];
				plain4 = Tab1[2 * c + 1];

				if (judge_zero(plain1, plain2, plain3, plain4) == 1)
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
				plain1 = Tab2[2 * b];
				plain2 = Tab2[2 * b + 1];
				plain3 = Tab2[2 * c];
				plain4 = Tab2[2 * c + 1];


				if (judge_zero(plain1, plain2, plain3, plain4) == 1)
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
				plain1 = Tab3[2 * b];
				plain2 = Tab3[2 * b + 1];
				plain3 = Tab3[2 * c];
				plain4 = Tab3[2 * c + 1];
				if (judge_zero(plain1, plain2, plain3, plain4) == 1)
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
	}
	printf("there are %d experiments in total, where %d results is 5-round AES\n\n", test_number, count);
	endtime = time(NULL);
	printf("time=%f\n", difftime(endtime, starttime));

}





