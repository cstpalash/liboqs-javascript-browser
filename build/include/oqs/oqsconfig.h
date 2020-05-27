// SPDX-License-Identifier: MIT

#define OQS_VERSION_TEXT "0.3.0-rc1"
#define OQS_COMPILE_BUILD_TARGET "x86-Linux-4.19.0-9-amd64"
#define OQS_PORTABLE_BUILD 1

#define OQS_KEM_DEFAULT OQS_KEM_alg_frodokem_640_aes
#define OQS_SIG_DEFAULT OQS_SIG_alg_dilithium_2

/* #undef OQS_USE_OPENSSL */
/* #undef OQS_USE_AES_OPENSSL */
/* #undef OQS_USE_SHA2_OPENSSL */
/* #undef OQS_USE_SHA3_OPENSSL */

/* #undef OQS_USE_PTHREADS_IN_TESTS */
/* #undef OQS_USE_CPU_EXTENSIONS */

/* #undef OQS_USE_AES_INSTRUCTIONS */
/* #undef OQS_USE_AVX_INSTRUCTIONS */
/* #undef OQS_USE_AVX2_INSTRUCTIONS */
/* #undef OQS_USE_AVX512_INSTRUCTIONS */
/* #undef OQS_USE_BMI_INSTRUCTIONS */
/* #undef OQS_USE_BMI2_INSTRUCTIONS */
/* #undef OQS_USE_POPCNT_INSTRUCTIONS */
/* #undef OQS_USE_SSE_INSTRUCTIONS */
/* #undef OQS_USE_SSE2_INSTRUCTIONS */
/* #undef OQS_USE_SSE3_INSTRUCTIONS */

#define OQS_ENABLE_KEM_BIKE 1
#define OQS_ENABLE_KEM_bike1_l1_cpa 1
#define OQS_ENABLE_KEM_bike1_l3_cpa 1
#define OQS_ENABLE_KEM_bike1_l1_fo 1
#define OQS_ENABLE_KEM_bike1_l3_fo 1

#define OQS_ENABLE_KEM_FRODOKEM 1
#define OQS_ENABLE_KEM_frodokem_640_aes 1
#define OQS_ENABLE_KEM_frodokem_640_shake 1
#define OQS_ENABLE_KEM_frodokem_976_aes 1
#define OQS_ENABLE_KEM_frodokem_976_shake 1
#define OQS_ENABLE_KEM_frodokem_1344_aes 1
#define OQS_ENABLE_KEM_frodokem_1344_shake 1

#define OQS_ENABLE_KEM_SIDH 1
#define OQS_ENABLE_KEM_sidh_p434 1
#define OQS_ENABLE_KEM_sidh_p434_compressed 1
#define OQS_ENABLE_KEM_sidh_p503 1
#define OQS_ENABLE_KEM_sidh_p503_compressed 1
#define OQS_ENABLE_KEM_sidh_p610 1
#define OQS_ENABLE_KEM_sidh_p610_compressed 1
#define OQS_ENABLE_KEM_sidh_p751 1
#define OQS_ENABLE_KEM_sidh_p751_compressed 1

#define OQS_ENABLE_KEM_SIKE 1
#define OQS_ENABLE_KEM_sike_p434 1
#define OQS_ENABLE_KEM_sike_p434_compressed 1
#define OQS_ENABLE_KEM_sike_p503 1
#define OQS_ENABLE_KEM_sike_p503_compressed 1
#define OQS_ENABLE_KEM_sike_p610 1
#define OQS_ENABLE_KEM_sike_p610_compressed 1
#define OQS_ENABLE_KEM_sike_p751 1
#define OQS_ENABLE_KEM_sike_p751_compressed 1

#define OQS_ENABLE_SIG_PICNIC 1
#define OQS_ENABLE_SIG_picnic_L1_UR 1
#define OQS_ENABLE_SIG_picnic_L1_FS 1
#define OQS_ENABLE_SIG_picnic_L3_UR 1
#define OQS_ENABLE_SIG_picnic_L3_FS 1
#define OQS_ENABLE_SIG_picnic_L5_UR 1
#define OQS_ENABLE_SIG_picnic_L5_FS 1
#define OQS_ENABLE_SIG_picnic2_L1_FS 1
#define OQS_ENABLE_SIG_picnic2_L3_FS 1
#define OQS_ENABLE_SIG_picnic2_L5_FS 1

#define OQS_ENABLE_SIG_QTESLA 1
#define OQS_ENABLE_SIG_qTesla_p_I 1
#define OQS_ENABLE_SIG_qTesla_p_III 1

///// OQS_COPY_FROM_PQCLEAN_FRAGMENT_ADD_ALG_ENABLE_DEFINES_START

#define OQS_ENABLE_KEM_CLASSIC_MCELIECE 1
#define OQS_ENABLE_KEM_classic_mceliece_348864 1
#define OQS_ENABLE_KEM_classic_mceliece_348864f 1
#define OQS_ENABLE_KEM_classic_mceliece_460896 1
#define OQS_ENABLE_KEM_classic_mceliece_460896f 1
#define OQS_ENABLE_KEM_classic_mceliece_6688128 1
#define OQS_ENABLE_KEM_classic_mceliece_6688128f 1
#define OQS_ENABLE_KEM_classic_mceliece_6960119 1
#define OQS_ENABLE_KEM_classic_mceliece_6960119f 1
#define OQS_ENABLE_KEM_classic_mceliece_8192128 1
#define OQS_ENABLE_KEM_classic_mceliece_8192128f 1

#define OQS_ENABLE_KEM_KYBER 1
#define OQS_ENABLE_KEM_kyber_512 1
/* #undef OQS_ENABLE_KEM_kyber_512_avx2 */
#define OQS_ENABLE_KEM_kyber_768 1
/* #undef OQS_ENABLE_KEM_kyber_768_avx2 */
#define OQS_ENABLE_KEM_kyber_1024 1
/* #undef OQS_ENABLE_KEM_kyber_1024_avx2 */
#define OQS_ENABLE_KEM_kyber_512_90s 1
/* #undef OQS_ENABLE_KEM_kyber_512_90s_avx2 */
#define OQS_ENABLE_KEM_kyber_768_90s 1
/* #undef OQS_ENABLE_KEM_kyber_768_90s_avx2 */
#define OQS_ENABLE_KEM_kyber_1024_90s 1
/* #undef OQS_ENABLE_KEM_kyber_1024_90s_avx2 */

#define OQS_ENABLE_KEM_LEDACRYPT 1
#define OQS_ENABLE_KEM_ledacrypt_ledakemlt12 1
#define OQS_ENABLE_KEM_ledacrypt_ledakemlt32 1
#define OQS_ENABLE_KEM_ledacrypt_ledakemlt52 1

#define OQS_ENABLE_KEM_NEWHOPE 1
#define OQS_ENABLE_KEM_newhope_512cca 1
#define OQS_ENABLE_KEM_newhope_1024cca 1

#define OQS_ENABLE_KEM_NTRU 1
#define OQS_ENABLE_KEM_ntru_hps2048509 1
#define OQS_ENABLE_KEM_ntru_hps2048677 1
#define OQS_ENABLE_KEM_ntru_hps4096821 1
#define OQS_ENABLE_KEM_ntru_hrss701 1

#define OQS_ENABLE_KEM_SABER 1
#define OQS_ENABLE_KEM_saber_lightsaber 1
#define OQS_ENABLE_KEM_saber_saber 1
#define OQS_ENABLE_KEM_saber_firesaber 1

#define OQS_ENABLE_KEM_THREEBEARS 1
#define OQS_ENABLE_KEM_threebears_babybear 1
#define OQS_ENABLE_KEM_threebears_babybear_ephem 1
#define OQS_ENABLE_KEM_threebears_mamabear 1
#define OQS_ENABLE_KEM_threebears_mamabear_ephem 1
#define OQS_ENABLE_KEM_threebears_papabear 1
#define OQS_ENABLE_KEM_threebears_papabear_ephem 1

#define OQS_ENABLE_SIG_DILITHIUM 1
#define OQS_ENABLE_SIG_dilithium_2 1
/* #undef OQS_ENABLE_SIG_dilithium_2_avx2 */
#define OQS_ENABLE_SIG_dilithium_3 1
/* #undef OQS_ENABLE_SIG_dilithium_3_avx2 */
#define OQS_ENABLE_SIG_dilithium_4 1
/* #undef OQS_ENABLE_SIG_dilithium_4_avx2 */

#define OQS_ENABLE_SIG_FALCON 1
#define OQS_ENABLE_SIG_falcon_512 1
#define OQS_ENABLE_SIG_falcon_1024 1

#define OQS_ENABLE_SIG_MQDSS 1
#define OQS_ENABLE_SIG_mqdss_31_48 1
#define OQS_ENABLE_SIG_mqdss_31_64 1

#define OQS_ENABLE_SIG_RAINBOW 1
#define OQS_ENABLE_SIG_rainbow_Ia_classic 1
#define OQS_ENABLE_SIG_rainbow_Ia_cyclic 1
#define OQS_ENABLE_SIG_rainbow_Ia_cyclic_compressed 1
#define OQS_ENABLE_SIG_rainbow_IIIc_classic 1
#define OQS_ENABLE_SIG_rainbow_IIIc_cyclic 1
#define OQS_ENABLE_SIG_rainbow_IIIc_cyclic_compressed 1
#define OQS_ENABLE_SIG_rainbow_Vc_classic 1
#define OQS_ENABLE_SIG_rainbow_Vc_cyclic 1
#define OQS_ENABLE_SIG_rainbow_Vc_cyclic_compressed 1

#define OQS_ENABLE_SIG_SPHINCS 1
#define OQS_ENABLE_SIG_sphincs_haraka_128f_robust 1
/* #undef OQS_ENABLE_SIG_sphincs_haraka_128f_robust_aesni */
#define OQS_ENABLE_SIG_sphincs_haraka_128f_simple 1
/* #undef OQS_ENABLE_SIG_sphincs_haraka_128f_simple_aesni */
#define OQS_ENABLE_SIG_sphincs_haraka_128s_robust 1
/* #undef OQS_ENABLE_SIG_sphincs_haraka_128s_robust_aesni */
#define OQS_ENABLE_SIG_sphincs_haraka_128s_simple 1
/* #undef OQS_ENABLE_SIG_sphincs_haraka_128s_simple_aesni */
#define OQS_ENABLE_SIG_sphincs_haraka_192f_robust 1
/* #undef OQS_ENABLE_SIG_sphincs_haraka_192f_robust_aesni */
#define OQS_ENABLE_SIG_sphincs_haraka_192f_simple 1
/* #undef OQS_ENABLE_SIG_sphincs_haraka_192f_simple_aesni */
#define OQS_ENABLE_SIG_sphincs_haraka_192s_robust 1
/* #undef OQS_ENABLE_SIG_sphincs_haraka_192s_robust_aesni */
#define OQS_ENABLE_SIG_sphincs_haraka_192s_simple 1
/* #undef OQS_ENABLE_SIG_sphincs_haraka_192s_simple_aesni */
#define OQS_ENABLE_SIG_sphincs_haraka_256f_robust 1
/* #undef OQS_ENABLE_SIG_sphincs_haraka_256f_robust_aesni */
#define OQS_ENABLE_SIG_sphincs_haraka_256f_simple 1
/* #undef OQS_ENABLE_SIG_sphincs_haraka_256f_simple_aesni */
#define OQS_ENABLE_SIG_sphincs_haraka_256s_robust 1
/* #undef OQS_ENABLE_SIG_sphincs_haraka_256s_robust_aesni */
#define OQS_ENABLE_SIG_sphincs_haraka_256s_simple 1
/* #undef OQS_ENABLE_SIG_sphincs_haraka_256s_simple_aesni */
#define OQS_ENABLE_SIG_sphincs_sha256_128f_robust 1
/* #undef OQS_ENABLE_SIG_sphincs_sha256_128f_robust_avx2 */
#define OQS_ENABLE_SIG_sphincs_sha256_128f_simple 1
/* #undef OQS_ENABLE_SIG_sphincs_sha256_128f_simple_avx2 */
#define OQS_ENABLE_SIG_sphincs_sha256_128s_robust 1
/* #undef OQS_ENABLE_SIG_sphincs_sha256_128s_robust_avx2 */
#define OQS_ENABLE_SIG_sphincs_sha256_128s_simple 1
/* #undef OQS_ENABLE_SIG_sphincs_sha256_128s_simple_avx2 */
#define OQS_ENABLE_SIG_sphincs_sha256_192f_robust 1
/* #undef OQS_ENABLE_SIG_sphincs_sha256_192f_robust_avx2 */
#define OQS_ENABLE_SIG_sphincs_sha256_192f_simple 1
/* #undef OQS_ENABLE_SIG_sphincs_sha256_192f_simple_avx2 */
#define OQS_ENABLE_SIG_sphincs_sha256_192s_robust 1
/* #undef OQS_ENABLE_SIG_sphincs_sha256_192s_robust_avx2 */
#define OQS_ENABLE_SIG_sphincs_sha256_192s_simple 1
/* #undef OQS_ENABLE_SIG_sphincs_sha256_192s_simple_avx2 */
#define OQS_ENABLE_SIG_sphincs_sha256_256f_robust 1
/* #undef OQS_ENABLE_SIG_sphincs_sha256_256f_robust_avx2 */
#define OQS_ENABLE_SIG_sphincs_sha256_256f_simple 1
/* #undef OQS_ENABLE_SIG_sphincs_sha256_256f_simple_avx2 */
#define OQS_ENABLE_SIG_sphincs_sha256_256s_robust 1
/* #undef OQS_ENABLE_SIG_sphincs_sha256_256s_robust_avx2 */
#define OQS_ENABLE_SIG_sphincs_sha256_256s_simple 1
/* #undef OQS_ENABLE_SIG_sphincs_sha256_256s_simple_avx2 */
#define OQS_ENABLE_SIG_sphincs_shake256_128f_robust 1
/* #undef OQS_ENABLE_SIG_sphincs_shake256_128f_robust_avx2 */
#define OQS_ENABLE_SIG_sphincs_shake256_128f_simple 1
/* #undef OQS_ENABLE_SIG_sphincs_shake256_128f_simple_avx2 */
#define OQS_ENABLE_SIG_sphincs_shake256_128s_robust 1
/* #undef OQS_ENABLE_SIG_sphincs_shake256_128s_robust_avx2 */
#define OQS_ENABLE_SIG_sphincs_shake256_128s_simple 1
/* #undef OQS_ENABLE_SIG_sphincs_shake256_128s_simple_avx2 */
#define OQS_ENABLE_SIG_sphincs_shake256_192f_robust 1
/* #undef OQS_ENABLE_SIG_sphincs_shake256_192f_robust_avx2 */
#define OQS_ENABLE_SIG_sphincs_shake256_192f_simple 1
/* #undef OQS_ENABLE_SIG_sphincs_shake256_192f_simple_avx2 */
#define OQS_ENABLE_SIG_sphincs_shake256_192s_robust 1
/* #undef OQS_ENABLE_SIG_sphincs_shake256_192s_robust_avx2 */
#define OQS_ENABLE_SIG_sphincs_shake256_192s_simple 1
/* #undef OQS_ENABLE_SIG_sphincs_shake256_192s_simple_avx2 */
#define OQS_ENABLE_SIG_sphincs_shake256_256f_robust 1
/* #undef OQS_ENABLE_SIG_sphincs_shake256_256f_robust_avx2 */
#define OQS_ENABLE_SIG_sphincs_shake256_256f_simple 1
/* #undef OQS_ENABLE_SIG_sphincs_shake256_256f_simple_avx2 */
#define OQS_ENABLE_SIG_sphincs_shake256_256s_robust 1
/* #undef OQS_ENABLE_SIG_sphincs_shake256_256s_robust_avx2 */
#define OQS_ENABLE_SIG_sphincs_shake256_256s_simple 1
/* #undef OQS_ENABLE_SIG_sphincs_shake256_256s_simple_avx2 */
///// OQS_COPY_FROM_PQCLEAN_FRAGMENT_ADD_ALG_ENABLE_DEFINES_END
