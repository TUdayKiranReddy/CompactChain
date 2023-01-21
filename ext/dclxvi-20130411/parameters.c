/*
 * File:   dclxvi-20130411/parameters.c
 * Author: Ruben Niederhagen, Peter Schwabe
 * Public Domain
 */

#include "fpe.h"
#include "fp2e.h"
#include "fp6e.h"
#include "fp12e.h"
#include "curvepoint_fp.h"
#include "twistpoint_fp2.h"
#include "scalar.h"

#ifdef __cplusplus
#define EXTERN extern
#else
#define EXTERN
#endif

//EXTERN const scalar_t bn_6uplus2 =  {0x1EC817A18A131208ULL,2,0,0};
#define BN_6UPLUS2_NAFLEN 66
EXTERN const unsigned long bn_naflen_6uplus2 = BN_6UPLUS2_NAFLEN;
EXTERN const signed char bn_6uplus2_naf[BN_6UPLUS2_NAFLEN] = {0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, -1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, -1, 0, 1, 0, 0, 0, 1, 0, -1, 0, 0, 0, -1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, -1, 0, -1, 0, 0, 0, 0, 1, 0, 0, 0, 1};
//EXTERN const scalar_t bn_u =        {0x5BBC1015F02AC17DULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL};
EXTERN const scalar_t bn_n       = {0x1A2EF45B57AC7261ULL, 0x2E8D8E12F82B3924ULL, 0xAA6FECB86184DC21ULL, 0x8FB501E34AA387F9ULL};
EXTERN const scalar_t bn_pminus2 = {0x185CAC6C5E089665ULL, 0xEE5B88D120B5B59EULL, 0xAA6FECB86184DC21ULL, 0x8FB501E34AA387F9ULL};

//EXTERN const unsigned long bn_u_bitsize = 63;

EXTERN const double bn_v = 1868033.;
EXTERN const double bn_v6 = 11208198.;
const char * bn_pstr = "65000549695646603732796438742359905742825358107623003571877145026864184071783";
EXTERN const scalar_t bn_v_scalar = {1868033,0,0,0};

EXTERN const fpe_t bn_zeta       = {{{ -5604098, -934016, -934016, 2, 0, 0, -5604096, -934016, -934016, 1, 0, 0}}};  /* zeta   */
EXTERN const fpe_t bn_zeta2      = {{{ 5604097, 934016, 934016, -2, 0, 0, -5604102, -934016, -934016, 0, 0, 0}}};  /* zeta^2 */

EXTERN const curvepoint_fp_t bn_curvegen = {{{{{1.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.}}}, 
                                      {{{ -2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}},
                                      {{{1.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.}}},
                                      {{{0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.,0.}}}}};                                                       

EXTERN const twistpoint_fp2_t bn_twistgen = {{{{{490313, 4260028, -821156, -818020, 106592, -171108, 757738, 545601, 597403,
                       366066, -270886, -169528, 3101279, 2043941, -726481, 382478, -650880, -891316,
                       -13923, 327200, -110487, 473555, -7301, 608340}}},
                                              {{{-4628877, 3279202, 431044, 459682, -606446, -924615, -927454, 90760, 13692,
                                                                       -225706, -430013, -373196, 3004032, 4097571, 380900, 919715, -640623, -402833,
                                                                       -729700, -163786, -332478, -440873, 510935, 593941}}},
                                              {{{1.,0.,0.,0.,0.,0., 0.,0.,0.,0.,0.,0., 0.,0.,0.,0.,0.,0., 0.,0.,0.,0.,0.,0.}}},
                                              {{{0.,0.,0.,0.,0.,0., 0.,0.,0.,0.,0.,0., 0.,0.,0.,0.,0.,0., 0.,0.,0.,0.,0.,0.}}}}};

EXTERN const fp2e_t bn_z2p          = {{{-3981901, -4468327, 248857, -740622, 900229, -562222,
                         260246, -632491, -928317, -38527, 838674, 36774, -2702081, 3668149,
                                                -873042, 304894, 876721, 213663,
                                                                       562599, -128685, -325465, 518143, 457851, 750024 }}}; /* Z^(2p) */
EXTERN const fp2e_t bn_z3p          = {{{-1220868, -3662603, -18020, -54060, 771971, 447880,
                         -925219, -907622, 808438, 557280, -170086, -510257, -548011, -1644029,
                                                332930, -869243, -918612,
                                                                       -887802, -656367, -101068, 599384, -69882, -756823, -402435 }}}; /* Z^(3p) */

EXTERN const fp2e_t bn_ypminus1 = {{{-3981901, -4468327, 248857, -740622, 900229,
                         -562222, 260246, -632491, -928317, -38527, 838674, 36774, -2702081,
                                                3668149, -873042, 304894, 876721,
                                                                       213663, 562599, -128685, -325465, 518143, 457851, 750024 }}}; // Y^{p-1} lies in F_{p^2}
EXTERN const fp2e_t bn_zpminus1 = {{{-127312, 512442, -137362, 859841, -693124, 477483,
                         -456715, 571378, -391523, 771884, -684646, 729153, 4294836, 3621570,
                                                -839768, -538090, -213833,
                                                                       -814642, -240945, -172644, 308331, -116810, 574718, 249147 }}}; // Z^{p-1}, lies in F_{p^2}

EXTERN const fp2e_t bn_ypminus1_squ = {{{1555911, 5331252, -776828, 226463,
                         691213, -261413, -410662, -394138, -432410, -178831, -475754,
                                                92316, -5497403, -1697028, 207147, -413437,
                                                                       -291878, 77064, 214666, 415072, -853656, 644193, 622068, 571473 }}}; // (Y^{p-1})^2 i F_{p^2}

#undef EXTERN
