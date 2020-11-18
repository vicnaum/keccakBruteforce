/* -------------------------------------------------------------------------
 * Works when compiled for either 32-bit or 64-bit targets, optimized for 
 * 64 bit.
 *
 * Canonical implementation of Init/Update/Finalize for SHA-3 byte input. 
 *
 * SHA3-256, SHA3-384, SHA-512 are implemented. SHA-224 can easily be added.
 *
 * Based on code from http://keccak.noekeon.org/ .
 *
 * I place the code that I wrote into public domain, free to use. 
 *
 * I would appreciate if you give credits to this work if you used it to 
 * write or test * your code.
 *
 * Aug 2015. Andrey Jivsov. crypto@brainhub.org
 * ---------------------------------------------------------------------- */

/* *************************** Self Tests ************************ */

/* 
 * There are two set of mutually exclusive tests, based on SHA3_USE_KECCAK,
 * which is undefined in the production version.
 *
 * Known answer tests are from NIST SHA3 test vectors at
 * http://csrc.nist.gov/groups/ST/toolkit/examples.html
 *
 * SHA3-256:
 *   http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA3-256_Msg0.pdf
 *   http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA3-256_1600.pdf
 * SHA3-384: 
 *   http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA3-384_1600.pdf 
 * SHA3-512: 
 *   http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA3-512_1600.pdf 
 *
 * These are refered to as [FIPS 202] tests.
 *
 * -----
 *
 * A few Keccak algorithm tests (when M and not M||01 is hashed) are
 * added here. These are from http://keccak.noekeon.org/KeccakKAT-3.zip,
 * ShortMsgKAT_256.txt for sizes even to 8. There is also one test for 
 * ExtremelyLongMsgKAT_256.txt.
 *
 * These will work with this code when SHA3_USE_KECCAK converts Finalize
 * to use "pure" Keccak algorithm.
 *
 *
 * These are referred to as [Keccak] test.
 *
 * -----
 *
 * In one case the input from [Keccak] test was used to test SHA3
 * implementation. In this case the calculated hash was compared with
 * the output of the sha3sum on Fedora Core 20 (which is Perl's based).
 *
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>

#include "sha3.h"

int bench(int num) {
  uint8_t buf[32];
  uint8_t str[5];

  clock_t begin = clock();
  for (int i=0; i<num; i++) {
    str[0] = i;
    sha3_HashBuffer(256, SHA3_FLAGS_KECCAK, str, 5, buf, sizeof(buf));
    sha3_HashBuffer(256, SHA3_FLAGS_KECCAK, buf, 32, buf, sizeof(buf));
  }
  clock_t finish = clock();

  double time_spent = (double)(finish - begin) / CLOCKS_PER_SEC;

  int speed = (double) num / time_spent;

  printf("Bench: %i hashes per second\n", speed);
  return speed;
}

int brute(int start, int stop, int num) {
  uint8_t buf[32];

  printf("Bruteforcing for %i characters\n", num);


  /* ---- "pure" Keccak algorithm begins; from [Keccak] ----- */
  uint8_t str[num];

  str[0] = start;
  str[1] = 32;
  str[2] = 32;
  str[3] = 32;
  str[4] = 32;

  printf("Starting from (");
  for (int i = 0; i<num; i++)
  {
    printf("%c", str[i]);
  }
  printf(")\n");

  for (int i = start; i<stop; i++) {
    for (int j = 32; j<127; j++) {
      for (int k = 32; k<127; k++) {
        for (int l = 32; l<127; l++) {
         for (int m = 32; m<127; m++) {
            str[0] = i;
            str[1] = j;
            str[2] = k;
            str[3] = l;
            str[4] = m;
            sha3_HashBuffer(256, SHA3_FLAGS_KECCAK, str, num, buf, sizeof(buf));
            sha3_HashBuffer(256, SHA3_FLAGS_KECCAK, buf, 32, buf, sizeof(buf));


            if(memcmp(buf, "\x57\x46\xfe\x8a\xe2\xbf\x9f\xb2"
                          "\x4b\xcd\xf4\x97\x2e\xa7\x8c\x02"
                          "\x11\x21\x1e\x23\xc3\x76\x46\x19"
                          "\x56\xd4\x6d\x8d\x8a\x65\x19\xba", 256 / 8) == 0) {
                printf("Found! (");

                for (int i = 0; i<num; i++)
                {
                  printf("%c", str[i]);
                }
                printf(")\n");

                for (int i = 0; i<32; i++)
                {
                  printf("%02x", buf[i]);
                }
                printf("\n");

                return 10;
            }
          }
        }
      }
    }
  }
  printf("Nothing found... Ended at (");
  for (int i = 0; i<num; i++)
  {
    printf("%c", str[i]);
  }
  printf(")\n");

  return 0;
}

static void help() {
    printf("To call: #Threads #Thread\n(ex: sha3run 8 2 - means 8 threads total and run 2 thread)\n");
}

int main(int argc, char *argv[])
{
  if( argc != 3) {
    help();
    return 1;
  }

  int speed = bench(1000000);

  int threads = atoi(argv[1]);
  int thread = atoi(argv[2]);

  int num = 5;

  printf("Running thread %i of %i\n", thread, threads);

  int threadSize = (127-32) / threads;
  printf("ThreadSize: %i\n", threadSize);
  int start = 32 + (thread-1) * threadSize;
  printf("Start: %i\n", start);
  int end;

  if (thread == threads) {
    end = 127;
  } else {
    end = start + threadSize;
  }
  printf("End: %i\n", end);

  printf("Number of hashes to check: %f\n", threadSize*pow(95,num-1));

  printf("Estimated time to complete: %f minutes\n", (double) threadSize * pow(95,num-1) / 60 / (double) speed);

  clock_t begin = clock();
  brute(start, end, num);
  clock_t finish = clock();

  double time_spent = (double)(finish - begin) / CLOCKS_PER_SEC;
  printf("Elapsed: %f seconds\n", time_spent);

  return 0;
}