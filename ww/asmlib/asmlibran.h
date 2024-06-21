/*****************************   randoma.h   **********************************
* Author:        Agner Fog
* Date created:  1997
* Last modified: 2013-09-20
* Project:       randoma
* Source URL:    www.agner.org/random
*
* Description:
* This header file contains function prototypes and class declarations for
* the randoma library of uniform random number generators optimized in 
* assembly language.
*
* The following random number generators are available:
* Mersenne Twister, Mother-Of-All generator and SFMT generator.
*
* This library is available in many versions for different platforms,
* see ran-instructions.pdf for details.
*
* Copyright 1997-2013 by Agner Fog. 
* GNU General Public License http://www.gnu.org/licenses/gpl.html
*******************************************************************************


Description of random number generator functions:
=================================================

Single-threaded versions:
-------------------------
void MersenneRandomInit(int seed);
void MotherRandomInit(int seed);
void SFMTgenRandomInit(int seed, int IncludeMother);
This function must be called before any random number is generated.
Different values for seed will generate different random number sequences.
SFMTgenRandomInit will make a combination of the SFMT generator and the
Mother-Of-All generator if IncludeMother = 1 or an SFMT generator alone if
IncludeMother = 0.

void MersenneRandomInitByArray(int const seeds[], int NumSeeds);
void SFMTgenRandomInitByArray (int const seeds[], int NumSeeds, int IncludeMother);
Alternative to MersenneRandomInit when the seed consists of more than one integer.

int MersenneIRandom (int min, int max);
int MotherIRandom   (int min, int max);
int SFMTgenIRandom  (int min, int max);
Generates a random integer in the interval from min to max, inclusive.

int MersenneIRandomX(int min, int max);
int SFMTgenIRandomX (int min, int max);
Same as above. All possible output values have exactly the same probability
in the IRandomX versions, whereas the IRandom versions may have a slight 
bias when the interval length is very high and not a power of 2.

double MersenneRandom();
double MotherRandom();
double SFMTgenRandom();
long double SFMTgenRandomL();
Generates a random number x in the interval 0 <= x < 1 with uniform distribution.
The resolution is 2^(-32) for MersenneRandom() and MotherRandom(), 
2^(-52) for SFMTgenRandom() and 2^(-63) for SFMTgenRandomL().
(SFMTgenRandomL() requires that the compiler supports long double precision).

uint32_t MersenneBRandom();
uint32_t MotherBRandom();
uint32_t SFMTgenBRandom();
Generates a random 32-bit number. All 32 bits are random.


DLL versions:
-------------
These functions use the __stdcall calling convention rather than __cdecl.
They are intended for use with randomad32.dll or randomad64.dll for 
programming languages that do not support static linking. The function 
names are the same as above with a D appended to the name.


Thread-safe versions:
---------------------
These functions are wrapped in the classes CRandomMersenneA, CRandomMotherA
and CRandomSFMTA. Use these for multi-threaded applications or when an 
object-oriented design is desired. There is no performance penalty for 
using these classes. Each thread should have its own instance of the 
random number generator class to prevent interaction between the threads.
Make sure each instance has a different seed.

*******************************************************************************/

#ifndef ASMLIBRAN_H
#define ASMLIBRAN_H

#include "asmlib.h"

/***********************************************************************
System-specific definitions
***********************************************************************/

// Define macro for extern "C" __stdcall call for dynamic linking:
#if defined(_WIN32) && !defined(_WIN64)
   // __stdcall used only in 32-bit Windows
   #define DLL_STDCALL  __stdcall
#else
   // 64-bit Windows has only one calling convention.
   // 32 and 64 bit Unix does not use __stdcall for dynamic linking
   #define DLL_STDCALL
#endif


/***********************************************************************
Define size of state vector
***********************************************************************/

// Must match the value used in the library source (randomah.asi)
#define SFMT_N_A 88

#define MERS_N_A 624

// Turn off name mangling
#ifdef __cplusplus
   extern "C" {
#endif

/***********************************************************************
Function prototypes for random number generators
***********************************************************************/

/***********************************************************************
Define function for Physical random number generator
***********************************************************************/

int PhysicalSeed(int seeds[], int NumSeeds);                   // Physical random seed generator. Not deterministic
int DLL_STDCALL PhysicalSeedD(int seeds[], int NumSeeds);      // Windows DLL version


/***********************************************************************
Define functions for Mersenne Twister
Thread-safe, single-threaded and Windows DLL versions
***********************************************************************/

// Single-threaded static link versions for Mersenne Twister
void   MersenneRandomInit(int seed);                            // Re-seed
void   MersenneRandomInitByArray(int const seeds[], int NumSeeds);// Seed by more than 32 bits
int    MersenneIRandom (int min, int max);                      // Output random integer
int    MersenneIRandomX(int min, int max);                      // Output random integer, exact
double MersenneRandom();                                        // Output random float
uint32_t MersenneBRandom();                                     // Output random bits

// Single-threaded dynamic link versions for Mersenne Twister
void   DLL_STDCALL MersenneRandomInitD(int seed);               // Re-seed
void   DLL_STDCALL MersenneRandomInitByArrayD(int const seeds[], int NumSeeds); // Seed by more than 32 bits
int    DLL_STDCALL MersenneIRandomD (int min, int max);         // Output random integer
int    DLL_STDCALL MersenneIRandomXD(int min, int max);         // Output random integer, exact
double DLL_STDCALL MersenneRandomD();                           // Output random float
uint32_t DLL_STDCALL MersenneBRandomD();                        // Output random bits

// Thread-safe library functions for Mersenne Twister.
// The thread-safe versions have as the first parameter a pointer to a
// private memory buffer. These functions are intended to be called from
// the class CRandomMersenneA defined below. 
// If calling from C rather than C++ then supply a private memory buffer
// as Pthis. The necessary size of the buffer is given in the class 
// definition below.
#define MERS_BUFFERSIZE (208+MERS_N_A*4)                          // Size of internal buffer

void   MersRandomInit(void * Pthis, int seed);                  // Re-seed
void   MersRandomInitByArray(void * Pthis, int const seeds[], int NumSeeds); // Seed by more than 32 bits
int    MersIRandom (void * Pthis, int min, int max);            // Output random integer
int    MersIRandomX(void * Pthis, int min, int max);            // Output random integer, exact
double MersRandom  (void * Pthis);                              // Output random float
uint32_t MersBRandom (void * Pthis);                            // Output random bits


/***********************************************************************
Define functions for Mother-of-all generator
Thread-safe, single-threaded and Windows DLL versions
***********************************************************************/
// Single-threaded static link versions for Mother-of-all
void   MotherRandomInit(int seed);                              // Re-seed
int    MotherIRandom (int min, int max);                        // Output random integer
double MotherRandom();                                          // Output random float
uint32_t MotherBRandom();                                       // Output random bits

// Single-threaded dynamic link versions for Mother-of-all
void   DLL_STDCALL MotherRandomInitD(int seed);                 // Re-seed
int    DLL_STDCALL MotherIRandomD (int min, int max);           // Output random integer
double DLL_STDCALL MotherRandomD();                             // Output random float
uint32_t DLL_STDCALL MotherBRandomD();                          // Output random bits

// Thread-safe library functions for Mother-of-all
// The thread-safe versions have as the first parameter a pointer to a 
// private memory buffer. These functions are intended to be called from
// the class CRandomMotherA defined below. 
// If calling from C rather than C++ then supply a private memory buffer
// as Pthis. The necessary size of the buffer is given in the class 
// definition below.
#define MOTHER_BUFFERSIZE 80                                    // Size of internal buffer

void   MotRandomInit(void * Pthis, int seed);                   // Initialization
int    MotIRandom(void * Pthis, int min, int max);              // Get integer random number in desired interval
double MotRandom (void * Pthis);                                // Get floating point random number
uint32_t MotBRandom(void * Pthis);                              // Output random bits


/***********************************************************************
Define functions for SFMT generator.
Thread-safe, single-threaded and Windows DLL versions
***********************************************************************/

// Single-threaded static link versions for SFMT
void   SFMTgenRandomInit(int seed, int IncludeMother = 0);     // Re-seed
void   SFMTgenRandomInitByArray(int const seeds[], int NumSeeds, int IncludeMother = 0); // Seed by more than 32 bits
int    SFMTgenIRandom (int min, int max);                      // Output random integer
int    SFMTgenIRandomX(int min, int max);                      // Output random integer, exact
double SFMTgenRandom();                                        // Output random floating point number, double presision
long double SFMTgenRandomL();                                  // Output random floating point number, long double presision
uint32_t SFMTgenBRandom();                                     // Output random bits

// Single-threaded dynamic link versions for SFMT
void   DLL_STDCALL SFMTgenRandomInitD(int seed, int IncludeMother);// Re-seed
void   DLL_STDCALL SFMTgenRandomInitByArrayD(int const seeds[], int NumSeeds, int IncludeMother); // Seed by more than 32 bits
int    DLL_STDCALL SFMTgenIRandomD (int min, int max);         // Output random integer
int    DLL_STDCALL SFMTgenIRandomXD(int min, int max);         // Output random integer, exact
double DLL_STDCALL SFMTgenRandomD();                           // Output random float
uint32_t DLL_STDCALL SFMTgenBRandomD();                        // Output random bits

// Thread-safe library functions for SFMT
// The thread-safe versions have as the first parameter a pointer to a
// private memory buffer. These functions are intended to be called from
// the class CRandomSFMTA defined below. 
// If calling from C rather than C++ then supply a private memory buffer
// as Pthis. The necessary size of the buffer is given in the class 
// definition below.
#define SFMT_BUFFERSIZE (128+SFMT_N_A*16)                         // Size of internal buffer

void   SFMTRandomInit(void * Pthis, int ThisSize, int seed, int IncludeMother = 0);  // Re-seed
void   SFMTRandomInitByArray(void * Pthis, int ThisSize, int const seeds[], int NumSeeds, int IncludeMother = 0); // Seed by more than 32 bits
int    SFMTIRandom (void * Pthis, int min, int max);            // Output random integer
int    SFMTIRandomX(void * Pthis, int min, int max);            // Output random integer, exact
double SFMTRandom  (void * Pthis);                              // Output random floating point number, double presision
long double SFMTRandomL (void * Pthis);                         // Output random floating point number, long double precision
uint32_t SFMTBRandom (void * Pthis);                            // Output random bits


/***********************************************************************
   Miscellaneous utility functions
***********************************************************************/
int PhysicalSeed(int seeds[], int NumSeeds); // Seed from physical random number generator on VIA processor

uint64_t ReadTSC (void);    // Read internal CPU clock counter (useful as seed)

int InstructionSet (void);  // Find supported instruction set (used internally)


#ifdef __cplusplus
}  // end of extern "C"
#endif

/***********************************************************************
Define classes for thread-safe versions of random number generators
***********************************************************************/
#ifdef __cplusplus


// Class for Mersenne Twister
class CRandomMersenneA {                                   // Encapsulate random number generator
public:
   CRandomMersenneA(int seed) {                            // Constructor
      RandomInit(seed);}
   void RandomInit(int seed) {                             // Re-seed
      MersRandomInit(this, seed);}
   void RandomInitByArray(int const seeds[], int NumSeeds) {// Seed by more than 32 bits
      MersRandomInitByArray(this, seeds, NumSeeds);}
   int IRandom (int min, int max) {                        // Output random integer
      return MersIRandom(this, min, max);}
   int IRandomX(int min, int max) {                        // Output random integer, exact
      return MersIRandomX(this, min, max);}
   double Random() {                                       // Output random float
      return MersRandom(this);}
   uint32_t BRandom() {                                    // Output random bits
      return MersBRandom(this);}
private:
   char internals[MERS_BUFFERSIZE];                        // Internal variables
};


// Class for Mother-of-all
class CRandomMotherA {                                     // Encapsulate random number generator
public:
   CRandomMotherA(int seed) {                              // Constructor
      RandomInit(seed);}
   void RandomInit(int seed) {                             // Initialization
      MotRandomInit(this, seed);}
   int IRandom(int min, int max) {                         // Get integer random number in desired interval
      return MotIRandom(this, min, max);}
   double Random() {                                       // Get floating point random number
      return MotRandom(this);}
   uint32_t BRandom() {                                    // Output random bits
      return MotBRandom(this);}
private:
   char internals[MOTHER_BUFFERSIZE];                      // Internal variables
};


// Class for SFMT generator with or without Mother-Of-All generator
class CRandomSFMTA {                                       // Encapsulate random number generator
public:
   CRandomSFMTA(int seed, int IncludeMother = 0) {         // Constructor
      RandomInit(seed, IncludeMother);}
   void RandomInit(int seed, int IncludeMother = 0) {      // Re-seed
      SFMTRandomInit(this, sizeof(*this), seed, IncludeMother);}
   void RandomInitByArray(int const seeds[], int NumSeeds, int IncludeMother = 0) {// Seed by more than 32 bits
      SFMTRandomInitByArray(this, sizeof(*this), seeds, NumSeeds, IncludeMother);}
   int IRandom (int min, int max) {                        // Output random integer
      return SFMTIRandom(this, min, max);}
   int IRandomX(int min, int max) {                        // Output random integer, exact
      return SFMTIRandomX(this, min, max);}
   double Random() {                                       // Output random float
      return SFMTRandom(this);}
   long double RandomL() {                                 // Output random float
      return SFMTRandomL(this);}
   uint32_t BRandom() {                                    // Output random bits
      return SFMTBRandom(this);}
private:
   char internals[SFMT_BUFFERSIZE];                        // Internal variables
};


// Class for SFMT generator without Mother-Of-All generator
// Derived from CRandomSFMTA
class CRandomSFMTA0 : public CRandomSFMTA {
public:
   CRandomSFMTA0(int seed) : CRandomSFMTA(seed,0) {}
};


// Class for SFMT generator combined with Mother-Of-All generator
// Derived from CRandomSFMTA
class CRandomSFMTA1 : public CRandomSFMTA {
public:
   CRandomSFMTA1(int seed) : CRandomSFMTA(seed,1) {}
};


#endif // __cplusplus

#endif // ASMLIBRAN_H
