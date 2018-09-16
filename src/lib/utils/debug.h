/**
 * @file debug.h This file contains macros and associated helper functions for quick cerr oriented debugging 
    that can be quickly enabled and disabled. It also contains functions for timing code.
 * @author  TPOC: palisade@njit.edu
 *
 * @copyright Copyright (c) 2017, New Jersey Institute of Technology (NJIT)
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this
 * list of conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef __dbg_h__
#define __dbg_h__

//#include <cstdlib.h>

/* defining NDEBUG in the compile line turns everything off.
   unless PROFILE is defined in the file before all includes,'
   in which case TIC/TOC will still work and PROFILELOG() can be
   used for logging results to std::cout, and DEBUG() will remain
   silent. dbg_flag does not get used by PROFILELOG()
 */

#include <iostream>
#include <vector>
#include "time.h"
#include <utility> // for forward
#include <chrono> //for timing

#if!defined(NDEBUG) 

// note that for the following dbg_flag needs to be defined in some scope

// debugging macro prints value of x on cerr
#define DEBUG(x) do {                   \
    if (dbg_flag) { std::cerr << x <<std::endl; }   \
  } while (0)

// debugging macro prints typography of x and value of x on cerr
#define DEBUGEXP(x) do {                    \
    if (dbg_flag) { std::cerr << #x << ":" << x << std::endl; } \
  } while (0)


// debugging macro prints value of x and location in code of x on cerr
#define DEBUGWHERE(x) do {                  \
    if (dbg_flag) { std::cerr << #x << ":" << x << " at " << __FILE__ << " line "<< __LINE__ LL std::endl; }    \
  } while (0)

#if defined(PROFILE) //Profiler works

#define PROFILELOG(x) do {      \
    if (true) {std::cout << x <<std::endl;} \
  } while (0)

// debugging macro prints typography of x and value of x on cerr
#define PROFILELOGEXP(x) do {   \
    if (true){ std::cout << #x << ":" << x << std::endl; }  \
  } while (0)


// debugging macro prints value of x and location in codex on cerr
#define PROFILELOGWHERE(x) do {                 \
    if (true){ std::cout << #x << ":" << x << " at " << __FILE__ << " line "<< __LINE__ LL std::endl;} \
  } while (0)

#else //#if defined(PROFILE) //profiling a noop
#define PROFILELOG(x)  
#define PROFILELOGEXP(x)
#define PROFILELOGWHERE(x)

#endif //PROFILE

#define TIC(t) t=timeNow()
#define TOC(t) duration(timeNow()-t)
#define TOC_NS(t) duration_ns(timeNow()-t) 
#define TOC_US(t) duration_us(timeNow()-t) 
#define TOC_MS(t) duration_ms(timeNow()-t) 

#else //NDEBUG

//#define debug(M, ...) fprintf(stderr, "DEBUG %s:%d: " M "\n", __FILE__, __LINE__, ##__VA_ARGS__)

#if !defined(PROFILE)

//these are turned off functions

#define DEBUG(x) 
#define DEBUGEXP(x) 
#define DEBUGWHERE(x)

#define PROFILELOG(x)
#define PROFILELOGEXP(x)
#define PROFILELOGWHERE(x)


#define TIC(t) 0
#define TOC(t) 0
#define TOC_NS(t) 0
#define TOC_US(t) 0
#define TOC_MS(t) 0

#else //PROFILE
//if PROFILE is turned on, then TIC TOC still work and 

#define DEBUG(x) 
#define DEBUGEXP(x) 
#define DEBUGWHERE(x)

#define PROFILELOG(x) do {                  \
    if (true) { std::cerr << x <<std::endl; }           \
  } while (0)

// debugging macro prints typography of x and value of x on cerr
#define PROFILELOGEXP(x) do {   \
    if (true) {std::cout << #x << ":" << x << std::endl;    }   \
  } while (0)

// debugging macro prints value of x and location in codex on cerr
#define PROFILELOGWHERE(x) do {                 \
                   if (true) {std::cout << #x << ":" << x << " at " << __FILE__ << " line "<< __LINE__ LL std::endl;} \
  } while (0)

#define TIC(t) t=timeNow()
#define TOC(t) duration(timeNow()-t)
#define TOC_NS(t) duration_ns(timeNow()-t) 
#define TOC_US(t) duration_us(timeNow()-t) 
#define TOC_MS(t) duration_ms(timeNow()-t) 

#endif //PROFILE

#endif //NDEBUG

typedef std::chrono::high_resolution_clock::time_point TimeVar;


#define duration(a) std::chrono::duration_cast<std::chrono::milliseconds>(a).count()
#define duration_ns(a) std::chrono::duration_cast<std::chrono::nanoseconds>(a).count()
#define duration_us(a) std::chrono::duration_cast<std::chrono::microseconds>(a).count()
#define duration_ms(a) std::chrono::duration_cast<std::chrono::milliseconds>(a).count()
#define timeNow() std::chrono::high_resolution_clock::now()


double currentDateTime();

template<typename F, typename... Args>
double funcTime(F func, Args&&... args){
    TimeVar t1=timeNow();
    func(std::forward<Args>(args)...);
    return duration(timeNow()-t1);
}



#endif //#__dbg_h__
