#ifndef TEST_H
#define TEST_H

#include <cstdint>
#include <iostream>
#include <iomanip>
#include <iostream>
#include <fstream>
#include <cstdint>
#include <assert.h>
#include <random>
#include "curve25519.h"
#include "lhe25519.h"
#include "performance.h"

using namespace std;

void print(uint8_t x[32]) {
    ios_base::fmtflags f( cout.flags() );  // save flags state
    cout << std::hex;
    for (int i = 0; i < 32; i++) {
        cout << (int)x[i] << " ";
    }
    cout << endl;
    cout.flags( f );  // restore flags state
}

#endif
