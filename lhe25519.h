/*
 * Copyright 2019 Zhicong Huang (zhicong303@gmail.com). All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

#ifndef LHE25519_H
#define LHE25519_H

#include <random>
#include <iostream>
#include <stdexcept>
#include <unordered_map>
#include "curve25519.h"
#include "test.h"

struct Ciphertext {
    ge_p3 c0;
    ge_p3 c1;
};

struct Plaintext {
    uint8_t m[32] = {0};
};

struct PublicKey {
    ge_p3 data_;

    PublicKey(){}

    PublicKey(const ge_p3& data) {
        const uint8_t* src = reinterpret_cast<const uint8_t*>(&data);
        uint8_t* dst = reinterpret_cast<uint8_t*>(&data_);
        memcpy(dst, src, sizeof(data_));
    }

    PublicKey(const PublicKey& pk) {
        operator=(pk); 
    }

    PublicKey& operator=(const PublicKey& pk) {
        const uint8_t* src = reinterpret_cast<const uint8_t*>(&pk.data_);
        uint8_t* dst = reinterpret_cast<uint8_t*>(&data_);
        memcpy(dst, src, sizeof(data_));

        return *this;
    }
};

struct SecretKey {
    uint8_t data_[32];

    SecretKey() {}

    SecretKey(const uint8_t data[32]) {
        memcpy(data_, data, sizeof(data_)); 
    }

    SecretKey(const SecretKey& sk) {
        operator=(sk); 
    }

    SecretKey& operator=(const SecretKey& sk) {
        memcpy(data_, sk.data_, sizeof(data_));
        
        return *this;
    }
};

void random_bytes(void* data, size_t len) {
    int* alias = (int *)(&data);
    std::random_device rd;
    for (size_t i = 0; i < len / sizeof(int); ++i)
        alias[i] = rd();

    if (len % sizeof(int) != 0) {
			int extra = rd();
			memcpy((len/sizeof(int)*sizeof(int))+(char *) data, &extra, len%sizeof(4));
		}
}

#define MSG_BITS 40
#define BABY_BITS 15
#define GIANT_BITS (MSG_BITS-BABY_BITS)

class LHE25519 {

public:
    
    LHE25519(const PublicKey& pk)
        : pk_(pk), has_sk_(false) {
    }

    LHE25519(const PublicKey& pk, const SecretKey& sk)
        : pk_(pk), sk_(sk), has_sk_(true) {
    }

    LHE25519() {

    }

    void key_gen() {
        random_bytes(sk_.data_, sizeof(sk_.data_));
        sk_.data_[0] &= 248;
        sk_.data_[31] &= 63;
        sk_.data_[31] |= 64;

        ge_scalarmult_base(&pk_.data_, sk_.data_);

        has_sk_ = true;
    }

    /*
     * The decryption table content is fixed for curve Ed25519, 
     * hence it only needs to be precomputed once.
     */
    void precompute_decrypt_table() {
        /* 
         * We use bay-step-giant-step to optimize the tradeoff between
         * look-up table storage and the decryption speed:
         * For 40-bit message m, we break it as: m = m1*2^{BABY_BITS} + m0,
         * where -2^{GIANT_BITS-1} <= m1 <= 2^{GIANT_BITS-1}-1, 0 <= m0 <= 2^{BABY_BITS}-1
         * And we only store the giant steps in the table: m1*2^{BABY_BITS}
         */

        ge_p3 entry;
        Plaintext plain;

        int n = 1L << (GIANT_BITS-1);
        uint8_t tmp[32];
        for (int i = -n; i < n; i++) {
            encode(plain,  ((int64_t)i) << BABY_BITS);
            ge_scalarmult_base(&entry, plain.m); 
            ge_p3_tobytes(tmp, &entry);
            table_[std::string((const char*)tmp, 32)] = i;
        }
    }

    const PublicKey& public_key() const {
        return pk_;
    }

    const SecretKey& secret_key() const {
        return sk_;
    }

    void encode(Plaintext& plain, int64_t value) {
        // This library can handle at most 40-bit messages (with sign bit): [-2^39, 2^39-1]
        int64_t upper_bound = (1L << 39) - 1;
        int64_t lower_bound = -(1L << 39); 
        if (value > upper_bound || value < lower_bound)
            throw std::invalid_argument("Input value out of supported range [-2^39, 2^39-1]");

        memset(plain.m, 0, sizeof(plain.m));
        for (int i = 0; i < 8; i++) {
            plain.m[i] = (value >> (8*i)) & 0xFFL;
        }

        // Positive encodinng finishes here
        if (value >= 0)
            return;

        // Next handles negative encoding 

        for (int i = 8; i < 32; i++)
            plain.m[i] = 255;

        // Add plain with L, essentially a modulo operation
        uint8_t carry = 0;
        for (int i = 0; i < 32; i++) {
            if (carry == 1 && plain.m[i] == 255) {
                plain.m[i] += L_[i] + carry;
                carry = 1;
            }
            else if ( (255 - carry - plain.m[i]) < L_[i] ) {
                plain.m[i] += L_[i] + carry;
                carry = 1;
            }
            else {
                plain.m[i] += L_[i] + carry;
                carry = 0;
            }
        }
    }

    void decode(int64_t& value, const Plaintext& plain) {
        uint8_t copy[32];
        memcpy(copy, plain.m, 32);
        x25519_sc_reduce(copy); 

        // Check whether plain is larger than 2^39 - 1
        bool negative = false;
        for (int i = 5; i < 32; i++) {
            negative |= (copy[i] > 0);
        }

        if (negative) {
            // Subtract L from plain to recover the negative number
            uint8_t borrow = 0;
            for (int i = 0; i < 32; i++) {
                if(borrow == 1 && L_[i] == 255) {
                    copy[i] -= (L_[i] + borrow);
                    borrow = 1;
                }
                else if (copy[i] < (L_[i] + borrow)) {
                    copy[i] -= (L_[i] + borrow);
                    borrow = 1;
                }
                else {
                    copy[i] -= (L_[i] + borrow);
                    borrow = 0;
                }
            }
        }
        // Copying the lower bytes works for a valid number in the range [-2^39, 2^39 - 1].
        // If the number is invalid, then the result is undefined.
        for (int i = 0; i < 8; i++)
            value |= ((int64_t)copy[i]) << (i*8);
    }

    void encrypt(Ciphertext& ciphertext, int64_t value) {
        Plaintext plain;
        encode(plain, value);
        encrypt(ciphertext, plain);
    }

    void encrypt(Ciphertext& ciphertext, const Plaintext& plaintext) {
        Plaintext r;

        random_bytes(r.m, sizeof(r.m));
        x25519_sc_reduce(r.m);
        ge_double_scalarmult_vartime(&ciphertext.c0, r.m, &pk_.data_, plaintext.m);
        ge_scalarmult_base(&ciphertext.c1, r.m);
    }

    void decrypt(int64_t& value, const Ciphertext& ciphertext) {
        Plaintext zero;
        
        ge_p2 R_p2;
        ge_p1p1 R_p1p1;
        ge_p3 R_p3;
        ge_cached R_cached;


        ge_double_scalarmult_vartime(&R_p2, sk_.data_, &ciphertext.c1, zero.m);
        ge_p2_to_cached(&R_cached, &R_p2);
        ge_sub(&R_p1p1, &ciphertext.c0, &R_cached);
        ge_p1p1_to_p3(&R_p3, &R_p1p1);
        ge_p3_to_cached(&R_cached, &R_p3);

        Plaintext baby_plain;
        ge_p3 baby_element;
        int n = 1L << BABY_BITS; 
        uint8_t tmp[32];
        for(int i = 0; i < n; i++) {
            encode(baby_plain, -i);
            ge_scalarmult_base(&baby_element, baby_plain.m);
            ge_add(&R_p1p1, &baby_element, &R_cached);
            ge_p1p1_to_p2(&R_p2, &R_p1p1);
            ge_tobytes(tmp, &R_p2);
            size_t found = table_.count(std::string((const char*)tmp, 32));
            
            if (found == 0) continue; 

            int64_t giant_step = table_[std::string((const char*)tmp, 32)]; 
            value = (giant_step << BABY_BITS) + i; 
            return;
        }
        std::cout << "[ERROR] Unable to decrypt" << std::endl;
    }

    void hom_add(Ciphertext& c, const Ciphertext& a, const Ciphertext& b) {
        ge_cached t0;
        ge_p1p1 t1; 

        ge_p3_to_cached(&t0, &b.c0);
        ge_add(&t1, &a.c0, &t0);
        ge_p1p1_to_p3(&c.c0, &t1);

        ge_p3_to_cached(&t0, &b.c1);
        ge_add(&t1, &a.c1, &t0);
        ge_p1p1_to_p3(&c.c1, &t1);
    }

    void hom_sub(Ciphertext& c, const Ciphertext& a, const Ciphertext& b) {
        ge_cached t0;
        ge_p1p1 t1; 

        ge_p3_to_cached(&t0, &b.c0);
        ge_sub(&t1, &a.c0, &t0);
        ge_p1p1_to_p3(&c.c0, &t1);

        ge_p3_to_cached(&t0, &b.c1);
        ge_sub(&t1, &a.c1, &t0);
        ge_p1p1_to_p3(&c.c1, &t1); 
    }

    void hom_add_plain(Ciphertext& destination, const Ciphertext& encrypted, const Plaintext& plain) {
        ge_p3 tmp0;
        ge_cached tmp1;
        ge_p1p1 tmp2;

        ge_scalarmult_base(&tmp0, plain.m);
        ge_p3_to_cached(&tmp1, &tmp0);
        ge_add(&tmp2, &encrypted.c0, &tmp1);
        
        ge_p1p1_to_p3(&destination.c0, &tmp2);
        memcpy(
            reinterpret_cast<uint8_t*>(&destination.c1), 
            reinterpret_cast<const uint8_t*>(&encrypted.c1),
            sizeof(destination.c1)); 
    }

    void hom_sub_plain(Ciphertext& destination, const Ciphertext& encrypted, const Plaintext& plain) {
        ge_p3 tmp0;
        ge_cached tmp1;
        ge_p1p1 tmp2;

        ge_scalarmult_base(&tmp0, plain.m);
        ge_p3_to_cached(&tmp1, &tmp0);
        ge_sub(&tmp2, &encrypted.c0, &tmp1);
        
        ge_p1p1_to_p3(&destination.c0, &tmp2);
        memcpy(
            reinterpret_cast<uint8_t*>(&destination.c1), 
            reinterpret_cast<const uint8_t*>(&encrypted.c1),
            sizeof(destination.c1)); 
    }

    void hom_mul(Ciphertext& destination, const Ciphertext& encrypted, const Plaintext& plain) {
        Plaintext zero;

        ge_double_scalarmult_vartime(&destination.c0, plain.m, &encrypted.c0, zero.m);

        ge_double_scalarmult_vartime(&destination.c1, plain.m, &encrypted.c1, zero.m);
    }

    void hom_negate(Ciphertext& destination, const Ciphertext& encrypted) {
        uint8_t zero[32] = {0};
        ge_double_scalarmult_vartime(&destination.c0, neg_one_, &encrypted.c0, zero);
        ge_double_scalarmult_vartime(&destination.c1, neg_one_, &encrypted.c1, zero);
    }

    void save_table(std::ostream& stream) {
        size_t n = table_.size();
        stream.write((const char*)&n, sizeof(size_t));
        for (auto it = table_.begin(); it != table_.end(); ++it) {
            stream.write(it->first.data(), it->first.size());
            stream.write((const char*)&it->second, sizeof(int));
        }
    }

    void load_table(std::istream& stream) {
        size_t n = 0;
        stream.read((char*)&n, sizeof(size_t));
        table_.reserve(n);
        char buf[32];
        int step = 0;
        for (size_t i = 0; i < n; i++) {
            stream.read(buf, 32);
            stream.read((char*)&step, sizeof(int));
            table_[std::string((const char*)buf, 32)] = step;
        }
    }

    //virtual void save_pk(std::ostream& stream) = 0;

    //virtual void load_pk(std::istream& stream) = 0;

private:
    PublicKey pk_;
    SecretKey sk_;

    /* Group order is L = 2^252 + 27742317777372353535851937790883648493. */
    uint8_t L_[32] = {
        0xED, 0xD3, 0xF5, 0x5C, 0x1A, 0x63, 0x12, 0x58, 
        0xD6, 0x9C, 0xF7, 0xA2, 0xDE, 0xF9, 0xDE, 0x14, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
    };

    /* L-1 (-1 for signed number) */
    uint8_t neg_one_[32] = {
        0xEC, 0xD3, 0xF5, 0x5C, 0x1A, 0x63, 0x12, 0x58, 
        0xD6, 0x9C, 0xF7, 0xA2, 0xDE, 0xF9, 0xDE, 0x14, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
    };

    //uint8_t table_[1<<GIANT_BITS][32];
    std::unordered_map<std::string, int> table_;

    bool has_sk_;
};

#endif // LHE25519_H

