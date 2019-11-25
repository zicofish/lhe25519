
#include "test.h"

using namespace std;


void test_enc_dec() {
    LHE25519 scheme;
    scheme.precompute_decrypt_table();
    scheme.key_gen();

    Ciphertext ct1, ct2;
    Plaintext pt1, pt2;
    scheme.encode(pt1, -98);
    scheme.encode(pt2, 46);

    scheme.encrypt(ct1, pt1);
    scheme.encrypt(ct2, pt2);

    int64_t x1, x2;
    scheme.decrypt(x1, ct1);
    scheme.decrypt(x2, ct2);
    assert (x1 == -98);
    assert (x2 == 46);

    cout << "Test encryption and decryption succeeds" << endl;
}

void test_hom_add() {
    LHE25519 scheme;
    scheme.precompute_decrypt_table();
    scheme.key_gen();

    Ciphertext ct1, ct2;

    scheme.encrypt(ct1, 5);
    scheme.encrypt(ct2, 37);

    Ciphertext ct3;
    scheme.hom_add(ct3, ct1, ct2);
    int64_t r;
    scheme.decrypt(r, ct3);
    assert (r == 42);

    scheme.encrypt(ct1, -98);
    scheme.encrypt(ct2, 16);
    scheme.hom_add(ct3, ct1, ct2);
    scheme.decrypt(r, ct3);
    assert (r == -82);

    cout << "Test hom add succeeds" << endl;
}

void test_hom_add_plain() {
    LHE25519 scheme;
    scheme.precompute_decrypt_table();
    scheme.key_gen();

    Ciphertext ct1, ct_result;
    Plaintext pt1, pt2;
    scheme.encode(pt1, 15);
    scheme.encode(pt2, 37);

    scheme.encrypt(ct1, pt1);

    scheme.hom_add_plain(ct_result, ct1, pt2);

    int64_t r;
    scheme.decrypt(r, ct_result);
    assert (r == 52);

    cout << "Test hom add plain succeeds" << endl;
}

void test_hom_mul() {
    LHE25519 scheme;
    scheme.precompute_decrypt_table();
    scheme.key_gen();

    Ciphertext ct1, ct_result;
    Plaintext pt1, pt2;
    scheme.encode(pt1, 5);
    scheme.encode(pt2, 37);

    scheme.encrypt(ct1, pt1);

    scheme.hom_mul(ct_result, ct1, pt2);

    int64_t r;
    scheme.decrypt(r, ct_result);
    assert (r == 5 * 37);

    cout << "Test hom mul succeeds" << endl; 
}

void test_hom_negate() {
    LHE25519 scheme;
    scheme.precompute_decrypt_table();
    scheme.key_gen();

    Ciphertext ct1, ct_result;
    Plaintext pt1;
    scheme.encode(pt1, 50);

    scheme.encrypt(ct1, pt1);

    scheme.hom_negate(ct_result, ct1);

    int64_t r;
    scheme.decrypt(r, ct_result);
    assert (r == -50);

    cout << "Test hom negate succeeds" << endl;
}

void test_save_load_table() {
    LHE25519 scheme1, scheme2;
    scheme1.precompute_decrypt_table();

    ofstream ofs("decrypt_table.dat", ofstream::out|ofstream::binary);
    scheme1.save_table(ofs);
    ofs.close();

    ifstream ifs("decrypt_table.dat", ifstream::in|ifstream::binary);
    scheme2.load_table(ifs);
    ifs.close();

    scheme2.key_gen();

    Ciphertext ct1, ct2;
    Plaintext pt1, pt2;
    scheme2.encode(pt1, -98);
    scheme2.encode(pt2, 46);

    scheme2.encrypt(ct1, pt1);
    scheme2.encrypt(ct2, pt2);

    int64_t x1, x2;
    scheme2.decrypt(x1, ct1);
    scheme2.decrypt(x2, ct2);
    assert (x1 == -98);
    assert (x2 == 46);

    cout << "Test encryption and decryption succeeds" << endl;
}

void test_large_msg() {
    LHE25519 scheme;

    time_log("Precompute table");
    scheme.precompute_decrypt_table();
    time_log("Precompute table");

    time_log("Key generation"); 
    scheme.key_gen();
    time_log("Key generation"); 

    Ciphertext ct1, ct2;

    random_device rd;
    int64_t m1, m2;
    ((unsigned int*)&m1)[0] = rd();
    ((unsigned int*)&m1)[1] = rd();
    ((unsigned int*)&m2)[0] = rd();
    ((unsigned int*)&m2)[1] = rd();
    m1 = m1 & 0x7FFFFFFFFFL;
    m2 = m2 | 0xFFFFFF8000000000L;

    scheme.encrypt(ct1, m1);
    scheme.encrypt(ct2, m2);

    int64_t x1, x2;

    time_log("Decryption x1");
    scheme.decrypt(x1, ct1);
    time_log("Decryption x1");

    time_log("Decryption x2");
    scheme.decrypt(x2, ct2);
    time_log("Decryption x2");

    assert (x1 == m1);
    assert (x2 == m2);

    cout << "Test large encryption and decryption succeeds" << endl;
}

int main() {
    test_enc_dec(); 
    test_hom_add();
    test_hom_mul();
    test_hom_add_plain();
    test_hom_negate();
    return 0;
}
