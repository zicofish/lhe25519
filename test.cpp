#include "test.h"

using namespace std;

/*
 * You can also call this function to generate the lookup table again,
 * but it will produce exactly the same content as "decrypt_table.dat"
 * which we have already submitted.
 * It takes about 20 minutes to generate it.
 */
void precompute() {
    cout << "Precomputing decryption table..." << endl;
    time_log("Precompute");
    LHE25519 scheme;
    scheme.precompute_decrypt_table();

    ofstream ofs("decrypt_table.dat", ofstream::out|ofstream::binary);
    scheme.save_table(ofs);
    ofs.close();
    time_log("Precompute");
}

void tests() {
    LHE25519 scheme;

    // Load the precomputed decryption table.
    // The table content is fixed for curve Ed25519, 
    // hence it only needs to be precomputed once.
    // We have precomputed this table and submitted it along with the code.
    // You can also use the above "precompute()" function to compute it again, which
    // will produce exactly the same output "decryption_table.dat".
    cout << "Loading decryption table..." << endl;
    time_log("Load table");
    ifstream ifs("decrypt_table.dat", ifstream::in|ifstream::binary);
    scheme.load_table(ifs);
    ifs.close();
    time_log("Load table");

    // Generate a key pair
    time_log("Key generation");
    scheme.key_gen(); 
    time_log("Key generation");

    // Encryption
    Ciphertext ct1;
    time_log("Encryption");
    scheme.encrypt(ct1, 555555);
    time_log("Encryption");

    Ciphertext ct_result;
    int64_t result = 0;

    time_log("Decryption");
    scheme.decrypt(result, ct1);
    time_log("Decryption");
    assert (result == 555555);

    // Prepare some operands for later compuation
    Ciphertext ct2;
    scheme.encrypt(ct2, 111111);
    Plaintext pt_x, pt_y;
    scheme.encode(pt_x, 111111);
    scheme.encode(pt_y, 3);

    // Homomophic add
    time_log("Homomorphic add");
    scheme.hom_add(ct_result, ct1, ct2);
    time_log("Homomorphic add");
    scheme.decrypt(result, ct_result);
    assert (result == 666666);

    // Homomorphic add plain
    time_log("Homomorphic add plain");
    scheme.hom_add_plain(ct_result, ct1, pt_x);
    time_log("Homomorphic add plain");
    scheme.decrypt(result, ct_result);
    assert (result == 666666);

    // Homomophic sub
    time_log("Homomorphic sub");
    scheme.hom_sub(ct_result, ct2, ct1);
    time_log("Homomorphic sub");
    scheme.decrypt(result, ct_result);
    assert (result == -444444);

    // Homomorphic sub plain
    time_log("Homomorphic sub plain");
    scheme.hom_sub_plain(ct_result, ct1, pt_x);
    time_log("Homomorphic sub plain");
    scheme.decrypt(result, ct_result);
    assert (result == 444444);

    // Homomorphic mul plain
    time_log("Homomorhpic mul plain");
    scheme.hom_mul(ct_result, ct1, pt_y);
    time_log("Homomorhpic mul plain");
    scheme.decrypt(result, ct_result);
    assert (result == 555555 * 3);

    // Homomorphic negate
    time_log("Homomorphic negate");
    scheme.hom_negate(ct_result, ct1);
    time_log("Homomorphic negate");
    scheme.decrypt(result, ct_result);
    assert (result == -555555);

    cout << "Releasing memory used for decryption table..." << endl;
}

int main() {
    tests();
    return 0;
}
