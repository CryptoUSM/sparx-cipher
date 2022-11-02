#include <iostream>
#include <bit>
#include <bitset>
#include <cstdint>

using namespace std;

#define N_STEPS 8
#define ROUNDS_PER_STEPS 3
#define N_BRANCHES 2
#define K_SIZE 4

void A(uint16_t *l, uint16_t *r);
void L_2(uint16_t *plaintext);
void key_permutation(uint16_t *master_key, uint16_t key_state);
void key_schedule(uint16_t subkeys[][2*ROUNDS_PER_STEPS], uint16_t *master_key);
void sparx_encrypt(uint16_t *x, uint16_t k[][2*ROUNDS_PER_STEPS]);

#define ROTL(x, n) (((x) << n) | ((x) >> (16 - (n))))
#define SWAP(x, y) tmp = x; x = y; y = tmp

// sparx 64/128
void sparx_encrypt(uint16_t *plaintext, uint16_t subkey[][2*ROUNDS_PER_STEPS]){

    // plaintext= 0123 4567 89ab cdef
    for (int s=0; s<N_STEPS; s++){ //n_s, step --> run 8 times
        for (int i=0; i< N_BRANCHES; i++){ //2
            // i=0--- x[0], x[1]
            // i=1--- x[2], x[3]
            for (int r=0; r< ROUNDS_PER_STEPS; r++){ //3
//                cout<< hex<< plaintext[2*i]<< " xor "<< subkey[(N_BRANCHES*s)+i][2*r]<< " = ";
                plaintext[2*i] ^= subkey[(N_BRANCHES*s)+i][2*r];
//                cout<< hex<< plaintext[2*i]<< endl;
//                cout<< hex<< plaintext[2*i+1]<< " xor "<< subkey[(N_BRANCHES*s)+i][2*r+1]<< " = ";
                plaintext[2*i+1] ^= subkey[(N_BRANCHES*s)+i][(2*r)+1];
//                cout<< hex<< plaintext[2*i+1]<< endl;
                A(plaintext+(2*i), plaintext+(2*i+1) );
//                cout<< "plaintext next: "<< hex<< plaintext[0] << " "<< plaintext[1] << " "<< plaintext[2] << " "<< plaintext[3] << endl;
//                cout<< "----------"<< endl;

            }
        }
        L_2(plaintext);
    }

    for (int i=0 ; i<N_BRANCHES ; i++){
        plaintext[2*i] ^= subkey[N_BRANCHES*N_STEPS][2*i];
        plaintext[(2*i)+1] ^=  subkey[N_BRANCHES*N_STEPS][(2*i)+1];
    }

    cout<< "ciphertext: ";
    for (int j=0; j<K_SIZE; j++){
        cout<< hex<< plaintext[j]<< " ";
    }
    cout<< endl;
}

int main(){
    uint16_t master_key[2*K_SIZE]= {0x0011, 0x2233, 0x4455, 0x6677, 0x8899, 0xaabb, 0xccdd, 0xeeff};
    uint16_t subkey [N_BRANCHES*N_STEPS+1][2*ROUNDS_PER_STEPS] = {{0}}; //17row, 6col

    uint16_t plaintext[K_SIZE] = {0x0123, 0x4567, 0x89ab, 0xcdef};
    // 2bbe f152 01f5 5f98

    key_schedule(subkey, master_key);

    sparx_encrypt(plaintext, subkey); //output ciphertext

    return 0;
}

/* one-round keyless round of SPECK-32 */
void A(uint16_t *l, uint16_t *r){
//    cout<< "before A: "<< hex<< *l << " "<< *r << endl;
    (*l) = ROTL((*l), 9);
    (*l) += (*r);
    (*r) = ROTL(*(r), 2);
    (*r) ^= (*l);
//    cout<< "after A: "<< hex<< *l << " "<< *r << endl;

}

void L_2(uint16_t *plaintext){
//    cout<< "before L2: "<< hex<< plaintext[0] << " "<< plaintext[1] << " "<< plaintext[2] << " "<< plaintext[3] << endl;

    uint16_t tmp = ROTL((plaintext[0] ^ plaintext[1]), 8);
    plaintext[2] ^= plaintext[0] ^ tmp;
    plaintext[3] ^= plaintext[1] ^ tmp;
    SWAP(plaintext[0], plaintext[2]);
    SWAP(plaintext[1], plaintext[3]);

//    cout<< "after L2: "<< hex<< plaintext[0] << " "<< plaintext[1] << " "<< plaintext[2] << " "<< plaintext[3] << endl;

}

void key_schedule(uint16_t subkeys[][2*ROUNDS_PER_STEPS], uint16_t *master_key){
    for (int a=0 ; a<(N_BRANCHES*N_STEPS+1) ; a++){
//        cout<< a << "----- ";

        for (int b=0 ; b<2*ROUNDS_PER_STEPS ; b++){
            subkeys[a][b] = master_key[b];

//            cout<< hex<< subkeys[a][b]<< " ";

        }
//        cout<< endl;

        key_permutation(master_key, a+1); // update state
    }




}

void key_permutation(uint16_t *master_key, uint16_t key_state){
    /*  r←r+1 // key state
        k0 ← A(k0)
        (k1)L ← (k1)L + (k0)L mod 2^16
        (k1)R ← (k1)R + (k0)R  mod 2^16
        (k3)R ← (k3)R + r mod 2^16
     */
//    cout<< "master before key perm with state "<< key_state << "---";
//    for (int i=0; i<8; i++){
//        cout<< hex<< master_key[i]<< " ";
//    }
//    cout<< endl;

    A(master_key+0, master_key+1); // pointer for first 2 key, k[0], k[1] modified
    master_key[2] += master_key[0]; // k[2]= k[2]^ k[0] -- (k1)L ← (k1)L + (k0)L mod 2^16
    master_key[3] += master_key[1]; //
    master_key[7] += key_state;

    //  k0,k1,k2,k3 ← k3,k0,k1,k2
    uint16_t tmp_0, tmp_1;

    tmp_0 = master_key[6];
    tmp_1 = master_key[7];

//    master_key[2]= master_key[0];
//    master_key[3]= master_key[1];
//
//    master_key[4]= master_key[2];
//    master_key[5]= master_key[3];
//
//    master_key[6]= master_key[4];
//    master_key[7]= master_key[5];


    for (int i=7 ; i>=2 ; i--) // from
    {
        master_key[i] = master_key[i-2];
    }
    master_key[0] = tmp_0;
    master_key[1] = tmp_1;

    // ccdd ef00 4433 ccff 8 3376

//    cout<< "after key perm------";
//    for (int i=0; i< 8; i++){
//        cout<< hex<< master_key[i]<< " ";
//    }
//    cout<< endl;





}


