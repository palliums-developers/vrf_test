#include <iostream>
#include "verifiablerandom.h"

static void HexDump(const uint8_t *data, size_t size)
{
    for (size_t i = 0; i < size; i++) {
        bool last = i + 1 == size;
        printf("%02x%c", (unsigned int)data[i], last ? '\n' : ':');
    }
}

int main()
{
    // Sample EC P256 key
    static const uint8_t publickey[65] ={0x04,0xdb,0x72,0x4c,0xdd,0x2d,0x65,0xd9,0x0d,0xe9,0x82,0xd2,0xc6,0x94,0x3d,0x66,0x18,0x85,0x28,0xc2,0x84,0x6b,0x1f,0xeb,0x95,0x8d,0x25,0xf5,0xf1,0xbb,0x2b,0xc6,0xbe,0x16,0xab,0xce,0xbe,0x01,0xd6,0x31,0xd3,0x4e,0x69,0xfe,0xeb,0x87,0x49,0x1e,0x5d,0xfd,0x1a,0x04,0xf2,0x71,0x89,0x78,0x30,0x26,0xad,0x50,0xcd,0xcb,0xec,0x78,0x7c};

    static const uint8_t privatekey[33] ={0x00,0xe3,0xd3,0x78,0x92,0x71,0xe6,0x30,0x67,0x3c,0x10,0x98,0xe7,0x67,0x00,0xc4,0x13,0xb0,0xee,0x9a,0xd5,0x2b,0x6a,0xe1,0x71,0x5c,0x1e,0x8d,0x2e,0xea,0x9b,0x2d,0xe9};

    int result = EXIT_FAILURE;

    EC_POINT *pubkey = nullptr;
    BIGNUM *privkey = nullptr;
    int cnt=0;

    std::shared_ptr<ECVrfSuite> vrf = CVerifiableRandom::ecvrf_p256();
    if (!vrf) {
        fprintf(stderr, "failed to create VRF context\n");
        return 0;
    }

    pubkey = EC_POINT_new(vrf->group);
    if (EC_POINT_oct2point(vrf->group, pubkey, publickey, sizeof(publickey), nullptr) != 1) {
        fprintf(stderr, "failed to create public key\n");
        EC_POINT_clear_free(pubkey);
        return 0;
    }

    privkey = BN_bin2bn(privatekey, sizeof(privatekey), nullptr);
    if (!privkey) {
        fprintf(stderr, "failed to create private key\n");
        EC_POINT_clear_free(pubkey);
        BN_clear_free(privkey);
        return  0;
    }

    std::shared_ptr<uint8_t> proof(new uint8_t[vrf->proof_size]);
    if (!proof) {
        EC_POINT_clear_free(pubkey);
        BN_clear_free(privkey);
        return 0;
    }

    static const uint8_t message[] = "hello world";

    if (!CVerifiableRandom::ECVRF_prove(vrf.get(), pubkey, privkey, message, sizeof(message), proof.get(), vrf->proof_size)) {
        fprintf(stderr, "failed to create VRF proof\n");
        EC_POINT_clear_free(pubkey);
        BN_clear_free(privkey);
        return 0;
    }

    printf("message = ");
    HexDump(message, sizeof(message));
    printf("proof = ");
    HexDump(proof.get(), vrf->proof_size);

    bool valid = CVerifiableRandom::ECVRF_verify(vrf.get(), pubkey, message, sizeof(message), proof.get(), vrf->proof_size);
    printf("valid = %s\n", valid ? "true" : "false");
    result = EXIT_SUCCESS;
    EC_POINT_clear_free(pubkey);
    BN_clear_free(privkey);
    return 0;
}
