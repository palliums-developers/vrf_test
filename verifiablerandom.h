#ifndef CVERIFIABLERANDOM_H
#define CVERIFIABLERANDOM_H
#include <memory>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>

/**
 * EC VRF suite.
 */
struct ECVrfSuite {
    ECVrfSuite(EC_GROUP *group,const EVP_MD *hash,size_t ps,size_t es,size_t cs,size_t ss):
        group(group),hash(hash),proof_size(ps),ecp_size(es),c_size(cs),s_size(ss){}

    ~ECVrfSuite(){
        EC_GROUP_free(group);
    }

    EC_GROUP *group=nullptr;
    const EVP_MD *hash;
    size_t proof_size;
    size_t ecp_size;
    size_t c_size;
    size_t s_size;
};

class CVerifiableRandom
{
public:
    static std::shared_ptr<ECVrfSuite> ecvrf_p256();
    ///
    /// \brief bits_in_bytes Get number of bytes that fit given number of bits. ceil(div(bits/8))
    /// \param bits
    /// \return
    ///
    static int bits_in_bytes(int bits){ return (bits + 7) / 8;}

    static void bn2bin(const BIGNUM *num, uint8_t *buf, size_t size);

    static int bn_mod_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m);

    static EC_POINT* ec_mul_two(const EC_GROUP *group, const EC_POINT *p1, const BIGNUM *f1, const EC_POINT *p2, const BIGNUM *f2);

    static EC_POINT *RS2ECP(const EC_GROUP *group, const uint8_t *data, size_t size);

    static EC_POINT *ECVRF_hash_to_curve1(const ECVrfSuite *vrf, const EC_POINT *pubkey, const uint8_t *data, size_t size);

    static BIGNUM *ECVRF_hash_points(const ECVrfSuite *vrf, const EC_POINT **points, size_t count);

    static  bool ECVRF_prove(const ECVrfSuite *vrf, const EC_POINT *pubkey, const BIGNUM *privkey,
       const uint8_t *data, size_t size,uint8_t *proof, size_t proof_size);

    static bool ECVRF_decode_proof(const ECVrfSuite *vrf, const uint8_t *proof, size_t size,
        EC_POINT **gamma_ptr, BIGNUM **c_ptr, BIGNUM **s_ptr);

    static bool ECVRF_verify(const ECVrfSuite *vrf, const EC_POINT *pubkey,
       const uint8_t *data, size_t size,const uint8_t *proof, size_t proof_size);
};

#endif // CVERIFIABLERANDOM_H
