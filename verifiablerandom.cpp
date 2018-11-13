#include "verifiablerandom.h"
#include <assert.h>
#include <string.h>
#include <netinet/in.h>

std::shared_ptr<ECVrfSuite> CVerifiableRandom::ecvrf_p256()
{
    std::shared_ptr<ECVrfSuite> result = std::make_shared<ECVrfSuite>(EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1),EVP_sha256(),81,33,16,32);
    if (!result||!result->group)
        return nullptr;
    return result;
}

///
/// \brief Encode unsigned integer on a fixed width.
/// \param num
/// \param buf
/// \param size
///
void CVerifiableRandom::bn2bin(const BIGNUM *num, uint8_t *buf, size_t size)
{
    size_t need = BN_num_bytes(num);
    assert(need <= size);

    size_t pad = size - need;
    if (pad > 0) {
        memset(buf, 0, pad);
    }

    int ret = BN_bn2bin(num, buf + pad);
    assert(ret == need);
}

///
/// \brief OpenSSL BN_mod_mul segfaults without BN_CTX.
/// \param r
/// \param a
/// \param b
/// \param m
/// \return
///
int CVerifiableRandom::bn_mod_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m)
{
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {
        return 0;
    }

    int ret = BN_mod_mul(r, a, b, m, ctx);

    BN_CTX_free(ctx);

    return ret;
}

///
/// \brief Compute r = p1^f1 + p2^f2
/// \param group
/// \param p1
/// \param f1
/// \param p2
/// \param f2
/// \return
///
EC_POINT* CVerifiableRandom::ec_mul_two(const EC_GROUP *group, const EC_POINT *p1, const BIGNUM *f1, const EC_POINT *p2, const BIGNUM *f2)
{
    EC_POINT *result = EC_POINT_new(group);
    if (!result) {
        return nullptr;
    }

    const EC_POINT *points[] = { p1, p2 };
    const BIGNUM *factors[] = { f1, f2 };
    if (EC_POINTs_mul(group, result, nullptr, 2, points, factors, nullptr) != 1) {
        EC_POINT_clear_free(result);
        return nullptr;
    }

    return result;
}

///
/// \brief Try converting random string to EC point.
/// \param group
/// \param data
/// \param size
/// \return EC point or nullptr if the random string cannot be interpreted as an EC point.
///
EC_POINT *CVerifiableRandom::RS2ECP(const EC_GROUP *group, const uint8_t *data, size_t size)
{
    uint8_t buffer[size + 1];
    buffer[0] = 0x02;
    memcpy(buffer + 1, data, size);

    EC_POINT *point = EC_POINT_new(group);
    if (EC_POINT_oct2point(group, point, buffer, sizeof(buffer), nullptr) == 1) {
        return point;
    } else {
        EC_POINT_clear_free(point);
        return nullptr;
    }
}

///
/// \brief Convert hash value to an EC point.
/// \param vrf
/// \param pubkey
/// \param data
/// \param size
/// \return
///
EC_POINT *CVerifiableRandom::ECVRF_hash_to_curve1(const ECVrfSuite *vrf, const EC_POINT *pubkey, const uint8_t *data, size_t size)
{
    int degree = bits_in_bytes(EC_GROUP_get_degree(vrf->group));
    uint8_t _pubkey[degree + 1];
    if (EC_POINT_point2oct(vrf->group, pubkey, POINT_CONVERSION_COMPRESSED, _pubkey, sizeof(_pubkey), nullptr) != sizeof(_pubkey)) {
        return nullptr;
    }

    EC_POINT *result = nullptr;

    EVP_MD_CTX *md_template = EVP_MD_CTX_create();
    if (!md_template) {
        return nullptr;
    }
    EVP_DigestInit_ex(md_template, vrf->hash, nullptr);
    EVP_DigestUpdate(md_template, _pubkey, sizeof(_pubkey));
    EVP_DigestUpdate(md_template, data, size);

    EVP_MD_CTX *md = EVP_MD_CTX_create();
    if (!md) {
        EVP_MD_CTX_destroy(md_template);
        return nullptr;
    }

    for (uint32_t _counter = 0; result == nullptr || EC_POINT_is_at_infinity(vrf->group, result); _counter++) {
        assert(_counter < 256); // hard limit for debugging
        uint32_t counter = htonl(_counter);
        static_assert(sizeof(counter) == 4, "counter is 4-byte");

        uint8_t hash[EVP_MAX_MD_SIZE] = {0};
        unsigned hash_size = sizeof(hash);

        EVP_DigestInit_ex(md, vrf->hash, nullptr);
        EVP_MD_CTX_copy_ex(md, md_template);
        EVP_DigestUpdate(md, &counter, sizeof(counter));
        if (EVP_DigestFinal_ex(md, hash, &hash_size) != 1) {
            EC_POINT_clear_free(result);
            result = nullptr;
            break;
        }

        // perform multiplication with cofactor if cofactor is > 1
        BIGNUM *cofactor=BN_new();
        EC_GROUP_get_cofactor(vrf->group,cofactor,nullptr);
        assert(cofactor);
        result = RS2ECP(vrf->group, hash, hash_size);
        if (result != nullptr && !BN_is_one(cofactor)) {
            EC_POINT *tmp = EC_POINT_new(vrf->group);
            if (EC_POINT_mul(vrf->group, tmp, nullptr, result, cofactor, nullptr) != 1) {
                EC_POINT_clear_free(tmp);
                EC_POINT_clear_free(result);
                result = nullptr;
                break;
            }
            EC_POINT_clear_free(result);
            result = tmp;
        }
        BN_free(cofactor);
    }

    EVP_MD_CTX_destroy(md);
    EVP_MD_CTX_destroy(md_template);

    return result;
}

BIGNUM *CVerifiableRandom::ECVRF_hash_points(const ECVrfSuite *vrf, const EC_POINT **points, size_t count)
{
    BIGNUM *result = nullptr;
    uint8_t hash[EVP_MAX_MD_SIZE] = {0};
    unsigned hash_size = sizeof(hash);

    EVP_MD_CTX *md = EVP_MD_CTX_create();
    if (!md) {
        return nullptr;
    }
    EVP_DigestInit_ex(md, vrf->hash, nullptr);

    for (size_t i = 0; i < count; i++) {
        uint8_t buffer[vrf->ecp_size];
        if (EC_POINT_point2oct(vrf->group, points[i], POINT_CONVERSION_COMPRESSED, buffer, sizeof(buffer), nullptr) != sizeof(buffer)) {
            goto fail;
        }
        EVP_DigestUpdate(md, buffer, sizeof(buffer));
    }

    if (EVP_DigestFinal_ex(md, hash, &hash_size) != 1) {
        goto fail;
    }

    assert(hash_size >= vrf->c_size);
    result = BN_bin2bn(hash, vrf->c_size, nullptr);
fail:
    EVP_MD_CTX_destroy(md);

    return result;
}

bool CVerifiableRandom::ECVRF_prove(
   const ECVrfSuite *vrf, const EC_POINT *pubkey, const BIGNUM *privkey,
   const uint8_t *data, size_t size,
   uint8_t *proof, size_t proof_size)
{
   // TODO: check input constraints

   bool result = false;

   const EC_POINT *generator = EC_GROUP_get0_generator(vrf->group);
   assert(generator);
   BIGNUM *order = BN_new();
   EC_GROUP_get_order(vrf->group,order,nullptr);
   assert(order);

   EC_POINT *hash = nullptr;
   EC_POINT *gamma = nullptr;
   EC_POINT *g_k = nullptr;
   EC_POINT *h_k = nullptr;
   BIGNUM *nonce = nullptr;
   BIGNUM *c = nullptr;
   BIGNUM *cx = nullptr;
   BIGNUM *s = nullptr;

   int wrote = 0;

   hash = ECVRF_hash_to_curve1(vrf, pubkey, data, size);
   if (!hash) {
       goto fail;
   }else{
       gamma = EC_POINT_new(vrf->group);
       if (EC_POINT_mul(vrf->group, gamma, nullptr, hash, privkey, nullptr) != 1) {
           goto fail;
       }else{
           nonce = BN_new();
           if (BN_rand_range(nonce, order) != 1) {
               goto fail;
           }else{
               g_k = EC_POINT_new(vrf->group);
               if (EC_POINT_mul(vrf->group, g_k, nullptr, generator, nonce, nullptr) != 1) {
                   goto fail;
               }else{
                   h_k = EC_POINT_new(vrf->group);
                   if (EC_POINT_mul(vrf->group, h_k, nullptr, hash, nonce, nullptr) != 1) {
                       goto fail;
                   }else{
                       const EC_POINT *points[] = { generator, hash, pubkey, gamma, g_k, h_k };
                       c = ECVRF_hash_points(vrf, points, sizeof(points) / sizeof(EC_POINT *));
                       if (!c) {
                           goto fail;
                       }
                   }
               }
           }
       }
   }

   cx = BN_new();
   if (bn_mod_mul(cx, c, privkey, order) != 1) {
       goto fail;
   }

   s = BN_new();
   if (BN_mod_sub(s, nonce, cx, order, nullptr) != 1) {
       goto fail;
   }
   // write result
   wrote = EC_POINT_point2oct(vrf->group, gamma, POINT_CONVERSION_COMPRESSED, proof, vrf->ecp_size, nullptr);
   assert(wrote == vrf->ecp_size);
   (void)wrote;
   bn2bin(c, proof + vrf->ecp_size, vrf->c_size);
   bn2bin(s, proof + vrf->ecp_size + vrf->c_size, vrf->s_size);

   result = true;
fail:
   BN_free(order);
   EC_POINT_clear_free(hash);
   EC_POINT_clear_free(gamma);
   EC_POINT_clear_free(g_k);
   EC_POINT_clear_free(h_k);
   BN_clear_free(nonce);
   BN_clear_free(c);
   BN_clear_free(cx);
   BN_clear_free(s);

   return result;
}

bool CVerifiableRandom::ECVRF_decode_proof(
    const ECVrfSuite *vrf, const uint8_t *proof, size_t size,
    EC_POINT **gamma_ptr, BIGNUM **c_ptr, BIGNUM **s_ptr)
{
    if (size != vrf->proof_size) {
        return false;
    }

    assert(vrf->ecp_size + vrf->c_size + vrf->s_size == size);

    const uint8_t *gamma_raw = proof;
    const uint8_t *c_raw = gamma_raw + vrf->ecp_size;
    const uint8_t *s_raw = c_raw + vrf->c_size;
    assert(s_raw + vrf->s_size == proof + size);

    EC_POINT *gamma = EC_POINT_new(vrf->group);
    if (EC_POINT_oct2point(vrf->group, gamma, gamma_raw, vrf->ecp_size, nullptr) != 1) {
        EC_POINT_clear_free(gamma);
        return false;
    }

    BIGNUM *c = BN_bin2bn(c_raw, vrf->c_size, nullptr);
    if (!c) {
        EC_POINT_clear_free(gamma);
        return false;
    }

    BIGNUM *s = BN_bin2bn(s_raw, vrf->s_size, nullptr);
    if (!s) {
        EC_POINT_clear_free(gamma);
        BN_clear_free(c);
        return false;
    }

    *gamma_ptr = gamma;
    *c_ptr = c;
    *s_ptr = s;

    return true;
}


bool CVerifiableRandom::ECVRF_verify(const ECVrfSuite *vrf, const EC_POINT *pubkey,
   const uint8_t *data, size_t size,const uint8_t *proof, size_t proof_size)
{
   bool valid = false;

   EC_POINT *gamma = nullptr;
   EC_POINT *u = nullptr;
   EC_POINT *v = nullptr;
   BIGNUM *c = nullptr;
   BIGNUM *s = nullptr;
   BIGNUM *c2 = nullptr;

   if (!ECVRF_decode_proof(vrf, proof, proof_size, &gamma, &c, &s)) {
       goto fail;
   }else{
       const EC_POINT *generator = EC_GROUP_get0_generator(vrf->group);
       assert(generator);

       EC_POINT *hash = ECVRF_hash_to_curve1(vrf, pubkey, data, size);
       assert(hash);

       u = ec_mul_two(vrf->group, pubkey, c, generator, s);
       if (!u) {
           goto fail;
       }else{
           v = ec_mul_two(vrf->group, gamma, c, hash, s);
           if (!u) {
               goto fail;
           }else{

               const EC_POINT *points[] = {generator, hash, pubkey, gamma, u, v};
               c2 = ECVRF_hash_points(vrf, points, sizeof(points) / sizeof(EC_POINT *));
               if (!c2) {
                   goto fail;
               }
           }
       }
       EC_POINT_clear_free(hash);
   }

   valid = BN_cmp(c, c2) == 0;

fail:
   EC_POINT_clear_free(gamma);
   EC_POINT_clear_free(u);
   EC_POINT_clear_free(v);
   BN_clear_free(c);
   BN_clear_free(s);
   BN_clear_free(c2);

   return valid;
}
