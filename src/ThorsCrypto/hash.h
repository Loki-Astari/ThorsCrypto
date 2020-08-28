#ifndef THORS_ANVIL_CRYPTO_HASH_H
#define THORS_ANVIL_CRYPTO_HASH_H

#ifdef  __APPLE__
#define COMMON_DIGEST_FOR_OPENSSL
#include <CommonCrypto/CommonDigest.h>
#define THOR_SHA1(data, len, dst)       CC_SHA1(data, len, dst)
#define THOR_SHA256(data, len, dst)     CC_SHA256(data, len, dst)
#else
#include <openssl/sha.h>
#define THOR_SHA1(data, len, dst)       SHA1(data, len, dst)
#define THOR_SHA256(data, len, dst)     SHA256(data, len, dst)
#endif

#include <string>
#include <array>

//
// Wrapper for sha1 and sha256 hashing algorithms
//
// Provides a simple wrapper class with the appropriates types and size
// for the resulting "digest" object. Also provides several type safe
// versions of the hashing algorithm to allow multiple know types to
// be safely hashed.

namespace ThorsAnvil::Crypto
{

using Byte      = char unsigned;
using DigestPtr = Byte*;

template<std::size_t size>
class DigestStore
{
    std::array<Byte, size>      data;
    public:
        using iterator = typename std::array<Byte, size>::iterator;

        operator DigestPtr()                        {return &data[0];}
        std::string_view  view()                    {return std::string_view(reinterpret_cast<char const*>(&data[0]), std::size(data));}
        Byte&             operator[](std::size_t i) {return data[i];}
        iterator          begin()                   {return std::begin(data);}
        iterator          end()                     {return std::end(data);}
};

template<typename Hash>
using Digest = typename Hash::DigestStore;

// These versions of the hashing function are good for hashing short
// amounts of text. Use these for passwords and validation hashes
// do not use them for hashing large documents.
struct Sha1
{
    static constexpr std::size_t digestSize = SHA_DIGEST_LENGTH;
    using DigestStore = DigestStore<SHA_DIGEST_LENGTH>;

    static void hash(DigestStore& src,             DigestStore& dst)   {THOR_SHA1(src, SHA_DIGEST_LENGTH, dst);}
    static void hash(std::string_view src,         DigestStore& dst)   {THOR_SHA1(reinterpret_cast<Byte const*>(&src[0]), std::size(src), dst);}
    static void hash(std::string const& src,       DigestStore& dst)   {THOR_SHA1(reinterpret_cast<Byte const*>(&src[0]), std::size(src), dst);}
    // Use only if you know the destination is large enough!!
    static void hashUnsafe(std::string_view src,   DigestPtr dst)      {THOR_SHA1(reinterpret_cast<Byte const*>(&src[0]), std::size(src), dst);}
};
struct Sha256
{
    static constexpr std::size_t digestSize = SHA256_DIGEST_LENGTH;
    using DigestStore = DigestStore<SHA256_DIGEST_LENGTH>;

    static void hash(DigestStore& src,             DigestStore& dst)   {THOR_SHA256(src, SHA256_DIGEST_LENGTH, dst);}
    static void hash(std::string_view src,         DigestStore& dst)   {THOR_SHA256(reinterpret_cast<Byte const*>(&src[0]), std::size(src), dst);}
    static void hash(std::string const& src,       DigestStore& dst)   {THOR_SHA256(reinterpret_cast<Byte const*>(&src[0]), std::size(src), dst);}
    // Use only if you know the destination is large enough!
    static void hashUnsafe(std::string_view src,   DigestPtr dst)      {THOR_SHA256(reinterpret_cast<Byte const*>(&src[0]), std::size(src), dst);}
};

}

#endif
