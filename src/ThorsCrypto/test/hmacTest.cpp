
#include <gtest/gtest.h>
#include "hmac.h"

using namespace ThorsAnvil::Crypto;

TEST(hmacTest, StructSHA1_QuickBrownFox)
{
    std::string key     = "key";
    std::string data    = "The quick brown fox jumps over the lazy dog";

    Digest<HMac<Sha1>>      output;
    HMac<Sha1>::hash(key, data, output);

    std::string expected = "\xde\x7c\x9b\x85\xb8\xb7\x8a\xa6\xbc\x8a\x7a\x36\xf7\x0a\x90\x70\x1c\x9d\xb4\xd9";
    ASSERT_EQ(output.view(), expected);
}

TEST(hmacsha1Test, StructSHA256_QuickBrownFox)
{
    std::string key     = "key";
    std::string data    = "The quick brown fox jumps over the lazy dog";

    Digest<HMac<Sha256>>      output;
    HMac<Sha256>::hash(key, data, output);

    std::string expected = "\xf7\xbc\x83\xf4\x30\x53\x84\x24\xb1\x32\x98\xe6\xaa\x6f\xb1\x43\xef\x4d\x59\xa1\x49\x46\x17\x59\x97\x47\x9d\xbc\x2d\x1a\x3c\xd8";
    ASSERT_EQ(output.view(), expected);
}

