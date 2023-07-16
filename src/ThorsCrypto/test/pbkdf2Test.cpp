 
#include <gtest/gtest.h>
#include "pbkdf2.h"

using namespace ThorsAnvil::Crypto;
using namespace std::string_literals;

using Pbkdf2HMakSha1 = Pbkdf2<HMac<Sha1>>;

TEST(pbkdf2Test, StructPasswordSalt_One_Iter)
{
    std::string     password = "password";
    std::string     salt     = "salt";
    long            iter     = 1;

    Digest<Pbkdf2HMakSha1>  output;

    Pbkdf2HMakSha1::hash(password, salt, iter, output);

    std::string expected("\x0c\x60\xc8\x0f\x96\x1f\x0e\x71\xf3\xa9\xb5\x24\xaf\x60\x12\x06\x2f\xe0\x37\xa6"s);
    EXPECT_EQ(output.view(), expected);
}

TEST(pbkdf2Test, StructPasswordSalt_Two_Iter)
{
    std::string     password = "password";
    std::string     salt     = "salt";
    long            iter     = 2;

    Digest<Pbkdf2HMakSha1>  output;

    Pbkdf2HMakSha1::hash(password, salt, iter, output);

    std::string expected("\xea\x6c\x01\x4d\xc7\x2d\x6f\x8c\xcd\x1e\xd9\x2a\xce\x1d\x41\xf0\xd8\xde\x89\x57"s);
    EXPECT_EQ(output.view(), expected);
}

TEST(pbkdf2Test, StructPasswordSalt_4K_Iter)
{
    std::string     password = "password";
    std::string     salt     = "salt";
    long            iter     = 4096;

    Digest<Pbkdf2HMakSha1>  output;

    Pbkdf2HMakSha1::hash(password, salt, iter, output);

    std::string expected("\x4b\x00\x79\x01\xb7\x65\x48\x9a\xbe\xad\x49\xd9\x26\xf7\x21\xd0\x65\xa4\x29\xc1"s);
    EXPECT_EQ(output.view(), expected);
}

TEST(pbkdf2Test, StructPasswordSalt_16K_Iter)
{
    std::string     password = "password";
    std::string     salt     = "salt";
    long            iter     = 16777216;

    Digest<Pbkdf2HMakSha1>  output;

    Pbkdf2HMakSha1::hash(password, salt, iter, output);

    std::string expected("\xee\xfe\x3d\x61\xcd\x4d\xa4\xe4\xe9\x94\x5b\x3d\x6b\xa2\x15\x8c\x26\x34\xe9\x84"s);
    EXPECT_EQ(output.view(), expected);
}

TEST(pbkdf2Test, StructPasswordSalt_4K_Iter_25_Long)
{
    std::string     password = "passwordPASSWORDpassword";
    std::string     salt     = "saltSALTsaltSALTsaltSALTsaltSALTsalt";
    long            iter     = 4096;

    Digest<Pbkdf2HMakSha1>  output;

    Pbkdf2HMakSha1::hash(password, salt, iter, output);

    char expected[] =    "\x3d\x2e\xec\x4f\xe4\x1c\x84\x9b\x80\xc8\xd8\x36\x62\xc0\xe4\x4a\x8b\x29\x1a\x96";
    EXPECT_EQ(output.view(), std::string_view(expected, sizeof(expected) - 1));
}
