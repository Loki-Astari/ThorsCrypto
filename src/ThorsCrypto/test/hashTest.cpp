
#include <gtest/gtest.h>
#include "hash.h"

using namespace ThorsAnvil::Crypto;

TEST(hashTest, StructSha1LazyDog1)
{
    std::string         input = "The quick brown fox jumps over the lazy dog";
    Digest<Sha1>        output;

    Sha1::hash(input, output);

    std::string expected    = "\x2f\xd4\xe1\xc6\x7a\x2d\x28\xfc\xed\x84\x9e\xe1\xbb\x76\xe7\x39\x1b\x93\xeb\x12";
    EXPECT_EQ(output.view(), expected);
}
TEST(hashTest, StructSha1LazyCog1)
{
    std::string input = "The quick brown fox jumps over the lazy cog";
    Digest<Sha1>        output;

    Sha1::hash(input, output);

    std::string expected    = "\xde\x9f\x2c\x7f\xd2\x5e\x1b\x3a\xfa\xd3\xe8\x5a\x0b\xd1\x7d\x9b\x10\x0d\xb4\xb3";
    EXPECT_EQ(output.view(), expected);
}

TEST(hashTest, StructSha1Empty1)
{
    std::string input = "";
    Digest<Sha1>        output;

    Sha1::hash(input, output);

    std::string expected    = "\xda\x39\xa3\xee\x5e\x6b\x4b\x0d\x32\x55\xbf\xef\x95\x60\x18\x90\xaf\xd8\x07\x09";
    EXPECT_EQ(output.view(), expected);
}
