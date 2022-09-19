#include <gtest/gtest.h>
#include "md5.h"
#include <iostream>

using ThorsAnvil::Crypto::MD5;
using ThorsAnvil::Crypto::Hash;

TEST(md5Test, emptyOne)
{
    MD5 hash;
    Hash actual = hash.digest("");
    EXPECT_EQ(actual, Hash("d41d8cd98f00b204e9800998ecf8427e"));
}
TEST(md5Test, aOne)
{
    MD5 hash;
    Hash actual = hash.digest("a");
    EXPECT_EQ(actual, Hash("0cc175b9c0f1b6a831c399e269772661"));
}
TEST(md5Test, abcOne)
{
    MD5 hash;
    Hash actual = hash.digest("abc");
    EXPECT_EQ(actual, Hash("900150983cd24fb0d6963f7d28e17f72"));
}
TEST(md5Test, messageDigetOne)
{
    MD5 hash;
    Hash actual = hash.digest("message digest");
    EXPECT_EQ(actual, Hash("f96b697d7cb7938d525a2f31aaf161d0"));
}
TEST(md5Test, a2zOne)
{
    MD5 hash;
    Hash actual = hash.digest("abcdefghijklmnopqrstuvwxyz");
    EXPECT_EQ(actual, Hash("c3fcd3d76192e4007dfb496cca67e13b"));
}
TEST(md5Test, A2Za2z029One)
{
    MD5 hash;
    Hash actual = hash.digest("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
    EXPECT_EQ(actual, Hash("d174ab98d277d9f5a5611c2c9f419d9f"));
}
TEST(md5Test, eightOne)
{
    MD5 hash;
    Hash actual = hash.digest("12345678901234567890123456789012345678901234567890123456789012345678901234567890");
    EXPECT_EQ(actual, Hash("57edf4a22be3c955ac49da2e2107b67a"));
}

TEST(md5Test, emptyTwo)
{
    MD5 hash;
    hash.add("");
    hash.add("");
    Hash actual = hash.hash();
    EXPECT_EQ(actual, Hash("d41d8cd98f00b204e9800998ecf8427e"));
}
TEST(md5Test, aTwo)
{
    MD5 hash;
    hash.add("a");
    hash.add("");
    Hash actual = hash.hash();
    EXPECT_EQ(actual, Hash("0cc175b9c0f1b6a831c399e269772661"));
}
TEST(md5Test, abcTwo)
{
    MD5 hash;
    hash.add("ab");
    hash.add("c");
    Hash actual = hash.hash();
    EXPECT_EQ(actual, Hash("900150983cd24fb0d6963f7d28e17f72"));
}
TEST(md5Test, messageDigetTwo)
{
    MD5 hash;
    hash.add("message di");
    hash.add("gest");
    Hash actual = hash.hash();
    EXPECT_EQ(actual, Hash("f96b697d7cb7938d525a2f31aaf161d0"));
}
TEST(md5Test, a2zTwo)
{
    MD5 hash;
    hash.add("abcdefghijklmnopqrstuvwx");
    hash.add("yz");
    Hash actual = hash.hash();
    EXPECT_EQ(actual, Hash("c3fcd3d76192e4007dfb496cca67e13b"));
}

TEST(md5Test, A2Za2z029Two)
{
    MD5 hash;
    hash.add("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");
    hash.add("0123456789");
    Hash actual = hash.hash();
    EXPECT_EQ(actual, Hash("d174ab98d277d9f5a5611c2c9f419d9f"));
}
TEST(md5Test, eightTwo)
{
    MD5 hash;
    hash.add("12");
    hash.add("345678901234567890123456789012345678901234567890123456789012345678901234567890");
    Hash actual = hash.hash();
    EXPECT_EQ(actual, Hash("57edf4a22be3c955ac49da2e2107b67a"));
}
