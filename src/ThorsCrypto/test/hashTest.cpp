
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
TEST(hashTest, MD5TestCreate)
{
    std::string input = "TestString";
    Digest<Md5>        output;

    Md5::hash(input, output);

    std::string expected    = "\x5b\x56\xf4\x0f\x88\x28\x70\x1f\x97\xfa\x45\x11\xdd\xcd\x25\xfb";
    EXPECT_EQ(output.view(), expected);

    //std::string result = ThorsAnvil::DB::Util::md5("TestString");
    //ASSERT_EQ("5B56F40F8828701F97FA4511DDCD25FB", result);
}
TEST(hashTest, MD5TestCreateFromObjectEmpty)
{
    std::string input = "JustString";
    Digest<Md5>        output;

    Md5::hash(input, output);

    std::string expected    = "\x79\x19\xA4\x8C\xA7\xC5\x7E\xEA\x99\x5F\xBC\xB0\x0A\xB3\x93\x6B";
    EXPECT_EQ(output.view(), expected);

    //ThorsAnvil::DB::Util::MD5       test;
    //ASSERT_EQ("7919A48CA7C57EEA995FBCB00AB3936B", result);
}
TEST(hashTest, MD5TestCreateHexDigest)
{
    std::string input = "TestString";
    std::string output = hexdigest<Md5>(input);

    std::string expected    = "5b56f40f8828701f97fa4511ddcd25fb";
    EXPECT_EQ(output, expected);

    //std::string result = ThorsAnvil::DB::Util::md5("TestString");
    //ASSERT_EQ("5B56F40F8828701F97FA4511DDCD25FB", result);
}
TEST(hashTest, MD5TestCreateFromObjectEmptyHexDigest)
{
    std::string input = "JustString";
    std::string output = hexdigest<Md5>(input);

    std::string expected    = "7919a48ca7c57eea995fbcb00ab3936b";
    EXPECT_EQ(output, expected);

    //ThorsAnvil::DB::Util::MD5       test;
    //ASSERT_EQ("7919A48CA7C57EEA995FBCB00AB3936B", result);
}
#if 0
TEST(MD5Test, CreateFromObjectTestString)
{
    std::string input1 = "Init";
    Digest<Md5>        output;

    Md5::hash(input, output);
    Digest<Md5>        output;
    Md5:::


    std::string expected    = "\x95\xB1\x9F\x77\x39\xB0\xB7\xEA\x7D\x6B\x07\x58\x6B\xE5\x4F\x36";
    EXPECT_EQ(output.view(), expected);
    //ThorsAnvil::DB::Util::MD5       test("Init");
    //test.update("WithInit", 10);
    //ASSERT_EQ("95B19F7739B0B7EA7D6B07586BE54F36", result);
}
TEST(MD5Test, CreateFromObjectTestStringStream)
{
    test.update("WithInit", 10);
    test.finalize();
    std::stringstream resultStream;
    resultStream << test;
    std::string result = resultStream.str();
    std::transform(std::begin(result), std::end(result), std::begin(result), [](char x){return ::toupper(x);});
    ASSERT_EQ("95B19F7739B0B7EA7D6B07586BE54F36", result);
}
TEST(MD5Test, NotFinalized)
{
    ThorsAnvil::DB::Util::MD5       test;
    std::string result = test.hexdigest();
    ASSERT_EQ("", result);
}
#endif
