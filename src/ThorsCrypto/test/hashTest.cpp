
#include <gtest/gtest.h>
#include "hash.h"
#include "md5.h"

namespace TC = ThorsAnvil::Crypto;

TEST(hashTest, StructSha1LazyDog1)
{
    std::string         input = "The quick brown fox jumps over the lazy dog";
    TC::Digest<TC::Sha1>        output;

    TC::Sha1::hash(input, output);

    std::string expected    = "\x2f\xd4\xe1\xc6\x7a\x2d\x28\xfc\xed\x84\x9e\xe1\xbb\x76\xe7\x39\x1b\x93\xeb\x12";
    EXPECT_EQ(output.view(), expected);
}
TEST(hashTest, StructSha1LazyCog1)
{
    std::string input = "The quick brown fox jumps over the lazy cog";
    TC::Digest<TC::Sha1>        output;

    TC::Sha1::hash(input, output);

    std::string expected    = "\xde\x9f\x2c\x7f\xd2\x5e\x1b\x3a\xfa\xd3\xe8\x5a\x0b\xd1\x7d\x9b\x10\x0d\xb4\xb3";
    EXPECT_EQ(output.view(), expected);
}

TEST(hashTest, StructSha1Empty1)
{
    std::string input = "";
    TC::Digest<TC::Sha1>        output;

    TC::Sha1::hash(input, output);

    std::string expected    = "\xda\x39\xa3\xee\x5e\x6b\x4b\x0d\x32\x55\xbf\xef\x95\x60\x18\x90\xaf\xd8\x07\x09";
    EXPECT_EQ(output.view(), expected);
}
TEST(hashTest, MD5TestCreate)
{
    std::string input = "TestString";
    TC::Digest<TC::Md5>        output;

    TC::Md5::hash(input, output);

    std::string expected    = "\x5b\x56\xf4\x0f\x88\x28\x70\x1f\x97\xfa\x45\x11\xdd\xcd\x25\xfb";
    EXPECT_EQ(output.view(), expected);

    using namespace std::literals;
    TC::MD5       test;
    std::stringstream result;
    result << test.digest("TestString");
    ASSERT_EQ("5b56f40f8828701f97fa4511ddcd25fb", result.str());
}
TEST(hashTest, MD5TestCreateFromObjectEmpty)
{
    std::string input = "JustString";
    TC::Digest<TC::Md5>        output;

    TC::Md5::hash(input, output);

    std::string expected    = "\x79\x19\xA4\x8C\xA7\xC5\x7E\xEA\x99\x5F\xBC\xB0\x0A\xB3\x93\x6B";
    EXPECT_EQ(output.view(), expected);

    using namespace std::literals;
    TC::MD5       test;
    std::stringstream result;
    result << test.digest("JustString");
    ASSERT_EQ("7919a48ca7c57eea995fbcb00ab3936b", result.str());
}
TEST(hashTest, MD5TestCreateHexDigest)
{
    std::string input = "TestString";
    std::string output = TC::hexdigest<TC::Md5>(input);

    std::string expected    = "5b56f40f8828701f97fa4511ddcd25fb";
    EXPECT_EQ(output, expected);

    using namespace std::literals;
    TC::MD5       test;
    std::stringstream result;
    result << test.digest("TestString");
    ASSERT_EQ("5b56f40f8828701f97fa4511ddcd25fb", result.str());
}
TEST(hashTest, MD5TestCreateFromObjectEmptyHexDigest)
{
    std::string input = "JustString";
    std::string output = TC::hexdigest<TC::Md5>(input);

    std::string expected    = "7919a48ca7c57eea995fbcb00ab3936b";
    EXPECT_EQ(output, expected);

    using namespace std::literals;
    TC::Digest<TC::Md5>        hash;
    TC::Md5::hash("JustString"s, hash);
    char expectedResult[] = "\x79\x19\xA4\x8C\xA7\xC5\x7E\xEA\x99\x5F\xBC\xB0\x0A\xB3\x93\x6B";
    ASSERT_EQ(hash.view(), std::string_view(expectedResult, std::size(expectedResult) - 1));
}
TEST(hashTest, CreateFromObjectTestString)
{
    std::string input = "Init";
    TC::Digest<TC::Md5>        output;

    TC::Md5::hash(input, output);

    std::string expected    = "\x95\xB1\x9F\x77\x39\xB0\xB7\xEA\x7D\x6B\x07\x58\x6B\xE5\x4F\x36";
    EXPECT_EQ(output.view(), expected);

    using namespace std::literals;
    TC::MD5       test;
    std::stringstream result;
    result << test.digest("Init");
    ASSERT_EQ("95b19f7739b0b7ea7d6b07586be54f36", result.str());
}
TEST(hashTest, CreateFromObjectTestStringStream)
{
    using namespace std::literals;

    TC::MD5                 test;
    std::stringstream   resultStream;
    resultStream << test.digest("WithInit");

    std::string result = resultStream.str();
    std::transform(std::begin(result), std::end(result), std::begin(result), [](char x){return ::toupper(x);});
    ASSERT_EQ("8034432759B1BE546653F6FED5B17AE9", result);

    TC::Digest<TC::Md5>        output;
    TC::Md5::hash("WithInit"s, output);
    ASSERT_EQ(output.view(), "\x80\x34\x43\x27\x59\xB1\xBE\x54\x66\x53\xF6\xFE\xD5\xB1\x7A\xE9");
}
TEST(hashTest, NotFinalized)
{
    using namespace std::literals;
    TC::Digest<TC::Md5>        output;
    TC::Md5::hash(""s, output);
    char expectedResult[] = "\xd4\x1d\x8c\xd9\x8f\x00\xb2\x04\xe9\x80\x09\x98\xec\xf8\x42\x7e";
    ASSERT_EQ(output.view(), std::string_view(expectedResult, std::size(expectedResult) - 1));

    TC::MD5       test;
    std::stringstream result;
    result << test.digest("");
    ASSERT_EQ("d41d8cd98f00b204e9800998ecf8427e", result.str());
}
