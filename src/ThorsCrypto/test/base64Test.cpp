
#include <gtest/gtest.h>
#include "base64.h"

using ThorsAnvil::Crypto::make_decode64;
using ThorsAnvil::Crypto::make_encode64;

TEST(base64Test, Salt)
{
// 64:      QSXCR+Q6sek8bf92
// Salt:    4125c247e43ab1e93c6dff76
    std::string input   = "QSXCR+Q6sek8bf92";
    std::string expected= "\x41\x25\xc2\x47\xe4\x3a\xb1\xe9\x3c\x6d\xff\x76";
    std::string result(make_decode64(std::begin(input)), make_decode64(std::end(input)));

    EXPECT_EQ(result, expected);
}

TEST(base64Test, decode_any_carnal_pleasureDOT)
{
    std::string input   = "YW55IGNhcm5hbCBwbGVhc3VyZS4=";
    std::string expected= "any carnal pleasure.";
    std::string result(make_decode64(std::begin(input)), make_decode64(std::end(input)));

    EXPECT_EQ(result, expected);
}

TEST(base64Test, decode_any_carnal_pleasure)
{
    std::string input   = "YW55IGNhcm5hbCBwbGVhc3VyZQ==";
    std::string expected= "any carnal pleasure";
    std::string result(make_decode64(std::begin(input)), make_decode64(std::end(input)));

    EXPECT_EQ(result, expected);
}

TEST(base64Test, decode_any_carnal_pleasur)
{
    std::string input   = "YW55IGNhcm5hbCBwbGVhc3Vy";
    std::string expected= "any carnal pleasur";
    std::string result(make_decode64(std::begin(input)), make_decode64(std::end(input)));

    EXPECT_EQ(result, expected);
}

TEST(base64Test, decode_any_carnal_pleasu)
{
    std::string input   = "YW55IGNhcm5hbCBwbGVhc3U=";
    std::string expected= "any carnal pleasu";
    std::string result(make_decode64(std::begin(input)), make_decode64(std::end(input)));

    EXPECT_EQ(result, expected);
}

TEST(base64Test, decode_any_carnal_pleas)
{
    std::string input   = "YW55IGNhcm5hbCBwbGVhcw==";
    std::string expected= "any carnal pleas";
    std::string result(make_decode64(std::begin(input)), make_decode64(std::end(input)));

    EXPECT_EQ(result, expected);
}

TEST(base64Test, decode_pleasureDOT)
{
    std::string input   = "cGxlYXN1cmUu";
    std::string expected= "pleasure.";
    std::string result(make_decode64(std::begin(input)), make_decode64(std::end(input)));

    EXPECT_EQ(result, expected);
}

TEST(base64Test, decode_leasureDOT)
{
    std::string input   = "bGVhc3VyZS4=";
    std::string expected= "leasure.";
    std::string result(make_decode64(std::begin(input)), make_decode64(std::end(input)));

    EXPECT_EQ(result, expected);
}

TEST(base64Test, decode_easureDOT)
{
    std::string input   = "ZWFzdXJlLg==";
    std::string expected= "easure.";
    std::string result(make_decode64(std::begin(input)), make_decode64(std::end(input)));

    EXPECT_EQ(result, expected);
}

TEST(base64Test, decode_asureDOT)
{
    std::string input   = "YXN1cmUu";
    std::string expected= "asure.";
    std::string result(make_decode64(std::begin(input)), make_decode64(std::end(input)));

    EXPECT_EQ(result, expected);
}

TEST(base64Test, decode_sureDOT)
{
    std::string input   = "c3VyZS4=";
    std::string expected= "sure.";
    std::string result(make_decode64(std::begin(input)), make_decode64(std::end(input)));

    EXPECT_EQ(result, expected);
}
TEST(base64Test, encode_any_carnal_pleasureDOT)
{
    std::string expected = "YW55IGNhcm5hbCBwbGVhc3VyZS4=";
    std::string input   = "any carnal pleasure.";
    std::string result(make_encode64(std::begin(input)), make_encode64(std::end(input)));

    EXPECT_EQ(result, expected);
}

TEST(base64Test, encode_any_carnal_pleasure)
{
    std::string expected = "YW55IGNhcm5hbCBwbGVhc3VyZQ==";
    std::string input   = "any carnal pleasure";
    std::string result(make_encode64(std::begin(input)), make_encode64(std::end(input)));

    EXPECT_EQ(result, expected);
}

TEST(base64Test, encode_any_carnal_pleasur)
{
    std::string expected = "YW55IGNhcm5hbCBwbGVhc3Vy";
    std::string input   = "any carnal pleasur";
    std::string result(make_encode64(std::begin(input)), make_encode64(std::end(input)));

    EXPECT_EQ(result, expected);
}

TEST(base64Test, encode_any_carnal_pleasu)
{
    std::string expected = "YW55IGNhcm5hbCBwbGVhc3U=";
    std::string input   = "any carnal pleasu";
    std::string result(make_encode64(std::begin(input)), make_encode64(std::end(input)));

    EXPECT_EQ(result, expected);
}

TEST(base64Test, encode_any_carnal_pleas)
{
    std::string expected = "YW55IGNhcm5hbCBwbGVhcw==";
    std::string input   = "any carnal pleas";
    std::string result(make_encode64(std::begin(input)), make_encode64(std::end(input)));

    EXPECT_EQ(result, expected);
}

TEST(base64Test, encode_pleasureDOT)
{
    std::string expected = "cGxlYXN1cmUu";
    std::string input   = "pleasure.";
    std::string result(make_encode64(std::begin(input)), make_encode64(std::end(input)));

    EXPECT_EQ(result, expected);
}

TEST(base64Test, encode_leasureDOT)
{
    std::string expected = "bGVhc3VyZS4=";
    std::string input   = "leasure.";
    std::string result(make_encode64(std::begin(input)), make_encode64(std::end(input)));

    EXPECT_EQ(result, expected);
}

TEST(base64Test, encode_easureDOT)
{
    std::string expected = "ZWFzdXJlLg==";
    std::string input   = "easure.";
    std::string result(make_encode64(std::begin(input)), make_encode64(std::end(input)));

    EXPECT_EQ(result, expected);
}

TEST(base64Test, encode_asureDOT)
{
    std::string expected = "YXN1cmUu";
    std::string input   = "asure.";
    std::string result(make_encode64(std::begin(input)), make_encode64(std::end(input)));

    EXPECT_EQ(result, expected);
}

TEST(base64Test, encode_sureDOT)
{
    std::string expected = "c3VyZS4=";
    std::string input   = "sure.";
    std::string result(make_encode64(std::begin(input)), make_encode64(std::end(input)));

    EXPECT_EQ(result, expected);
}
