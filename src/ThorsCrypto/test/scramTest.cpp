
#include <gtest/gtest.h>
#include "scram.h"

using namespace ThorsAnvil::Crypto;
using namespace std::string_literals;

#if 0
Test data to validation the scram algorithm
Here is a complete example:
see: https://wiki.xmpp.org/web/SASL_and_SCRAM-SHA-1(-PLUS)_/_SCRAM-SHA-256(-PLUS)
Username: user
Password: pencil
Client generates the random nonce fyko+d2lbbFgONRv9qkxdawL
Initial message: n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL
Server generates the random nonce 3rfcNHYJY1ZVvWVs7j
Server replies: r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096
The salt (hex): 4125c247e43ab1e93c6dff76
Client final message bare: c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j
Salted password (hex): 1d96ee3a529b5a5f9e47c01f229a2cb8a6e15f7d
Client key (hex): e234c47bf6c36696dd6d852b99aaa2ba26555728
Stored key (hex): e9d94660c39d65c38fbad91c358f14da0eef2bd6
Auth message: n=user,r=fyko+d2lbbFgONRv9qkxdawL,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096,c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j
Client signature (hex): 5d7138c486b0bfabdf49e3e2da8bd6e5c79db613
Client proof (hex): bf45fcbf7073d93d022466c94321745fe1c8e13b
Server key (hex): 0fe09258b3ac852ba502cc62ba903eaacdbf7d31
Server signature (hex): ae617da6a57c4bbb2e0286568dae1d251905b0a4
Client final message: c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=
Server final message: v=rmF9pqV8S7suAoZWja4dJRkFsKQ=
Servers server signature (hex): ae617da6a57c4bbb2e0286568dae1d251905b0a4
#endif

TEST(scramTest, Client1)
{
    std::string serverFirstResponse = "r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096";
    std::string serverFinalResponse = "v=rmF9pqV8S7suAoZWja4dJRkFsKQ=";

    ScramClient1     client("user", "pencil", "fyko+d2lbbFgONRv9qkxdawL");

    EXPECT_EQ("n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL", client.getFirstMessage());
    EXPECT_EQ("c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=", client.getFinalMessage(serverFirstResponse));
    EXPECT_TRUE(client.validateServer(serverFinalResponse));
}

TEST(scramTest, Client256)
{
    std::string serverFirstResponse = "r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096";
    std::string serverFinalResponse = "v=XKW6VuW1FANROQabnJBz1KaeCnQL/HZByQtX/iU+o30=";

    ScramClient256     client("user", "pencil", "fyko+d2lbbFgONRv9qkxdawL");

    EXPECT_EQ("n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL", client.getFirstMessage());
    EXPECT_EQ("c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=qQRLRHGPDGjB+7iVAE7NNi5xEoHKHuLCHPNQ8BTmvds=", client.getFinalMessage(serverFirstResponse));
    EXPECT_EQ(true, client.validateServer(serverFinalResponse));
}

TEST(scramTest, V1Server1)
{
    std::string     clientFirstResponse = "n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL";
    std::string     clientFinalResponse = "c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=";
    V1::ScramServerSha1     server( clientFirstResponse,
                                4096,
                                [](){return "3rfcNHYJY1ZVvWVs7j";},
                                [](V1::DBInfoType type, std::string const& /*user*/){return type == V1::DBInfoType::Password ? "pencil" : "QSXCR+Q6sek8bf92";});
    EXPECT_EQ("r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096", server.getFirstMessage());
    EXPECT_EQ("v=rmF9pqV8S7suAoZWja4dJRkFsKQ=", server.getProofMessage(clientFinalResponse));
}

TEST(scramTest, Server1)
{
    std::string     clientFirstResponse = "n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL";
    std::string     clientFinalResponse = "c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=";

    ScramMechanism1     mechanism;
    DBInfo1             user = mechanism.makeAuthInfo("pencil", "QSXCR+Q6sek8bf92", 4096);

    ScramServer1     serveR{ [&](std::string const&)  {return user;}, [](){return "3rfcNHYJY1ZVvWVs7j";}};
    EXPECT_EQ("r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096", serveR.getFirstMessage(clientFirstResponse));
    EXPECT_TRUE(serveR.getFinalMessage(clientFinalResponse).first);
    EXPECT_EQ("v=rmF9pqV8S7suAoZWja4dJRkFsKQ=", serveR.getFinalMessage(clientFinalResponse).second);
}

TEST(scramTest, V1Server256)
{
    std::string     clientFirstResponse = "n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL";
    std::string     clientFinalResponse = "c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=qQRLRHGPDGjB+7iVAE7NNi5xEoHKHuLCHPNQ8BTmvds=";
    V1::ScramServerSha256   server( clientFirstResponse,
                                4096,
                                [](){return "3rfcNHYJY1ZVvWVs7j";},
                                [](V1::DBInfoType type, std::string const& /*user*/){return type == V1::DBInfoType::Password ? "pencil" : "QSXCR+Q6sek8bf92";});
    EXPECT_EQ("r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096", server.getFirstMessage());
    EXPECT_EQ("v=XKW6VuW1FANROQabnJBz1KaeCnQL/HZByQtX/iU+o30=", server.getProofMessage(clientFinalResponse));
}

TEST(scramTest, Server256)
{
    std::string     clientFirstResponse = "n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL";
    std::string     clientFinalResponse = "c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=qQRLRHGPDGjB+7iVAE7NNi5xEoHKHuLCHPNQ8BTmvds=";
    ScramMechanism256   mechanism;
    DBInfo256           user = mechanism.makeAuthInfo("pencil", "QSXCR+Q6sek8bf92", 4096);

    ScramServer256   serveR{ [&](std::string const&)  {return user;}, [](){return "3rfcNHYJY1ZVvWVs7j";}};
    EXPECT_EQ("r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096", serveR.getFirstMessage(clientFirstResponse));
    EXPECT_TRUE(serveR.getFinalMessage(clientFinalResponse).first);
    EXPECT_EQ("v=XKW6VuW1FANROQabnJBz1KaeCnQL/HZByQtX/iU+o30=", serveR.getFinalMessage(clientFinalResponse).second);
}

TEST(scramTest, Mech1)
{
    ScramMechanism1     mech;
    DBInfo  info = mech.makeAuthInfo("pencil", "rOprNGfwEbeRWgbNEkqO", 4096);

    EXPECT_EQ("\x29\xbf\xca\x3f\x88\x7c\x38\x5c\x01\xb7\x80\x4c\x37\x29\xed\x74\x17\x26\x01\x2e", info.storedKey.view());
    EXPECT_EQ("\x99\xe6\x55\x16\x8b\xad\xd9\xee\x03\xa7\xae\x8e\xa7\x8e\x21\x88\x91\x8b\xa0\x36", info.serverKey.view());
    EXPECT_EQ(4096, info.iteration);
}

TEST(scramTest, Mech256)
{
    ScramMechanism256     mech;
    DBInfo  info = mech.makeAuthInfo("pencil", "rOprNGfwEbeRWgbNEkqO", 4096);

    EXPECT_EQ("\xc5\xa4\x72\xe6\x7c\xe3\x55\x28\xd3\x77\x76\x74\x87\x55\xc6\xc2\x97\xb2\x78\xae\xd3\xfb\x92\x43\xb6\x4d\xe6\xe6\x7d\x64\x5d\xd6", info.storedKey.view());
    EXPECT_EQ("\x9a\x2b\x9e\x4b\x99\x0a\x71\x02\x5c\x36\xe6\x7b\xe0\x99\xae\x4e\x3f\xe9\x7a\xdf\xf7\x29\x01\x74\x38\x15\xe1\xab\xf2\x6e\x66\x3f", info.serverKey.view());
    EXPECT_EQ(4096, info.iteration);
}
