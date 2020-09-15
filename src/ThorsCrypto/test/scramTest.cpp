
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
Server's server signature (hex): ae617da6a57c4bbb2e0286568dae1d251905b0a4
#endif

TEST(scramTest, SimpleTeat)
{
    ScramClientSha1     client("user");;

    std::string clientFirstMessage = client.getFirstMessage();
    EXPECT_EQ(clientFirstMessage, "n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL");

    ScramServerSha1     server(clientFirstMessage);
    std::string serverFirstMessage = server.getFirstMessage();
    EXPECT_EQ(serverFirstMessage, "r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096");

    std::string clientProof        = client.getProofMessage("pencil", serverFirstMessage);
    EXPECT_EQ(clientProof, "c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=");

    std::string serverProof        = server.getProofMessage(clientProof);
    EXPECT_EQ(serverProof, "v=rmF9pqV8S7suAoZWja4dJRkFsKQ=");

    EXPECT_EQ(true, client.verifyServer(serverProof));

}

