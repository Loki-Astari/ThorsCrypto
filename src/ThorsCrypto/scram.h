#ifndef THORSANVIL_CRYPTO_SCRAM_H
#define THORSANVIL_CRYPTO_SCRAM_H

#include "ThorsCryptoConfig.h"
#include "hash.h"
#include "hmac.h"
#include "pbkdf2.h"
#include "base64.h"
#if defined(DEBUG)
#include <iostream>
#endif

// RFC-5801 Salted Challenge Response Authentication Mechanism (SCRAM) SASL and GSS-API Mechanisms

namespace ThorsAnvil::Crypto
{

enum class DBInfoType
{
    Password,
    Salt
};

using NonceGenerator = std::function<std::string()>;
using DBInfoAccess   = std::function<std::string(DBInfoType, std::string const&)>;

// See below in ScramClient and SCramServer for examples of Hi/HMAC/H
// Hi   = Pbkdf2<HMac<Sha1>>
// HMAC = HMac<Sha1>
// H    = Sha1
template<typename Hi, typename HMAC, typename H>
class ScramBase
{
    std::string getMessageBody(std::string const& section, std::string const& message) const
    {
        auto findSection = message.find(section);
        if (findSection == std::string::npos || findSection + 2 >= message.size())
        {
            return "";
        }
        findSection += 2;
        auto sectionEnd = message.find(',', findSection);
        if (sectionEnd == std::string::npos)
        {
            sectionEnd = message.size();
        }
        return message.substr(findSection, (sectionEnd - findSection));
    }

    std::string     clientFirstMessageBare;
    std::string     serviceFirstMessage;
    std::string     serverSignature64;
    std::string     clientProof64;
    NonceGenerator  nonceGenerator;

    public:
        ScramBase(std::string const& clientFirstMessageBare, NonceGenerator&& nonceGenerator)
            : clientFirstMessageBare(clientFirstMessageBare)
            , nonceGenerator(std::move(nonceGenerator))
        {}

    protected:
        std::size_t getServiceIteration()                                       const     {return std::stol(getMessageBody("i=", serviceFirstMessage));}
        std::string getUserFromMessage()                                        const     {return getMessageBody("n=", clientFirstMessageBare);}
        std::string getServiceSalt()                                            const     {return getMessageBody("s=", serviceFirstMessage);}
        std::string getClientNonce()                                            const     {return getMessageBody("r=", clientFirstMessageBare);}
        std::string getServiceNonce()                                           const     {return getMessageBody("r=", serviceFirstMessage);}
        std::string getVerification(std::string const& message)                 const     {return getMessageBody("v=", message);}
        std::string getProofFromClinet(std::string const& message)              const     {return getMessageBody("p=", message);}
        std::string normalize(std::string const& text)                          const     {return text;}

        std::string getClientFinalMessageWithoutProof()                         const     {return "c=biws,r=" + getServiceNonce();}
        std::string getAuthMessage()                                            const     {return clientFirstMessageBare + "," + serviceFirstMessage + "," + getClientFinalMessageWithoutProof();}

        std::string const& getClientFirstMessageBare()                          const     {return clientFirstMessageBare;}
        std::string const& getClientProof()                                     const     {return clientProof64;}
        std::string const& getServerSignature()                                 const     {return serverSignature64;}

        bool validateNonce(std::string const& message)                          const     {return getServiceNonce() == getMessageBody("r=", message);}
        void setServiceFirstMessage(std::string const& sfm)                               {serviceFirstMessage = sfm;}

        std::string generateNonce()                                                       {return nonceGenerator();}

        using HashDigest        = typename H::DigestStore;
        void calculateClientScramHash(std::string const& password)
        {
            Digest<Hi>      saltedPassword;
            Digest<HMAC>    clientKey;
            Digest<HMAC>    serverKey;
            Digest<HMAC>    clientSignature;
            Digest<HMAC>    serverSignature;
            Digest<H>       storedKey;

            using namespace std::literals;
            std::string    saltBase64      = getServiceSalt();
            std::string    salt              (make_decode64(std::begin(saltBase64)), make_decode64(std::end(saltBase64)));
            std::string    authMessage     = getAuthMessage();

            Hi::hash(normalize(password), salt, getServiceIteration(), saltedPassword);
            HMAC::hash(saltedPassword.view(), "Client Key"s, clientKey);
            HMAC::hash(saltedPassword.view(), "Server Key"s, serverKey);
            H::hash(clientKey, storedKey);
            HMAC::hash(storedKey.view(), authMessage, clientSignature);
            HMAC::hash(serverKey.view(), authMessage, serverSignature);

            for (std::size_t loop = 0 ; loop < HMAC::digestSize; ++loop)
            {
                clientKey[loop] = clientKey[loop] ^ clientSignature[loop];
            }
            clientProof64     = std::string(make_encode64(std::begin(clientKey)), make_encode64(std::end(clientKey)));
            serverSignature64 = std::string(make_encode64(std::begin(serverSignature)), make_encode64(std::end(serverSignature)));
        }
};

template<typename Hi, typename HMAC, typename H>
class ScramClient: public ScramBase<Hi, HMAC, H>
{
    using Base = ScramBase<Hi, HMAC, H>;
    public:
        ScramClient(std::string const& userName, NonceGenerator&& nonceGenerator)
            : Base(std::string("n=") + userName + ",r=" + nonceGenerator(), std::move(nonceGenerator))
        {
#if defined(DEBUG)
            std::cerr << "ScramClient: user:  >" << userName << "<\n";
            std::cerr << "ScramClient: Nonce: >fyko+d2lbbFgONRv9qkxdawL< Check >" << this->generateNonce() << "<\n";;
#endif
        }
        std::string getFirstMessage()
        {
            using namespace std::literals;
            std::string fm = "n,,"s + Base::getClientFirstMessageBare();
#if defined(DEBUG)
            std::cerr << "ScramClient: First: >" << fm << "<\n";
#endif
            return fm;
        }
        std::string getProofMessage(std::string const& password, std::string const& sfm)
        {
            using namespace std::literals;
            Base::setServiceFirstMessage(sfm);
            Base::calculateClientScramHash(password);
            std::string prof = Base::getClientFinalMessageWithoutProof() + ",p="s + Base::getClientProof();
#if defined(DEBUG)
            std::cerr << "ScramClient: pass:  >" << password << "<\n";
            std::cerr << "ScramClient: sfm:   >" << sfm << "<\n";
            std::cerr << "ScramClient: Proof: >" << prof << "<\n";
#endif
            return prof;
        }
        bool verifyServer(std::string const& serverProof)
        {
            return Base::getServerSignature() == Base::getVerification(serverProof);
        }
};

template<typename Hi, typename HMAC, typename H>
class ScramServer: public ScramBase<Hi, HMAC, H>
{
    using Base = ScramBase<Hi, HMAC, H>;

    long            iterationCount;
    DBInfoAccess    dbInfo;

    public:
        ScramServer(std::string const& clientFirstMessage,
                    std::size_t iterationCount = 4096,
                    NonceGenerator&& nonceGenerator = [](){return "3rfcNHYJY1ZVvWVs7j";},
                    DBInfoAccess&&   dbInfo         = [](DBInfoType type, std::string const& /*user*/){return type == DBInfoType::Password ? "pencil" : "QSXCR+Q6sek8bf92";})
            : Base(clientFirstMessage.substr(3), std::move(nonceGenerator))
            , iterationCount(iterationCount)
            , dbInfo(std::move(dbInfo))
        {
#if defined(DEBUG)
            std::cerr << "ScramServer: C First: >" << clientFirstMessage << "<\n";
            std::cerr << "ScramServer: Iter:    >" << iterationCount << "\n";
            std::cerr << "ScramServer: Nonce:   >3rfcNHYJY1ZVvWVs7j< Check >" << this->generateNonce() << "<\n";;
#endif
        }
        std::string getFirstMessage()
        {
            using namespace std::literals;
            std::string message = "r="s + Base::getClientNonce() + Base::generateNonce() + ",s="s + dbInfo(DBInfoType::Salt, Base::getUserFromMessage()) + ",i="s + std::to_string(iterationCount);
            Base::setServiceFirstMessage(message);
#if defined(DEBUG)
            std::cerr << "ScramServer: First: >" << message << "<\n";
#endif
            return message;
        }
        std::string getProofMessage(std::string const& clientProof)
        {
            using namespace std::literals;
#if defined(DEBUG)
            std::cerr << "ScramServer: C Prof:  >" << clientProof << "<\n";
#endif
            Base::calculateClientScramHash(Base::normalize(dbInfo(DBInfoType::Password, Base::getUserFromMessage())));
            if (Base::getClientProof() == Base::getProofFromClinet(clientProof)  && Base::validateNonce(clientProof))
            {
                std::string prof = "v="s + Base::getServerSignature();
#if defined(DEBUG)
                std::cerr << "ScramServer: C Prrof: >" << prof << "<\n";
#endif
                return prof;
            }
#if defined(DEBUG)
            std::cerr << "ScramServer: Proof:   >XXXXXXX<\n";
#endif
            return "";
        }
};

using ScramClientSha1   = ScramClient<Pbkdf2<HMac<Sha1>>, HMac<Sha1>, Sha1>;
using ScramServerSha1   = ScramServer<Pbkdf2<HMac<Sha1>>, HMac<Sha1>, Sha1>;
using ScramClientSha256 = ScramClient<Pbkdf2<HMac<Sha256>>, HMac<Sha256>, Sha256>;
using ScramServerSha256 = ScramServer<Pbkdf2<HMac<Sha256>>, HMac<Sha256>, Sha256>;
}

#endif
