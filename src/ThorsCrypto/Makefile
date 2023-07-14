
THORSANVIL_ROOT				?= $(realpath ../../)

TARGET						= ThorsCrypto.head
NAMESPACE					= ThorsAnvil::Crypto

LDLIBS_EXTERN_BUILD			= $(crypto_ROOT_LIB) $(ThorSerialize_ROOT_LIB)

CRYPTO_WARNINGS_Darwin		= -Wno-deprecated-declarations
CRYPTO_WARNINGS_Linux		= -Wno-missing-braces
CRYPTO_WARNINGS				= $(CRYPTO_WARNINGS_$(PLATFORM))
FILE_WARNING_FLAGS			+= $(CRYPTO_WARNINGS)

include $(THORSANVIL_ROOT)/build/tools/Makefile

