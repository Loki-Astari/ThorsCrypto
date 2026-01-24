CONFIG_NAME					= ThorsCrypto
THORSANVIL_ROOT				?= $(realpath ../../)
TARGET						= ThorsCrypto.head
NAMESPACE					= ThorsAnvil::Crypto


LDLIBS_EXTERN_BUILD			+= crypto ThorSerialize
LINK_LIBS					+= ThorsLogging

CRYPTO_WARNINGS_Darwin		+= -Wno-deprecated-declarations
CRYPTO_WARNINGS_MINGW64_NT	+= -Wno-deprecated-declarations
CRYPTO_WARNINGS_MSYS_NT		+= -Wno-deprecated-declarations
CRYPTO_WARNINGS_Linux		+= -Wno-missing-braces
CRYPTO_WARNINGS				+= $(CRYPTO_WARNINGS_$(PLATFORM))
FILE_WARNING_FLAGS			+= $(CRYPTO_WARNINGS) -Wno-sometimes-uninitialized
CONAN_FILE_WARNING_FLAGS	+= -Wno-deprecated-declarations

include $(THORSANVIL_ROOT)/build/tools/Makefile

