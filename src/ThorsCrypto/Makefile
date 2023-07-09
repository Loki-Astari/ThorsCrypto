
THORSANVIL_ROOT				?= $(realpath ../../)

TARGET						= ThorsCrypto.head
NAMESPACE					= ThorsAnvil::Crypto

LDLIBS_EXTERN_BUILD			= $(crypto_ROOT_LIB) $(ThorSerialize_ROOT_LIB)

UNITTEST_CXXFLAGS			+= -Wno-deprecated-declarations

include $(THORSANVIL_ROOT)/build/tools/Makefile

