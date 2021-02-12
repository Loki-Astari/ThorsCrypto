
THORSANVIL_ROOT				?= $(realpath ../../)

TARGET						= ThorsCrypto.head
LDLIBS_EXTERN_BUILD			= crypto

UNITTEST_CXXFLAGS			+= -Wno-deprecated-declarations
UNITTEST_LINK_LIBS			+= ThorsLogging $(crypto_ROOT_LIB)

include $(THORSANVIL_ROOT)/build/tools/Makefile

