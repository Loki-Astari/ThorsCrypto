
THORSANVIL_ROOT				?= $(realpath ../../)

TARGET						= ThorsCrypto.head
LDLIBS						= -lcrypto
LDFLAGS						= $(crypto_ROOT_LIBDIR)

UNITTEST_CXXFLAGS			+= -Wno-deprecated-declarations

include $(THORSANVIL_ROOT)/build/tools/Makefile

