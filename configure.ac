AC_INIT([ThorsCrypto], [3.0], [Loki.Astari+ThorsCrypto@gmail.com])
AC_PREREQ([2.65])

AC_CONFIG_MACRO_DIR([build/autotools/m4])
AC_CONFIG_AUX_DIR([build/autotools/build])

AX_THOR_FUNC_INIT_BUILD([ThorsCrypto], [src/ThorsCrypto/scram.h], [20])

AX_THOR_FEATURE_HEADER_ONLY_VARIANT([THORS_CRYPTO])

AX_THOR_CHECK_USE_CRYPTO
AX_THOR_CHECK_USE_THORS_SERIALIZE_HEADER_ONLY
AX_THOR_CHECK_USE_THORS_SERIALIZE

LT_INIT

AX_THOR_FUNC_TERM_BUILD([CRYPTO], [src/ThorsCrypto/ThorsCryptoConfig.h:config.h.in])

AC_OUTPUT
