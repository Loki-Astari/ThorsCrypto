AC_INIT([ThorsCrypto], [3.0], [Loki.Astari+ThorsCrypto@gmail.com])
AC_PREREQ([2.65])

AC_CONFIG_MACRO_DIR([build/autotools/m4])
AC_CONFIG_AUX_DIR([build/autotools/build])

AX_THOR_FUNC_INIT_BUILD([ThorsCrypto], [17], [src/ThorsCrypto/scram.h])

AX_THOR_CHECK_USE_CRYPTO

LT_INIT

AX_THOR_FUNC_TERM_BUILD([CRYPTO], [src/ThorsCrypto/ThorsCryptoConfig.h])

AC_OUTPUT
