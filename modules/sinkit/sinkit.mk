sinkit_CFLAGS := -fvisibility=hidden -fPIC
sinkit_SOURCES := modules/sinkit/oraculum.c modules/sinkit/sinkit.c
sinkit_DEPEND := $(libkres)
sinkit_LIBS := $(contrib_TARGET) $(libkres_TARGET) $(libkres_LIBS)  -lcurl
$(call make_c_module,sinkit)
