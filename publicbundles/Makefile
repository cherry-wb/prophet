include config-bundle.mak
include $(S2E_BUILD_PATH)/qemu-release/$(TARGET_DIR)/config-target.mak
include $(S2E_BUILD_PATH)/qemu-release/config-host.mak

CLANG_CC=$(LLVM_BUILD_PATH)/llvm-native/Release/bin/clang
CLANG_CXX=$(LLVM_BUILD_PATH)/llvm-native/Release/bin/clang++
LDFLAGS="-Wl,--warn-common -Wl,-z,relro -Wl,-z,now -pie -m64 -g -rdynamic"

DEFINES= -I. -I../linux-headers -I.. -I/usr/include -I/usr/include/lua5.1 -I/usr/include/sigc++-2.0 -I/usr/lib/x86_64-linux-gnu/sigc++-2.0/include 
DEFINES+= -I$(S2E_BUILD_PATH)/qemu-release/ -I$(S2E_BUILD_PATH)/qemu-release/$(TARGET_DIR) -I$(S2E_SRC_PATH)/qemu/slirp -I. -I$(S2E_SRC_PATH)/qemu -I$(S2E_SRC_PATH)/qemu/fpu -I$(S2E_SRC_PATH)/qemu/linux-headers -I$(S2E_SRC_PATH)/qemu/tcg
DEFINES+= -I$(S2E_SRC_PATH)/qemu/tcg/$(TARGET_BASE_ARCH) -I$(S2E_SRC_PATH)/qemu/target-$(TARGET_BASE_ARCH)
DEFINES+= -I$(S2E_SRC_PATH)/qemu/include -I/usr/include/p11-kit-1     -I/usr/include/libpng12
DEFINES+= -I$(LLVM_BUILD_PATH)/llvm-3.2.src/include -I$(LLVM_BUILD_PATH)/llvm-release/include -I$(S2E_SRC_PATH)/klee/include -I$(S2E_BUILD_PATH)/klee-release/include

DEFINES+= -D__STDC_LIMIT_MACROS -fPIC -DPIE -m64 -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -DNEED_CPU_H -MMD -MP -MT -O2
DEFINES+= -Wall -Wundef -Wwrite-strings -fno-strict-aliasing -fno-common -Wendif-labels -Wmissing-include-dirs -Wempty-body 
DEFINES+= -Wformat-security -Wformat-y2k -Winit-self -Wignored-qualifiers -Wtype-limits -fstack-protector-all -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 
DEFINES+= $(GLIB_CFLAGS) 
DEFINES+=$(LLVM_CXXFLAGS)

CC=$(CLANG_CC)
CPP=$(CLANG_CXX)
CFLAGS=-Wall -O2 -g -fPIC 
LDFLAGS=-g -shared 
LIBS+=

OBJS+= publicbundle.o bundle_interface.o
OBJS+= plugins/SimpleBundlePlugin.o

all: publicbundle.so

SHARED_LIBS+=

%.o: %.c 
	$(CC) $(CFLAGS) $(DEFINES) -c -o $@ $<

%.o: %.cpp
	$(CPP) $(CFLAGS) $(DEFINES) -c -o $@ $<
	
#publicbundle.o: CFLAGS+= --std=c99

publicbundle.so: $(SHARED_LIBS) $(OBJS)
	$(CPP) $(LDFLAGS) $^ -o $@ $(LIBS)
#	ar cru libpublicbundle.a $@

publicbundle-static.so: $(OBJS)
	$(CPP) -static-libgcc -Wl,-static $(LDFLAGS) $^ -o $@ $(LIBS)

clean:
	rm -f *.o *.d *.so *.a *~ plugins/*.o plugins/*.d

realclean:
	rm -f *.o  *.d *.so *.a *~ plugins/*.o plugins/*.d

# Include automatically generated dependency files
-include $(wildcard *.d)

