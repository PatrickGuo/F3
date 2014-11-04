noinst_LIBRARIES += hw-lib/libonet.a

hw_lib_libonet_a_SOURCES = \
	hw-lib/nf2_of_api.c	\
	hw-lib/nf2_of_api.h	\
	hw-lib/nf2.h	\
	hw-lib/reg_defines_openflow_switch.h	\
	hw-lib/nf2util.c	\
	hw-lib/nf2util.h



#lib_libonet_a_LIBADD = oflib/ofl-actions.o                       
#hw_lib_nf2_a_CPPFLAGS += -I hw-lib
