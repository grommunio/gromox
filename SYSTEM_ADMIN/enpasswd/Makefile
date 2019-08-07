OUTPUT_TYPE=BIN # OBJ, LIB, BIN or SHA
# modify name here for binary excutable file name, if output type is OBJ, 
# no need to specify the output name
OUTPUT_NAME=enpasswd
C_SOURCE_FILES=$(wildcard *.c)
CPP_SOURCE_FILES=$(wildcard *.cxx *.cpp *.C)
INCLUDE_PATHS=../common/include# add include paths here
LIBRARY_PATHS=/usr/lib64/mysql /usr/lib/mysql# add library paths here
LIBRARY_FILES=mysqlclient# add library files here
COMPILING_FLAGS=#add here c or c++ flags for compiling
LINK_FLAGS=$(patsubst %,-L%,$(LIBRARY_PATHS)) $(patsubst %,-l%,$(LIBRARY_FILES)) ../lib/common.so
INCLUDE_PATHS:=$(patsubst %,-I%,$(INCLUDE_PATHS))
MAKE_PATH = ../make_include#indicate location of the make_common.mk

###############################################################################
#                          do not modify below!!!                             #
#                                                                             #
###############################################################################
include $(MAKE_PATH)/make_config.mk
.PHONY : normal
.PHONY : debug
.PHONY : clean
.PHONY : depend
normal :
	@$(ECHO) "C_SOURCE_FILES=$(C_SOURCE_FILES)\nCPP_SOURCE_FILES=$(CPP_SOURCE_FILES)\nOUTPUT_TYPE=$(OUTPUT_TYPE)\nOUTPUT_NAME=$(OUTPUT_NAME)\nINCLUDE_PATHS=$(INCLUDE_PATHS)\nCOMPILING_FLAGS=$(COMPILING_FLAGS)\nLINK_FLAGS=$(LINK_FLAGS)">temp.mk
	$(MAKE) depend
	$(MAKE) -f $(MAKE_PATH)/make_common.mk -I./
debug :
	@$(ECHO) "C_SOURCE_FILES=$(C_SOURCE_FILES)\nCPP_SOURCE_FILES=$(CPP_SOURCE_FILES)\nOUTPUT_TYPE=$(OUTPUT_TYPE)\nOUTPUT_NAME=$(OUTPUT_NAME)\nINCLUDE_PATHS=$(INCLUDE_PATHS)\nCOMPILING_FLAGS=$(COMPILING_FLAGS)\nLINK_FLAGS=$(LINK_FLAGS)">temp.mk
	$(MAKE) depend
	$(MAKE) -f $(MAKE_PATH)/make_common.mk -I./ "DEBUG=-g"
depend :
	touch depend.mk
	$(MAKEDEPEND) $(INCLUDE_PATHS) $(CPP_SOURCE_FILES) $(C_SOURCE_FILES) -f depend.mk
	rm depend.mk.bak
clean :
	-@rm *.o $(OUTPUT_NAME) depend.mk temp.mk 1>/dev/null 2>&1
