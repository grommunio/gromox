OUTPUT_NAME=exchange_emsmdb.proc# modify name here for binary excutable file name
HARDLNK_LIBS=#add here the hard link libraries here
LIBRARY_PATHS=# add library paths here
LIBRARY_FILES=# add library files here
LINK_FLAGS=$(patsubst %,-L%,$(LIBRARY_PATHS)) $(patsubst %,-l%,$(LIBRARY_FILES))
SCRIPTS_PATH=../../scripts

.PHONY : normal
.PHONY : debug
.PHONY : link
.PHONY : clean
.PHONY : $(OUTPUT_NAME)
	
normal : $(OUTPUT_NAME)
	@$(SCRIPTS_PATH)/compile normal
	$(SCRIPTS_PATH)/lnksha $(OUTPUT_NAME) $(LINK_FLAGS) $(HARDLNK_LIBS)
debug : $(OUTPUT_NAME)
	@$(SCRIPTS_PATH)/compile debug
	$(SCRIPTS_PATH)/lnksha $(OUTPUT_NAME) $(LINK_FLAGS) $(HARDLNK_LIBS)
link : $(OUTPUT_NAME)
	$(SCRIPTS_PATH)/lnksha $(OUTPUT_NAME) $(LINK_FLAGS) $(HARDLNK_LIBS)
clean :
	@$(SCRIPTS_PATH)/compile clean
	-@rm $(OUTPUT_NAME) 1>/dev/null 2>&1
