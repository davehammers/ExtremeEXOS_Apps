
all: $(ALLSUBDIRS)
all: $(APP_OBJ)

# is APP defined by the Makefile
ifdef APP
ARTIFACT_TAR = $(APP).tar
# is APP_SRC defined to grep for the version string
ifdef APP_SRC

test_release release: VERSION = $(shell grep '_version_.*=' $(APP_SRC) | cut -d\' -f2)

ifdef APP_LST
test_release release: ARTIFACT_LOCAL_LST=$(APP_LST)
else
test_release release: ARTIFACT_LOCAL_LST=$(patsubst %.tar,%.lst,$(ARTIFACT_TAR))
endif

test_release release: CHKMD5_LST=$(shell if [ -f $(ARTIFACT_LOCAL_LST) ]; then md5sum $(ARTIFACT_LOCAL_LST) | cut -f1 -d\  ;fi)
test_release release: CHKSHA_LST=$(shell if [ -f $(ARTIFACT_LOCAL_LST) ]; then shasum -a 1 $(ARTIFACT_LOCAL_LST) | cut -f1 -d\  ;fi)

test_release release: ARTIFACT_UPLOAD_LST=$(patsubst %.tar,%_$(VERSION).lst,$(ARTIFACT_TAR))
test_release release: ARTIFACT_UPLOAD_DIR=$(patsubst %.tar,%,$(ARTIFACT_TAR))
test_release release: ARTIFACT_UPLOAD_TAG=$(patsubst %.tar,%_$(VERSION),$(ARTIFACT_TAR))

test_release: ARTIFACT_UPLOAD_REPO=$(ARTIFACT_TEST_REPO)
release: ARTIFACT_UPLOAD_REPO=$(ARTIFACT_REPO)

.PHONY: release test_release upload_lst upload_tar
test_release: upload_lst
	$(Q)echo $(ARTIFACT_UPLOAD_TAG)

release: upload_lst
	git tag $(ARTIFACT_UPLOAD_TAG)
	git push origin --tags

upload_lst: $(ARTIFACT_LOCAL_LST) upload_tar
	if [ -f $(ARTIFACT_LOCAL_LST) ]; then \
		curl --header "X-Checksum-Sha1:$(CHKSHA_LST)" --header "X-Checksum-MD5:$(CHKMD5_LST)"  -T $(ARTIFACT_LOCAL_LST) "http://engartifacts1.extremenetworks.com:8081/artifactory/$(ARTIFACT_UPLOAD_REPO)/$(ARTIFACT_UPLOAD_DIR)/lst/$(ARTIFACT_UPLOAD_LST)";\
	fi

upload_tar: $(ARTIFACT_TAR)
	if [ -f $(ARTIFACT_TAR) ]; then \
		$(APP_TOOLS_UPLOAD_ARTIFACT) -f $(ARTIFACT_TAR) -v $(VERSION) -r $(ARTIFACT_UPLOAD_REPO);\
	fi
endif
endif

release: $(RELEASEDIRS)
test_release: $(TEST_RELEASEDIRS)


$(ARTIFACT_TAR): $(ARTIFACT_TAR_SRC)
	tar -cvf $@ $?

%.pyc : %.py
	$(HOST_PYTHON) -m compileall -q -l -d $(@D) $< 

%.lst : %.py
	tar -cvf $@ $?

clean:: $(CLEANDIRS)
	$(RM) $(ARTIFACT_TAR) $(APP_OBJ)

$(ALLSUBDIRS):
	$(MAKE) -C $(@D)

$(CLEANDIRS) $(RELEASEDIRS) $(TEST_RELEASEDIRS):
	$(MAKE) $(@F) -C $(@D)
