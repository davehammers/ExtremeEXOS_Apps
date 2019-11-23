######################################################################
# APPLICATION GIT REPO
######################################################################
TOP_DIR := $(shell z=`pwd`;while true; do if [ -f $$z/defs.mk ]; then echo $$z; break;fi;z=`dirname $$z`; done)


######################################################################
# Application variables
######################################################################
APP_TOOLS = $(TOP_DIR)/tools
APP_TOOLS_UPLOAD_ARTIFACT = $(APP_TOOLS)/artifactory/upload_artifact.py

APP_OBJ = $(APP_SRC:%.py=%.pyc)

######################################################################
# ARTIFACTORY
######################################################################
# DEFAULT APPLICATION ARTIFACTORY
ARTIFACT_REPO = xos-apps-local-snapshots
ARTIFACT_TEST_REPO = xos-apps-local-test

HOST_PYTHON = /usr/bin/env python2.7

# find all of the subdirectories with Makefiles
# make pseudo lists with /clean and /release added
SUBDIRS = $(dir $(wildcard */Makefile))
ALLSUBDIRS = $(addsuffix all, $(SUBDIRS))
CLEANDIRS = $(addsuffix clean, $(SUBDIRS))
RELEASEDIRS = $(addsuffix release, $(filter-out docs/, $(SUBDIRS)))
TEST_RELEASEDIRS = $(addsuffix test_release, $(filter-out docs/, $(SUBDIRS)))
.PHONY: $(SUBDIRS) $(CLEANDIRS) $(RELEASEDIRS) $(TEST_RELEASEDIRS)
