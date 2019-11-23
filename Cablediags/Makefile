include ../defs.mk

all:

APP=cablediag
ARTIFACT_TAR_SRC = $(APP).py

APP_SRC = $(ARTIFACT_TAR_SRC)

PY_DOWNLOAD = $(APP).lst

.PHONY: all 
all: $(PY_DOWNLOAD)
$(PY_DOWNLOAD): $(ARTIFACT_TAR_SRC)

include ../rules.mk
