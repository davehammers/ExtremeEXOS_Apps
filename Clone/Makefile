include ../defs.mk
APP=clone
ARTIFACT_TAR_SRC = $(APP).py

APP_SRC = \
	clone.py


PY_OBJ = $(APP_SRC:.py=.pyc)

PY_DOWNLOAD = clone.lst

.PHONY: all 
all: $(PY_DOWNLOAD)
$(PY_DOWNLOAD): $(PY_OBJ)

clean::
	$(RM) $(PY_DOWNLOAD) $(PY_OBJ)

include ../rules.mk
