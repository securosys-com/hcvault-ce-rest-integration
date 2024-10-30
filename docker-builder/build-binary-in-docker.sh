#!/bin/bash
echo "Build ${ARTIFACT_NAME} in ${BIN_OS}_${BIN_ARCH}"; 
echo "Build Binary"

git config --global --add safe.directory /go/src
chmod 777 -R /go/src/bin
cd /go/src && IS_DOCKER=true GOOS=${BIN_OS} GOARCH=${BIN_ARCH} make bin	    

echo "END Build Binary"
