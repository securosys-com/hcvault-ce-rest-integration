#!/bin/bash
git config --global --add safe.directory /go/src

echo "Build ${ARTIFACT_NAME} in ${BIN_OS}_${BIN_ARCHS}"; 
if [[ "$BIN_OS" == "windows" ]]; then
		for ARCH in ${BIN_ARCHS}; do\
			echo "Build windows in ARCH: ${ARCH}"; \
            cd /go/src && IS_DOCKER=true GOOS=${BIN_OS} GOARCH=${ARCH} make bin; \	
			cp bin/vault builds/vault.exe; \
			chmod 777 -R /go/src/bin; \
            cd builds; \
			zip -9 ${ARTIFACT_NAME}_windows_${ARCH}.zip vault.exe; \
			shasum -a 256 ${ARTIFACT_NAME}_windows_${ARCH}.zip >> ${ARTIFACT_NAME}_SHA256SUMS; \
			cd ..; \
			rm builds/vault.exe; \
		done;
else
		for ARCH in ${BIN_ARCHS}; do\
			echo "Build ${BIN_OS} in ARCH: ${ARCH}"; \
            cd /go/src && IS_DOCKER=true GOOS=${BIN_OS} GOARCH=${ARCH} make bin; \	
			cp bin/vault builds/vault; \
            chmod 777 -R /go/src/bin; \
			cd builds; \
			zip -9 ${ARTIFACT_NAME}_${BIN_OS}_${ARCH}.zip vault; \
			shasum -a 256 ${ARTIFACT_NAME}_${BIN_OS}_${ARCH}.zip >> ${ARTIFACT_NAME}_SHA256SUMS; \
			cd ..; \
			rm builds/vault; \
		done;

fi

echo "END Build ${ARTIFACT_NAME} in ${BIN_OS}_${BIN_ARCHS}"; 




