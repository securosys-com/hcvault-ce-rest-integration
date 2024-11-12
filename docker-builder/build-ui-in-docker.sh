#!/bin/bash
echo "Build UI"; 
cd /go/src/ui && npm install -g yarn
cd /go/src && GOOS=${BIN_OS} GOARCH=${BIN_ARCH} make static-dist;
chmod 777 -R /go/src/ui
chmod 777 -R /go/src/http/web_ui
echo "DONE Build UI"; 
