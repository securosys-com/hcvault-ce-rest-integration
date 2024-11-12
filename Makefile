#Artifactory vars
IMAGE_NAME = hcvault-ce-rest-integration:$(VERSION)
ARTIFACTORY_NAME = securosys.jfrog.io/$(INTERNAL_PREFIX)hcvault-ce-rest-integration/
ARTIFACT_NAME = HCVault_CE-Rest-Integration
TEST_RESULT_PATH = $(PWD)/
ifneq ($(FDB_ENABLED), )
	CGO_ENABLED=1
	BUILD_TAGS+=foundationdb
endif
GOPATH=`go env GOPATH`
ifneq ($(IS_DOCKER), )
	GOPATH=/go
endif
#For test config
export CONFIG_HSM_PATH = $(PWD)/hsm
# Determine this makefile's path.
# Be sure to place this BEFORE `include` directives, if any.
THIS_FILE := $(lastword $(MAKEFILE_LIST))

TEST?=$$($(GO_CMD) list ./... | grep -v /vendor/ | grep -v /integ)
TEST_TIMEOUT?=45m
EXTENDED_TEST_TIMEOUT=60m
INTEG_TEST_TIMEOUT=120m
VETARGS?=-asmdecl -atomic -bool -buildtags -copylocks -methods -nilfunc -printf -rangeloops -shift -structtags -unsafeptr
EXTERNAL_TOOLS_CI=\
	golang.org/x/tools/cmd/goimports \
	github.com/golangci/revgrep/cmd/revgrep \
	mvdan.cc/gofumpt \
	honnef.co/go/tools/cmd/staticcheck \
	github.com/bufbuild/buf/cmd/buf
EXTERNAL_TOOLS=\
	github.com/client9/misspell/cmd/misspell
GOFMT_FILES?=$$(find . -name '*.go' | grep -v pb.go | grep -v vendor)
SED?=$(shell command -v gsed || command -v sed)

GO_VERSION_MIN=$$(cat $(CURDIR)/.go-version)
GO_CMD?=go
CGO_ENABLED?=0
ifneq ($(FDB_ENABLED), )
	CGO_ENABLED=1
	BUILD_TAGS+=foundationdb
endif

default: dev

# bin generates the releasable binaries for Vault
bin: prep
	@CGO_ENABLED=$(CGO_ENABLED) BUILD_TAGS='$(BUILD_TAGS) ui' sh -c "'$(CURDIR)/scripts/build.sh'"

# dev creates binaries for testing Vault locally. These are put
# into ./bin/ as well as $GOPATH/bin
dev: BUILD_TAGS+=testonly
dev: prep
	@CGO_ENABLED=$(CGO_ENABLED) BUILD_TAGS='$(BUILD_TAGS)' VAULT_DEV_BUILD=1 sh -c "'$(CURDIR)/scripts/build.sh'"
dev-ui: BUILD_TAGS+=testonly
dev-ui: assetcheck prep
	@CGO_ENABLED=$(CGO_ENABLED) BUILD_TAGS='$(BUILD_TAGS) ui' VAULT_DEV_BUILD=1 sh -c "'$(CURDIR)/scripts/build.sh'"
dev-dynamic: BUILD_TAGS+=testonly
dev-dynamic: prep
	@CGO_ENABLED=1 BUILD_TAGS='$(BUILD_TAGS)' VAULT_DEV_BUILD=1 sh -c "'$(CURDIR)/scripts/build.sh'"

# *-mem variants will enable memory profiling which will write snapshots of heap usage
# to $TMP/vaultprof every 5 minutes. These can be analyzed using `$ go tool pprof <profile_file>`.
# Note that any build can have profiling added via: `$ BUILD_TAGS=memprofiler make ...`
dev-mem: BUILD_TAGS+=memprofiler
dev-mem: dev
dev-ui-mem: BUILD_TAGS+=memprofiler
dev-ui-mem: assetcheck dev-ui
dev-dynamic-mem: BUILD_TAGS+=memprofiler
dev-dynamic-mem: dev-dynamic

release:	
		rm -rf builds
		
		@if [ "$(RELEASE_ALL)" != "1" ]; then\
			BIN_OS=linux BIN_ARCH=amd64 make docker-ui-build ; \
		fi;

		mkdir builds
		for ARCH in amd64 arm64; do\
			echo "Build MacOS in ARCH: $${ARCH}"; \
			BIN_OS=darwin BIN_ARCH="$${ARCH}" make docker-binary-build; \
			cp bin/vault builds/vault; \
			cd builds; \
			zip -9 $(ARTIFACT_NAME)_darwin_$${ARCH}.zip vault; \
			shasum -a 256 $(ARTIFACT_NAME)_darwin_$${ARCH}.zip >> $(ARTIFACT_NAME)_SHA256SUMS; \
			cd ..; \
			rm builds/vault; \
		done;
		for ARCH in 386 amd64; do\
			echo "Build Windows in ARCH: $${ARCH}"; \
			BIN_OS=windows BIN_ARCH="$${ARCH}" make docker-binary-build; \
			cp bin/vault builds/vault.exe; \
			cd builds; \
			zip -9 $(ARTIFACT_NAME)_windows_$${ARCH}.zip vault.exe; \
			shasum -a 256 $(ARTIFACT_NAME)_windows_$${ARCH}.zip >> $(ARTIFACT_NAME)_SHA256SUMS; \
			cd ..; \
			rm builds/vault.exe; \
		done;
		for ARCH in 386 amd64 arm arm64; do\
			echo "Build Linux in ARCH: $${ARCH}"; \
			BIN_OS=linux BIN_ARCH="$${ARCH}" make docker-binary-build; \
			cp bin/vault builds/vault; \
			cd builds; \
			zip -9 $(ARTIFACT_NAME)_linux_$${ARCH}.zip vault; \
			shasum -a 256 $(ARTIFACT_NAME)_linux_$${ARCH}.zip >> $(ARTIFACT_NAME)_SHA256SUMS; \
			cd ..; \
			rm builds/vault; \
		done;
		for ARCH in 386 amd64 arm; do\
			echo "Build FreeBSD in ARCH: $${ARCH}"; \
			BIN_OS=freebsd BIN_ARCH="$${ARCH}" make docker-binary-build; \
			cp bin/vault builds/vault; \
			cd builds; \
			zip -9 $(ARTIFACT_NAME)_freebsd_$${ARCH}.zip vault; \
			shasum -a 256 $(ARTIFACT_NAME)_freebsd_$${ARCH}.zip >> $(ARTIFACT_NAME)_SHA256SUMS; \
			cd ..; \
			rm builds/vault; \
		done;
		for ARCH in 386 amd64 arm; do\
			echo "Build NetBSD in ARCH: $${ARCH}"; \
			BIN_OS=netbsd BIN_ARCH="$${ARCH}" make docker-binary-build; \
			cp bin/vault builds/vault; \
			cd builds; \
			zip -9 $(ARTIFACT_NAME)_netbsd_$${ARCH}.zip vault; \
			shasum -a 256 $(ARTIFACT_NAME)_netbsd_$${ARCH}.zip >> $(ARTIFACT_NAME)_SHA256SUMS; \
			cd ..; \
			rm builds/vault; \
		done;
		for ARCH in 386 amd64 arm; do\
			echo "Build OpenBSD in ARCH: $${ARCH}"; \
			BIN_OS=openbsd BIN_ARCH="$${ARCH}" make docker-binary-build; \
			cp bin/vault builds/vault; \
			cd builds; \
			zip -9 $(ARTIFACT_NAME)_openbsd_$${ARCH}.zip vault; \
			shasum -a 256 $(ARTIFACT_NAME)_openbsd_$${ARCH}.zip >> $(ARTIFACT_NAME)_SHA256SUMS; \
			cd ..; \
			rm builds/vault; \
		done;

release-new:	
		rm -rf builds
		
		@if [ "$(RELEASE_ALL)" != "1" ]; then\
			BIN_OS=linux BIN_ARCH=amd64 make docker-ui-build ; \
		fi;

		mkdir builds
		BIN_OS=darwin BIN_ARCHS="amd64 arm64" make docker-binaries-build
		BIN_OS=windows BIN_ARCHS="386 amd64" make docker-binaries-build
		BIN_OS=linux BIN_ARCHS="386 amd64 arm arm64" make docker-binaries-build
		BIN_OS=freebsd BIN_ARCHS="386 amd64 arm" make docker-binaries-build
		BIN_OS=netbsd BIN_ARCHS="386 amd64 arm" make docker-binaries-build
		BIN_OS=openbsd BIN_ARCHS="386 amd64 arm" make docker-binaries-build

release-all:
	make clean
	make docker-ui-build BIN_OS=linux BIN_ARCH=amd64
	
	make docker VERSION=${VERSION} RELEASE_ALL=1
	make release-new VERSION=${VERSION}  RELEASE_ALL=1

# Creates a Docker image by adding the compiled linux/amd64 binary found in ./bin.
clean-docker:
	rm -rf buildDocker

docker-ui-build:
	docker compose -f docker-builder/docker-compose.yml run -e ARTIFACT_NAME=${ARTIFACT_NAME} -e BIN_ARCH=${BIN_ARCH} -e BIN_OS=${BIN_OS} hcvault_ui_builder
	docker compose -f docker-builder/docker-compose.yml down --remove-orphans --rmi all
	docker volume prune -f
	docker container prune -f
docker-binaries-build:
	docker compose -f docker-builder/docker-compose.yml run -e ARTIFACT_NAME=${ARTIFACT_NAME} -e BIN_ARCHS="${BIN_ARCHS}" -e BIN_OS=${BIN_OS} hcvault_binaries_builder
	docker compose -f docker-builder/docker-compose.yml down --remove-orphans --rmi all
	docker volume prune -f
	docker container prune -f

docker-binary-build:
	docker compose -f docker-builder/docker-compose.yml run -e ARTIFACT_NAME=${ARTIFACT_NAME} -e BIN_ARCH=${BIN_ARCH} -e BIN_OS=${BIN_OS} hcvault_binary_builder
	docker compose -f docker-builder/docker-compose.yml down --remove-orphans --rmi all
	docker volume prune -f
	docker container prune -f

docker:
	
	rm -rf buildDocker
	mkdir buildDocker
	make docker-ui-build BIN_OS=linux BIN_ARCH=amd64
	make docker-binary-build BIN_OS=linux BIN_ARCH=amd64
    
	docker build . -t "$(ARTIFACTORY_NAME)$(IMAGE_NAME)"
	docker save "$(ARTIFACTORY_NAME)$(IMAGE_NAME)"| gzip -f > "buildDocker/$(IMAGE_NAME)_docker.tar.gz"
	cd buildDocker && shasum -a 256 "$(IMAGE_NAME)_docker.tar.gz" >> "$(IMAGE_NAME)_docker_SHA256SUM";

rem_image:
	docker rm -f $$(docker ps -a -q --filter='ancestor=$(IMAGE_ID)') 2> /dev/null || true
	docker image rm $$(docker images --filter since=$(IMAGE_ID) -q) -f 2> /dev/null || true
	docker image rm -f $(IMAGE_ID)

docker_clean:
	 for ID in $$(docker images | grep $(IMAGE_NAME) | awk '{ print $$3}'); do\
        echo "Removing... "$${ID}; \
        make rem_image IMAGE_ID="$${ID}"; \
      done;

clean-images:
	make docker_clean IMAGE_NAME=vault_radiusd_any_client
	make docker_clean IMAGE_NAME=docker.mirror.hashicorp.services/library/consul
	make docker_clean IMAGE_NAME=docker.mirror.hashicorp.services/multani/nomad
	make docker_clean IMAGE_NAME=docker.mirror.hashicorp.services/postgres
	make docker_clean IMAGE_NAME=docker.mirror.hashicorp.services/library/mysql
	make docker_clean IMAGE_NAME=docker.mirror.hashicorp.services/michelvocks/docker-test-openldap
	make docker_clean IMAGE_NAME=docker.mirror.hashicorp.services/jumanjiman/radiusd
	make docker_clean IMAGE_NAME=ubuntu/bind9
	make docker_clean IMAGE_NAME=docker.mirror.hashicorp.services/library/golang
	make docker_clean IMAGE_NAME=vault_pki_zlint_validator
	make docker_clean IMAGE_NAME=docker.mirror.hashicorp.services/linuxserver/openssh-server
	make docker_clean IMAGE_NAME=docker.mirror.hashicorp.services/library/couchdb
	make docker_clean IMAGE_NAME=docker.mirror.hashicorp.services/cockroachdb/cockroach
	make docker_clean IMAGE_NAME=hashicorp/vault-enterprise

	docker volume prune -f
	docker container prune -f
	docker network prune -f

clean:
	rm -rf builds
	rm -rf buildDocker
	make clean-images	
	
# test runs the unit tests and vets the code
test: BUILD_TAGS+=testonly
test: prep
	go install github.com/jstemmer/go-junit-report/v2@latest
	@CGO_ENABLED=$(CGO_ENABLED) \
	VAULT_ADDR= \
	VAULT_TOKEN= \
	VAULT_DEV_ROOT_TOKEN_ID= \
	VAULT_ACC= \
	$(GO_CMD) test -tags='unit integration' -timeout=360m -parallel=20 2>&1 ./... | ${GOPATH}/bin/go-junit-report -iocopy -out ${TEST_RESULT_PATH}junit_report_all.xml -set-exit-code
	make clean-images
	
test-securosys-hsm: prep
	go install github.com/jstemmer/go-junit-report/v2@latest
	cd hsm && $(GO_CMD) test -count=1 -tags='unit integration' -v -timeout 1m 2>&1 ./... | ${GOPATH}/bin/go-junit-report -iocopy -out ${TEST_RESULT_PATH}junit_report_hsm.xml -set-exit-code

testcompile: prep
	@for pkg in $(TEST) ; do \
		$(GO_CMD) test -v -c -tags='$(BUILD_TAGS)' $$pkg -parallel=4 ; \
	done

# testacc runs acceptance tests
testacc: BUILD_TAGS+=testonly
testacc: prep
	@if [ "$(TEST)" = "./..." ]; then \
		echo "ERROR: Set TEST to a specific package"; \
		exit 1; \
	fi
	VAULT_ACC=1 $(GO_CMD) test -tags='$(BUILD_TAGS)' $(TEST) -v $(TESTARGS) -timeout=$(EXTENDED_TEST_TIMEOUT)

# testrace runs the race checker
testrace: BUILD_TAGS+=testonly
testrace: prep
	@CGO_ENABLED=1 \
	VAULT_ADDR= \
	VAULT_TOKEN= \
	VAULT_DEV_ROOT_TOKEN_ID= \
	VAULT_ACC= \
	$(GO_CMD) test -tags='$(BUILD_TAGS)' -race $(TEST) $(TESTARGS) -timeout=$(EXTENDED_TEST_TIMEOUT) -parallel=20

cover:
	./scripts/coverage.sh --html

# vet runs the Go source code static analysis tool `vet` to find
# any common errors.
vet:
	@$(GO_CMD) list -f '{{.Dir}}' ./... | grep -v /vendor/ \
		| grep -v '.*github.com/hashicorp/vault$$' \
		| xargs $(GO_CMD) vet ; if [ $$? -eq 1 ]; then \
			echo ""; \
			echo "Vet found suspicious constructs. Please check the reported constructs"; \
			echo "and fix them if necessary before submitting the code for reviewal."; \
		fi

# deprecations runs staticcheck tool to look for deprecations. Checks entire code to see if it
# has deprecated function, variable, constant or field
deprecations: bootstrap prep
	@BUILD_TAGS='$(BUILD_TAGS)' ./scripts/deprecations-checker.sh ""

# ci-deprecations runs staticcheck tool to look for deprecations. All output gets piped to revgrep
# which will only return an error if changes that is not on main has deprecated function, variable, constant or field
ci-deprecations: ci-bootstrap prep
	@BUILD_TAGS='$(BUILD_TAGS)' ./scripts/deprecations-checker.sh main

tools/codechecker/.bin/codechecker:
	@cd tools/codechecker && $(GO_CMD) build -o .bin/codechecker .

# vet-codechecker runs our custom linters on the test functions. All output gets
# piped to revgrep which will only return an error if new piece of code violates
# the check
vet-codechecker: bootstrap tools/codechecker/.bin/codechecker prep
	@$(GO_CMD) vet -vettool=./tools/codechecker/.bin/codechecker -tags=$(BUILD_TAGS) ./... 2>&1 | revgrep

# vet-codechecker runs our custom linters on the test functions. All output gets
# piped to revgrep which will only return an error if new piece of code that is
# not on main violates the check
ci-vet-codechecker: ci-bootstrap tools/codechecker/.bin/codechecker prep
	@$(GO_CMD) vet -vettool=./tools/codechecker/.bin/codechecker -tags=$(BUILD_TAGS) ./... 2>&1 | revgrep origin/main

# lint runs vet plus a number of other checkers, it is more comprehensive, but louder
lint:
	@$(GO_CMD) list -f '{{.Dir}}' ./... | grep -v /vendor/ \
		| xargs golangci-lint run; if [ $$? -eq 1 ]; then \
			echo ""; \
			echo "Lint found suspicious constructs. Please check the reported constructs"; \
			echo "and fix them if necessary before submitting the code for reviewal."; \
		fi
# for ci jobs, runs lint against the changed packages in the commit
ci-lint:
	@golangci-lint run --deadline 10m --new-from-rev=HEAD~

# Lint protobuf files
protolint: ci-bootstrap
	buf lint

# prep runs `go generate` to build the dynamically generated
# source files.
#
# n.b.: prep used to depend on fmtcheck, but since fmtcheck is
# now run as a pre-commit hook (and there's little value in
# making every build run the formatter), we've removed that
# dependency.
prep:
	$(GO_CMD) mod tidy
	@GOARCH= GOOS= $(GO_CMD) generate $$($(GO_CMD) list ./... | grep -v /vendor/)

# bootstrap the build by downloading additional tools needed to build
ci-bootstrap: .ci-bootstrap
.ci-bootstrap:
	@for tool in  $(EXTERNAL_TOOLS_CI) ; do \
		echo "Installing/Updating $$tool" ; \
		GO111MODULE=off $(GO_CMD) get -u $$tool; \
	done
	@touch .ci-bootstrap

# bootstrap the build by downloading additional tools that may be used by devs
bootstrap: ci-bootstrap
	go generate -tags tools tools/tools.go
	go install github.com/bufbuild/buf/cmd/buf@v1.25.0

# Note: if you have plugins in GOPATH you can update all of them via something like:
# for i in $(ls | grep vault-plugin-); do cd $i; git remote update; git reset --hard origin/master; dep ensure -update; git add .; git commit; git push; cd ..; done
update-plugins:
	grep vault-plugin- go.mod | cut -d ' ' -f 1 | while read -r P; do echo "Updating $P..."; go get -v "$P"; done

static-assets-dir:
	@mkdir -p ./http/web_ui

install-ui-dependencies:
	@echo "--> Installing JavaScript assets"
	@cd ui && yarn

test-ember: install-ui-dependencies
	@echo "--> Running ember tests"
	@cd ui && yarn run test:oss

test-ember-enos: install-ui-dependencies
	@echo "--> Running ember tests with a real backend"
	@cd ui && yarn run test:enos

check-vault-in-path:
	@VAULT_BIN=$$(command -v vault) || { echo "vault command not found"; exit 1; }; \
		[ -x "$$VAULT_BIN" ] || { echo "$$VAULT_BIN not executable"; exit 1; }; \
		printf "Using Vault at %s:\n\$$ vault version\n%s\n" "$$VAULT_BIN" "$$(vault version)"

ember-dist: install-ui-dependencies
	@cd ui && npm rebuild node-sass
	@echo "--> Building Ember application"
	@cd ui && yarn run build
	@rm -rf ui/if-you-need-to-delete-this-open-an-issue-async-disk-cache

ember-dist-dev: install-ui-dependencies
	@cd ui && npm rebuild node-sass
	@echo "--> Building Ember application"
	@cd ui && yarn run build:dev

static-dist: ember-dist
static-dist-dev: ember-dist-dev

proto: bootstrap
	buf generate

	# No additional sed expressions should be added to this list. Going forward
	# we should just use the variable names choosen by protobuf. These are left
	# here for backwards compatability, namely for SDK compilation.
	$(SED) -i -e 's/Id/ID/' -e 's/SPDX-License-IDentifier/SPDX-License-Identifier/' vault/request_forwarding_service.pb.go
	$(SED) -i -e 's/Idp/IDP/' -e 's/Url/URL/' -e 's/Id/ID/' -e 's/IDentity/Identity/' -e 's/EntityId/EntityID/' -e 's/Api/API/' -e 's/Qr/QR/' -e 's/Totp/TOTP/' -e 's/Mfa/MFA/' -e 's/Pingid/PingID/' -e 's/namespaceId/namespaceID/' -e 's/Ttl/TTL/' -e 's/BoundCidrs/BoundCIDRs/' -e 's/SPDX-License-IDentifier/SPDX-License-Identifier/' helper/identity/types.pb.go helper/identity/mfa/types.pb.go helper/storagepacker/types.pb.go sdk/plugin/pb/backend.pb.go sdk/logical/identity.pb.go vault/activity/activity_log.pb.go

	# This will inject the sentinel struct tags as decorated in the proto files.
	protoc-go-inject-tag -input=./helper/identity/types.pb.go
	protoc-go-inject-tag -input=./helper/identity/mfa/types.pb.go

fmtcheck:
	@sh -c "'$(CURDIR)/scripts/gofmtcheck.sh'"

fmt: ci-bootstrap
	find . -name '*.go' | grep -v pb.go | grep -v vendor | xargs go run mvdan.cc/gofumpt -w

protofmt: ci-bootstrap
	buf format -w

semgrep:
	semgrep --include '*.go' --exclude 'vendor' -a -f tools/semgrep .

semgrep-ci:
	semgrep --error --include '*.go' --exclude 'vendor' -f tools/semgrep/ci .

assetcheck:
	@echo "==> Checking compiled UI assets..."
	@sh -c "'$(CURDIR)/scripts/assetcheck.sh'"

spellcheck:
	@echo "==> Spell checking website..."
	@misspell -error -source=text website/source

mysql-database-plugin:
	@CGO_ENABLED=0 $(GO_CMD) build -o bin/mysql-database-plugin ./plugins/database/mysql/mysql-database-plugin

mysql-legacy-database-plugin:
	@CGO_ENABLED=0 $(GO_CMD) build -o bin/mysql-legacy-database-plugin ./plugins/database/mysql/mysql-legacy-database-plugin

cassandra-database-plugin:
	@CGO_ENABLED=0 $(GO_CMD) build -o bin/cassandra-database-plugin ./plugins/database/cassandra/cassandra-database-plugin

influxdb-database-plugin:
	@CGO_ENABLED=0 $(GO_CMD) build -o bin/influxdb-database-plugin ./plugins/database/influxdb/influxdb-database-plugin

postgresql-database-plugin:
	@CGO_ENABLED=0 $(GO_CMD) build -o bin/postgresql-database-plugin ./plugins/database/postgresql/postgresql-database-plugin

mssql-database-plugin:
	@CGO_ENABLED=0 $(GO_CMD) build -o bin/mssql-database-plugin ./plugins/database/mssql/mssql-database-plugin

hana-database-plugin:
	@CGO_ENABLED=0 $(GO_CMD) build -o bin/hana-database-plugin ./plugins/database/hana/hana-database-plugin

mongodb-database-plugin:
	@CGO_ENABLED=0 $(GO_CMD) build -o bin/mongodb-database-plugin ./plugins/database/mongodb/mongodb-database-plugin

.PHONY: bin default prep test vet bootstrap ci-bootstrap fmt fmtcheck mysql-database-plugin mysql-legacy-database-plugin cassandra-database-plugin influxdb-database-plugin postgresql-database-plugin mssql-database-plugin hana-database-plugin mongodb-database-plugin ember-dist ember-dist-dev static-dist static-dist-dev assetcheck check-vault-in-path packages build build-ci semgrep semgrep-ci vet-codechecker ci-vet-codechecker

.NOTPARALLEL: ember-dist ember-dist-dev

# These ci targets are used for used for building and testing in Github Actions
# workflows and for Enos scenarios.
.PHONY: ci-build
ci-build:
	@$(CURDIR)/scripts/ci-helper.sh build

.PHONY: ci-build-ui
ci-build-ui:
	@$(CURDIR)/scripts/ci-helper.sh build-ui

.PHONY: ci-bundle
ci-bundle:
	@$(CURDIR)/scripts/ci-helper.sh bundle

.PHONY: ci-get-artifact-basename
ci-get-artifact-basename:
	@$(CURDIR)/scripts/ci-helper.sh artifact-basename

.PHONY: ci-get-date
ci-get-date:
	@$(CURDIR)/scripts/ci-helper.sh date

.PHONY: ci-get-revision
ci-get-revision:
	@$(CURDIR)/scripts/ci-helper.sh revision

.PHONY: ci-get-version-package
ci-get-version-package:
	@$(CURDIR)/scripts/ci-helper.sh version-package

.PHONY: ci-prepare-legal
ci-prepare-legal:
	@$(CURDIR)/scripts/ci-helper.sh prepare-legal
