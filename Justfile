tool-golangci:
    @hash golangci-lint > /dev/null 2>&1; if [ $? -ne 0 ]; then \
    GOBIN="$(pwd)/tools/bin" go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest; \
    fi

tool-gofumpt:
    @hash gofumpt > /dev/null 2>&1; if [ $? -ne 0 ]; then \
    GOBIN="$(pwd)/tools/bin" go install mvdan.cc/gofumpt@latest; \
    fi

tool-gci:
    @hash gci > /dev/null 2>&1; if [ $? -ne 0 ]; then \
    GOBIN="$(pwd)/tools/bin" go install github.com/daixiang0/gci@latest; \
    fi

tool-docbuild:
    @hash docbuild > /dev/null 2>&1; if [ $? -ne 0 ]; then \
    GOBIN="$(pwd)/tools/bin" go install github.com/DataDog/go-secure-sdk/internal/tools/docbuild; \
    fi

tool-licenses:
    @hash go-licenses > /dev/null 2>&1; if [ $? -ne 0 ]; then \
    GOBIN="$(pwd)/tools/bin" go install github.com/google/go-licenses@latest; \
    fi

tool-cyclonedx-gomod:
    @hash cyclonedx-gomod > /dev/null 2>&1; if [ $? -ne 0 ]; then \
    GOBIN="$(pwd)/tools/bin" go install github.com/google/go-licenses@latest; \
    fi

lint: tool-golangci tool-gofumpt tool-gci
    [ $(gofumpt -extra -l . | wc -l) != 0 ] && { echo 'code not formated'; exit 1; }; \
    [ $(gci diff -s standard -s "prefix(golang.org/x/)" -s default -s "prefix(github.com/DataDog)" . | wc -l) != 0 ] && { echo 'imports not sorted'; exit 1; }; \
    $(pwd)/tools/bin/golangci-lint run --timeout 5m

fmt: tool-gofumpt tool-gci
    $(pwd)/tools/bin/gofumpt -w --extra . && \
    $(pwd)/tools/bin/gci write -s standard -s "prefix(golang.org/x/)" -s default -s "prefix(github.com/DataDog)" .

dist:
    mkdir dist

test:
    gotestsum ./... -- -cover -race

check-licenses: tool-licenses
    $(pwd)/tools/bin/go-licenses check --disallowed_types=forbidden,restricted,reciprocal,permissive,unknown .

update-3rdparty-licenses: tool-licenses
    $(pwd)/tools/bin/go-licenses csv ./... > LICENSE-3rdparty.csv

bom: dist tool-cyclonedx-gomod
    $(pwd)/tools/bin/cyclonedx-gomod mod -licenses -type library -std -json -output dist/bom.json .

update-readme: tool-docbuild
    $(pwd)/tools/bin/docbuild
