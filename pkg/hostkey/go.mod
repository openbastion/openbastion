module github.com/openbastion/openbastion/pkg/hostkey

go 1.22

require golang.org/x/crypto v0.24.0

require golang.org/x/sys v0.21.0 // indirect

// Les mêmes miroirs GitHub que les services (voir /NOTES_SANDBOX.md).
replace golang.org/x/crypto => github.com/golang/crypto v0.24.0

replace golang.org/x/sys => github.com/golang/sys v0.21.0
