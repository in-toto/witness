set -e

# Verify that generated Markdown docs are up-to-date.
tmpdir=$(mktemp -d)
go run -tags pivkey,pkcs11key,cgo ./cmd/help --dir "$tmpdir"
echo "###########################################"
echo "If diffs are found, run: make docgen"
echo "###########################################"
diff -Naur "$tmpdir" docs/