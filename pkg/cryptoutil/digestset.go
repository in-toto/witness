package cryptoutil

import (
	"bytes"
	"crypto"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"os"
)

var (
	hashNames = map[crypto.Hash]string{
		crypto.SHA256: "sha256",
		crypto.SHA1:   "sha1",
	}

	hashesByName = map[string]crypto.Hash{
		"sha256": crypto.SHA256,
		"sha1":   crypto.SHA1,
	}
)

type ErrUnsupportedHash string

func (e ErrUnsupportedHash) Error() string {
	return fmt.Sprintf("unsupported hash function: %v", string(e))
}

type DigestSet map[crypto.Hash]string

func HashToString(h crypto.Hash) (string, error) {
	if name, ok := hashNames[h]; ok {
		return name, nil
	}

	return "", ErrUnsupportedHash(h.String())
}

func HashFromString(name string) (crypto.Hash, error) {
	if hash, ok := hashesByName[name]; ok {
		return hash, nil
	}

	return crypto.Hash(0), ErrUnsupportedHash(name)
}

// Equal returns true if every digest for hash functions both artifacts have in common are equal.
// If the two artifacts don't have any digests from common hash functions, equal will return false.
// If any digest from common hash functions differ between the two artifacts, equal will return false.
func (first DigestSet) Equal(second DigestSet) bool {
	hasMatchingDigest := false
	for hash, digest := range first {
		otherDigest, ok := second[hash]
		if !ok {
			continue
		}

		if digest == otherDigest {
			hasMatchingDigest = true
		} else {
			return false
		}
	}

	return hasMatchingDigest
}

func (ds DigestSet) ToNameMap() (map[string]string, error) {
	nameMap := make(map[string]string)
	for hash, digest := range ds {
		name, ok := hashNames[hash]
		if !ok {
			return nameMap, ErrUnsupportedHash(hash.String())
		}

		nameMap[name] = digest
	}

	return nameMap, nil
}

func NewDigestSet(digestsByName map[string]string) (DigestSet, error) {
	ds := make(DigestSet)
	for hashName, digest := range digestsByName {
		hash, ok := hashesByName[hashName]
		if !ok {
			return ds, ErrUnsupportedHash(hashName)
		}

		ds[hash] = digest
	}

	return ds, nil
}

func CalculateDigestSet(r io.Reader, hashes []crypto.Hash) (DigestSet, error) {
	digestSet := make(DigestSet)
	writers := []io.Writer{}
	hashfuncs := map[crypto.Hash]hash.Hash{}
	for _, hash := range hashes {
		hashfunc := hash.New()
		hashfuncs[hash] = hashfunc
		writers = append(writers, hashfunc)
	}

	multiwriter := io.MultiWriter(writers...)
	if _, err := io.Copy(multiwriter, r); err != nil {
		return digestSet, err
	}

	for hash, hashfunc := range hashfuncs {
		digestSet[hash] = string(HexEncode(hashfunc.Sum(nil)))
	}
	return digestSet, nil
}

func CalculateDigestSetFromBytes(data []byte, hashes []crypto.Hash) (DigestSet, error) {
	return CalculateDigestSet(bytes.NewReader(data), hashes)
}

func CalculateDigestSetFromFile(path string, hashes []crypto.Hash) (DigestSet, error) {
	file, err := os.Open(path)
	if err != nil {
		return DigestSet{}, err
	}

	fType, err := isFileType(file)
	if err != nil {
		return DigestSet{}, err
	}

	if !fType {
		return DigestSet{}, fmt.Errorf("%s is not a file", path)
	}

	defer file.Close()
	return CalculateDigestSet(file, hashes)
}

func (ds DigestSet) MarshalJSON() ([]byte, error) {
	nameMap, err := ds.ToNameMap()
	if err != nil {
		return nil, err
	}

	return json.Marshal(nameMap)
}

func (ds *DigestSet) UnmarshalJSON(data []byte) error {
	nameMap := make(map[string]string)
	err := json.Unmarshal(data, &nameMap)
	if err != nil {
		return err
	}

	newDs, err := NewDigestSet(nameMap)
	if err != nil {
		return err
	}

	*ds = newDs
	return nil
}

func isFileType(f *os.File) (bool, error) {
	stat, err := f.Stat()
	if err != nil {
		return false, err
	}

	mode := stat.Mode()

	isSpecial := stat.Mode()&os.ModeCharDevice != 0

	if isSpecial {
		return false, nil
	}

	if mode.IsRegular() {
		return true, nil
	}

	if mode.Perm().IsDir() {
		return true, nil
	}

	if mode&os.ModeSymlink == 1 {
		return true, nil
	}

	return false, nil
}
