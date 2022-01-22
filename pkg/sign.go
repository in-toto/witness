// Copyright 2021 The Witness Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package witness

import (
	"encoding/json"
	"io"

	"github.com/testifysec/witness/pkg/cryptoutil"
	"github.com/testifysec/witness/pkg/dsse"
)

func Sign(r io.Reader, dataType string, w io.Writer, signers ...cryptoutil.Signer) error {
	env, err := dsse.Sign(dataType, r, signers...)
	if err != nil {
		return err
	}

	encoder := json.NewEncoder(w)
	return encoder.Encode(&env)
}
