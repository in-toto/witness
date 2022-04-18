// Copyright 2022 The Witness Contributors
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
	// imported so their init functions run
	_ "github.com/testifysec/witness/pkg/attestation/aws-iid"
	_ "github.com/testifysec/witness/pkg/attestation/commandrun"
	_ "github.com/testifysec/witness/pkg/attestation/environment"
	_ "github.com/testifysec/witness/pkg/attestation/gcp-iit"
	_ "github.com/testifysec/witness/pkg/attestation/git"
	_ "github.com/testifysec/witness/pkg/attestation/gitlab"
	_ "github.com/testifysec/witness/pkg/attestation/jwt"
	_ "github.com/testifysec/witness/pkg/attestation/maven"
	_ "github.com/testifysec/witness/pkg/attestation/oci"
	_ "github.com/testifysec/witness/pkg/attestation/sarif"
	_ "github.com/testifysec/witness/pkg/attestation/scorecard"
	_ "github.com/testifysec/witness/pkg/attestation/syft"
)
