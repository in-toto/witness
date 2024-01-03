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

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/in-toto/witness/cmd"
	"github.com/spf13/cobra/doc"
)

var directory string

func init() {
	flag.StringVar(&directory, "dir", "docs", "Directory to store the generated docs")
	flag.Parse()
}

func main() {
	// Generate CLI docs
	if err := doc.GenMarkdownTree(cmd.New(), directory); err != nil {
		log.Fatalf("Error generating docs: %s", err)
	}

	err := cmd.GenConfig(cmd.New(), "template.witness.yml")
	if err != nil {
		log.Fatalf("Error generating docs: %s", err)
	}

	f, err := os.ReadFile("template.witness.yml")
	if err != nil {
		log.Fatalf("Error generating docs: %s", err)
	}

	os.Remove("template.witness.yml")

	updateConfigMd(f)
}

func updateConfigMd(newYAML []byte) error {
	// Read the Markdown file
	fileName := "docs/config.md"
	content, err := os.ReadFile(fileName)
	if err != nil {
		log.Fatalf("Error generating docs: %s", err)
	}

	fileContent := string(content)
	comment := "<!-- Config file YAML placeholder -->"
	yamlBlockStart := "```yaml"
	yamlBlockEnd := "```"

	// Find the position of the comment
	commentPos := strings.Index(fileContent, comment)
	if commentPos == -1 {
		log.Fatalf("Error generating docs: %s", err)
	}

	// Find the positions of the YAML block
	yamlStartPos := strings.Index(fileContent[commentPos:], yamlBlockStart)
	if yamlStartPos == -1 {
		log.Fatalf("Error generating docs: %s", err)
	}
	yamlStartPos += commentPos + len(yamlBlockStart)

	yamlEndPos := strings.Index(fileContent[yamlStartPos:], yamlBlockEnd)
	if yamlEndPos == -1 {
		log.Fatalf("Error generating docs: %s", err)
	}
	yamlEndPos += yamlStartPos

	// Replace the YAML block entirely
	fileContent = fileContent[:yamlStartPos] + fmt.Sprintf("\n%s\n", string(newYAML)) + fileContent[yamlEndPos:]

	// Write the updated content back to the file
	err = os.WriteFile(fileName, []byte(fileContent), 0644)
	if err != nil {
		log.Fatalf("Error generating docs: %s", err)
	}

	return nil
}
