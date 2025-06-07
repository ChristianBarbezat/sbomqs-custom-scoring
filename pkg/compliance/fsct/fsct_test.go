// Copyright 2025 Interlynk.io
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fsct

import (
	"testing"

	"github.com/interlynk-io/sbomqs/pkg/compliance/common"
	"github.com/interlynk-io/sbomqs/pkg/compliance/db"
	"github.com/interlynk-io/sbomqs/pkg/cpe"
	"github.com/interlynk-io/sbomqs/pkg/omniborid"
	"github.com/interlynk-io/sbomqs/pkg/purl"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/interlynk-io/sbomqs/pkg/swhid"
	"github.com/interlynk-io/sbomqs/pkg/swid"
	"gotest.tools/assert"
)

type desired struct {
	score    float64
	result   string
	key      int
	id       string
	maturity string
}

func cdxDocWithSbomAuthorNameEmailAndContact() sbom.Document {
	authors := []sbom.GetAuthor{}
	author := sbom.Author{}
	author.Name = "Samantha Wright"
	author.AuthorType = "person"
	author.Email = "samantha.wright@example.com"
	author.Phone = "800-555-1212"
	authors = append(authors, author)

	doc := sbom.CdxDoc{
		CdxAuthors: authors,
	}
	return doc
}

func cdxDocWithSbomAuthorNameAndEmail() sbom.Document {
	authors := []sbom.GetAuthor{}
	author := sbom.Author{}
	author.Name = "Samantha Wright"
	author.AuthorType = "person"
	author.Email = "samantha.wright@example.com"
	authors = append(authors, author)

	doc := sbom.CdxDoc{
		CdxAuthors: authors,
	}
	return doc
}

func cdxDocWithSbomAuthorNameAndContact() sbom.Document {
	authors := []sbom.GetAuthor{}
	author := sbom.Author{}
	author.Name = "Samantha Wright"
	author.Phone = "800-555-1212"
	author.AuthorType = "person"
	authors = append(authors, author)

	doc := sbom.CdxDoc{
		CdxAuthors: authors,
	}
	return doc
}

func cdxDocWithSbomAuthorName() sbom.Document {
	authors := []sbom.GetAuthor{}
	author := sbom.Author{}
	author.Name = "Samantha Wright"
	author.AuthorType = "person"
	authors = append(authors, author)

	doc := sbom.CdxDoc{
		CdxAuthors: authors,
	}
	return doc
}

func cdxDocWithTool() sbom.Document {
	tools := []sbom.GetTool{}
	tool := sbom.Tool{}
	tool.Name = "sbom-tool"
	tool.Version = "9.1.2"
	tools = append(tools, tool)

	doc := sbom.CdxDoc{
		CdxTools: tools,
	}
	return doc
}

func cdxDocWithMultipleTools() sbom.Document {
	tools := []sbom.GetTool{}
	componentTool := sbom.Tool{}
	componentTool.Name = "sbom-tool"
	componentTool.Version = "9.1.2"
	tools = append(tools, componentTool)

	serviceTool := sbom.Tool{}
	serviceTool.Name = "syft"
	serviceTool.Version = "1.1.2"
	tools = append(tools, serviceTool)

	doc := sbom.CdxDoc{
		CdxTools: tools,
	}
	return doc
}

func cdxDocWithAuthorAndTools() sbom.Document {
	tools := []sbom.GetTool{}
	tool := sbom.Tool{}
	tool.Name = "sbom-tool"
	tool.Version = "9.1.2"
	tools = append(tools, tool)

	authors := []sbom.GetAuthor{}
	author := sbom.Author{}
	author.Name = "Samantha Wright"
	author.AuthorType = "person"
	author.Email = "samantha.wright@example.com"
	author.Phone = "800-555-1212"
	authors = append(authors, author)

	doc := sbom.CdxDoc{
		CdxAuthors: authors,
		CdxTools:   tools,
	}
	return doc
}

func TestFsctCDXSbomAuthorFields(t *testing.T) {
	testCases := []struct {
		name     string
		actual   *db.Record
		expected desired
	}{
		{
			name:   "CDX SBOM with author name only",
			actual: SbomAuthor(cdxDocWithSbomAuthorName()),
			expected: desired{
				score:    10.0,
				result:   "Samantha Wright",
				key:      SBOM_AUTHOR,
				id:       "doc",
				maturity: "Minimum",
			},
		},
		{
			name:   "CDX SBOM with author name and email",
			actual: SbomAuthor(cdxDocWithSbomAuthorNameAndEmail()),
			expected: desired{
				score:    10.0,
				result:   "Samantha Wright (samantha.wright@example.com)",
				key:      SBOM_AUTHOR,
				id:       "doc",
				maturity: "Minimum",
			},
		},
		{
			name:   "CDX SBOM with author name and contact",
			actual: SbomAuthor(cdxDocWithSbomAuthorNameAndContact()),
			expected: desired{
				score:    10.0,
				result:   "Samantha Wright (800-555-1212)",
				key:      SBOM_AUTHOR,
				id:       "doc",
				maturity: "Minimum",
			},
		},
		{
			name:   "CDX SBOM with author name, email and contact",
			actual: SbomAuthor(cdxDocWithSbomAuthorNameEmailAndContact()),
			expected: desired{
				score:    10.0,
				result:   "Samantha Wright (samantha.wright@example.com, 800-555-1212)",
				key:      SBOM_AUTHOR,
				id:       "doc",
				maturity: "Minimum",
			},
		},
		{
			name:   "CDX SBOM with a tool",
			actual: SbomAuthor(cdxDocWithTool()),
			expected: desired{
				score:    0.0,
				result:   "sbom-tool-9.1.2",
				key:      SBOM_AUTHOR,
				id:       "doc",
				maturity: "None",
			},
		},
		{
			name:   "CDX SBOM with multiple tools",
			actual: SbomAuthor(cdxDocWithMultipleTools()),
			expected: desired{
				score:    0.0,
				result:   "sbom-tool-9.1.2, syft-1.1.2",
				key:      SBOM_AUTHOR,
				id:       "doc",
				maturity: "None",
			},
		},
		{
			name:   "CDX SBOM with a Author and tool",
			actual: SbomAuthor(cdxDocWithAuthorAndTools()),
			expected: desired{
				score:    12.0,
				result:   "Samantha Wright (samantha.wright@example.com, 800-555-1212), sbom-tool-9.1.2",
				key:      SBOM_AUTHOR,
				id:       "doc",
				maturity: "Recommended",
			},
		},
	}
	for _, test := range testCases {
		assert.Equal(t, test.expected.score, test.actual.Score, "Score mismatch for %s", test.name)
		assert.Equal(t, test.expected.key, test.actual.CheckKey, "Key mismatch for %s", test.name)
		assert.Equal(t, test.expected.id, test.actual.ID, "ID mismatch for %s", test.name)
		assert.Equal(t, test.expected.result, test.actual.CheckValue, "Result mismatch for %s", test.name)
		assert.Equal(t, test.expected.maturity, test.actual.Maturity, "Maturity mismatch for %s", test.name)
	}
}

func cdxDocWithPrimaryComponent() sbom.Document {
	primary := sbom.PrimaryComp{}
	primary.Present = true
	primary.Name = "git@github.com:interlynk/sbomqs.git"

	doc := sbom.CdxDoc{
		PrimaryComponent: primary,
	}
	return doc
}

func cdxDocWithPreDefinedPhaseLifecycles() sbom.Document {
	phase := "build"

	doc := sbom.SpdxDoc{
		Lifecycle: phase,
	}
	return doc
}

func cdxDocWithCustomPhaseLifecycles() sbom.Document {
	name := "platform-integration-testing"
	// description := "Integration testing specific to the runtime platform"
	doc := sbom.SpdxDoc{
		Lifecycle: name,
	}
	return doc
}

func cdxDocWithTimestamp() sbom.Document {
	s := sbom.NewSpec()
	s.CreationTimestamp = "2020-04-13T20:20:39+00:00"
	doc := sbom.CdxDoc{
		CdxSpec: s,
	}
	return doc
}

func TestFsctCDXOtherSbomLevelFields(t *testing.T) {
	testCases := []struct {
		name     string
		actual   *db.Record
		expected desired
	}{
		{
			name:   "CDX SBOM with timestamp",
			actual: SbomTimestamp(cdxDocWithTimestamp()),
			expected: desired{
				score:    10.0,
				result:   "2020-04-13T20:20:39+00:00",
				key:      SBOM_TIMESTAMP,
				id:       "doc",
				maturity: "Minimum",
			},
		},
		{
			name:   "CDX SBOM with custom phase lifecycle",
			actual: SbomType(cdxDocWithCustomPhaseLifecycles()),
			expected: desired{
				score:    15.0,
				result:   "platform-integration-testing",
				key:      SBOM_TYPE,
				id:       "doc",
				maturity: "Aspirational",
			},
		},
		{
			name:   "CDX SBOM with pre-defined phase lifecycle",
			actual: SbomType(cdxDocWithPreDefinedPhaseLifecycles()),
			expected: desired{
				score:    15.0,
				result:   "build",
				key:      SBOM_TYPE,
				id:       "doc",
				maturity: "Aspirational",
			},
		},
		{
			name:   "CDX SBOM with primary component",
			actual: SbomPrimaryComponent(cdxDocWithPrimaryComponent()),
			expected: desired{
				score:    10.0,
				result:   "git@github.com:interlynk/sbomqs.git",
				key:      SBOM_PRIMARY_COMPONENT,
				id:       "doc",
				maturity: "Minimum",
			},
		},
	}

	for _, test := range testCases {
		assert.Equal(t, test.expected.score, test.actual.Score, "Score mismatch for %s", test.name)
		assert.Equal(t, test.expected.key, test.actual.CheckKey, "Key mismatch for %s", test.name)
		assert.Equal(t, test.expected.id, test.actual.ID, "ID mismatch for %s", test.name)
		assert.Equal(t, test.expected.result, test.actual.CheckValue, "Result mismatch for %s", test.name)
		assert.Equal(t, test.expected.maturity, test.actual.Maturity, "Maturity mismatch for %s", test.name)
	}
}

func spdxDocWithSbomAuthor() sbom.Document {
	authors := []sbom.GetAuthor{}
	author := sbom.Author{}

	author.Name = "Jane Doe"

	author.AuthorType = "person"
	authors = append(authors, author)

	doc := sbom.SpdxDoc{
		Auths: authors,
	}
	return doc
}

func spdxDocWithSbomAuthorAndTool() sbom.Document {
	authors := []sbom.GetAuthor{}
	tools := []sbom.GetTool{}

	tool := sbom.Tool{}
	author := sbom.Author{}
	author.Name = "Jane Doe"
	tool.Name = "syft"
	tool.Version = "1.9.0"

	author.AuthorType = "person"
	authors = append(authors, author)
	tools = append(tools, tool)

	doc := sbom.SpdxDoc{
		Auths:     authors,
		SpdxTools: tools,
	}
	return doc
}

func spdxDocWithSbomTool() sbom.Document {
	tools := []sbom.GetTool{}

	tool := sbom.Tool{}
	tool.Name = "syft"
	tool.Version = "1.9.0"

	tools = append(tools, tool)

	doc := sbom.SpdxDoc{
		SpdxTools: tools,
	}
	return doc
}

func spdxDocWithLifecycles() sbom.Document {
	creatorComment := "hellow, this is sbom build phase"

	doc := sbom.SpdxDoc{
		Lifecycle: creatorComment,
	}
	return doc
}

func spdxDocWithPrimaryComponent() sbom.Document {
	primary := sbom.PrimaryComp{}
	primary.Present = true
	primary.Name = "SPDXRef-DocumentRoot-File-sbomqs-linux-amd64"

	doc := sbom.CdxDoc{
		PrimaryComponent: primary,
	}
	return doc
}

func TestFsctSPDXSbomLevelFields(t *testing.T) {
	testCases := []struct {
		name     string
		actual   *db.Record
		expected desired
	}{
		{
			name:   "SPDX SBOM with lifecycle",
			actual: SbomType(spdxDocWithLifecycles()),
			expected: desired{
				score:    15.0,
				result:   "hellow, this is sbom build phase",
				key:      SBOM_TYPE,
				id:       "doc",
				maturity: "Aspirational",
			},
		},
		{
			name:   "SPDX SBOM with primary component",
			actual: SbomPrimaryComponent(spdxDocWithPrimaryComponent()),
			expected: desired{
				score:    10.0,
				result:   "SPDXRef-DocumentRoot-File-sbomqs-linux-amd64",
				key:      SBOM_PRIMARY_COMPONENT,
				id:       "doc",
				maturity: "Minimum",
			},
		},
		{
			name:   "SPDX SBOM with author name only",
			actual: SbomAuthor(spdxDocWithSbomAuthor()),
			expected: desired{
				score:    10.0,
				result:   "Jane Doe",
				key:      SBOM_AUTHOR,
				id:       "doc",
				maturity: "Minimum",
			},
		},
		{
			name:   "SPDX SBOM with tool only",
			actual: SbomAuthor(spdxDocWithSbomTool()),
			expected: desired{
				score:    0.0,
				result:   "syft-1.9.0",
				key:      SBOM_AUTHOR,
				id:       "doc",
				maturity: "None",
			},
		},
		{
			name:   "SPDX SBOM with Author and tool both",
			actual: SbomAuthor(spdxDocWithSbomAuthorAndTool()),
			expected: desired{
				score:    12.0,
				result:   "Jane Doe, syft-1.9.0",
				key:      SBOM_AUTHOR,
				id:       "doc",
				maturity: "Recommended",
			},
		},
	}

	for _, test := range testCases {
		assert.Equal(t, test.expected.score, test.actual.Score, "Score mismatch for %s", test.name)
		assert.Equal(t, test.expected.key, test.actual.CheckKey, "Key mismatch for %s", test.name)
		assert.Equal(t, test.expected.id, test.actual.ID, "ID mismatch for %s", test.name)
		assert.Equal(t, test.expected.result, test.actual.CheckValue, "Result mismatch for %s", test.name)
		assert.Equal(t, test.expected.maturity, test.actual.Maturity, "Maturity mismatch for %s", test.name)
	}
}

// COMPONENT LEVEL CHECKS

func compWithName() sbom.GetComponent {
	name := "github.com/google/uuid"

	comp := sbom.Component{
		Name: name,
	}
	return comp
}

func compWithVersion() sbom.GetComponent {
	name := "github.com/google/uuid"
	version := "v1.6.0"

	comp := sbom.Component{
		Name:    name,
		Version: version,
	}
	return comp
}

func spdxCompWithSupplierName() sbom.GetComponent {
	name := "github.com/google/uuid"
	supp := sbom.Supplier{}
	supp.Name = "Jane Doe"

	comp := sbom.Component{
		Name:     name,
		Supplier: supp,
	}
	return comp
}

func spdxCompWithSupplierEmail() sbom.GetComponent {
	name := "github.com/google/uuid"
	supp := sbom.Supplier{}
	supp.Email = "jane.doe@example.com"

	comp := sbom.Component{
		Name:     name,
		Supplier: supp,
	}
	return comp
}

func spdxCompWithSupplierNameAndEmail() sbom.GetComponent {
	name := "github.com/google/uuid"
	supp := sbom.Supplier{}
	supp.Email = "jane.doe@example.com"
	supp.Name = "Jane Doe"

	comp := sbom.Component{
		Name:     name,
		Supplier: supp,
	}
	return comp
}

func cdxCompWithSupplierName() sbom.GetComponent {
	name := "github.com/google/uuid"
	supp := sbom.Supplier{}
	supp.Name = "Acme, Inc"

	comp := sbom.Component{
		Name:     name,
		Supplier: supp,
	}
	return comp
}

func cdxCompWithSupplierURL() sbom.GetComponent {
	name := "github.com/google/uuid"
	supp := sbom.Supplier{}
	supp.URL = "https://example.com"

	comp := sbom.Component{
		Name:     name,
		Supplier: supp,
	}
	return comp
}

func cdxCompWithSupplierNameAndURL() sbom.GetComponent {
	name := "github.com/google/uuid"
	supp := sbom.Supplier{}
	supp.Name = "Acme, Inc"
	supp.URL = "https://example.com"

	comp := sbom.Component{
		Name:     name,
		Supplier: supp,
	}
	return comp
}

func cdxCompWithSupplierContactInfo() sbom.GetComponent {
	name := "github.com/google/uuid"

	supp := sbom.Supplier{}
	contact := sbom.Contact{}

	contact.Name = "Acme Distribution"
	contact.Email = "distribution@example.com"
	supp.Contacts = []sbom.Contact{contact}

	comp := sbom.Component{
		Name:     name,
		Supplier: supp,
	}
	return comp
}

func cdxCompWithSupplierAndContactInfo() sbom.GetComponent {
	name := "github.com/google/uuid"

	supp := sbom.Supplier{}
	supp.Name = "Acme, Inc"
	supp.URL = "https://example.com"

	contact := sbom.Contact{}
	contact.Name = "Acme Distribution"
	contact.Email = "distribution@example.com"
	supp.Contacts = []sbom.Contact{contact}

	comp := sbom.Component{
		Name:     name,
		Supplier: supp,
	}
	return comp
}

func compWithSmallContentCopyright() sbom.GetComponent {
	copyright := "2013-2023 The Cobra Authors"
	comp := sbom.NewComponent()
	comp.CopyRight = copyright
	comp.Name = "cobra"
	comp.Spdxid = "pkg:github/spf13/cobra@e94f6d0dd9a5e5738dca6bce03c4b1207ffbc0ec"

	return comp
}

func compWithBigContentCopyright() sbom.GetComponent {
	copyright := "2014 Sam Ghods\n staring in 2011 when the project was ported over:\n2006-2010 Kirill Simonov\n2006-2011 Kirill Simonov\n2011-2019 Canonical Ltd\n2012 The Go Authors. All rights reserved.\n2006 Kirill Simonov"
	comp := sbom.NewComponent()
	comp.CopyRight = copyright
	comp.Name = "yaml"
	comp.Spdxid = "pkg:github/kubernetes-sigs/yaml@c3772b51db126345efe2dfe4ff8dac83b8141684"

	return comp
}

func compWithNoAssertion() sbom.GetComponent {
	copyright := "NOASSERTION"
	comp := sbom.NewComponent()
	comp.CopyRight = copyright
	comp.Name = "yaml.v2"
	comp.Spdxid = "pkg:golang/gopkg.in/yaml.v2@v2.4.0"

	return comp
}

func TestFsctComponentLevelOnSpdxAndCdx(t *testing.T) {
	testCases := []struct {
		name     string
		actual   *db.Record
		expected desired
	}{
		{
			name:   "Comp with Name",
			actual: fsctPackageName(compWithName()),
			expected: desired{
				score:    10.0,
				result:   "github.com/google/uuid",
				key:      COMP_NAME,
				id:       common.UniqueElementID(compWithName()),
				maturity: "Minimum",
			},
		},
		{
			name:   "Comp with Version",
			actual: fsctPackageVersion(compWithVersion()),
			expected: desired{
				score:    10.0,
				result:   "v1.6.0",
				key:      COMP_VERSION,
				id:       common.UniqueElementID(compWithVersion()),
				maturity: "Minimum",
			},
		},
		{
			name:   "SPDX Comp with Supplier Name only",
			actual: fsctPackageSupplier(spdxCompWithSupplierName()),
			expected: desired{
				score:    10.0,
				result:   "Jane Doe",
				key:      COMP_SUPPLIER,
				id:       common.UniqueElementID(spdxCompWithSupplierName()),
				maturity: "Minimum",
			},
		},
		{
			name:   "SPDX Comp with Supplier Email",
			actual: fsctPackageSupplier(spdxCompWithSupplierEmail()),
			expected: desired{
				score:    10.0,
				result:   "jane.doe@example.com",
				key:      COMP_SUPPLIER,
				id:       common.UniqueElementID(spdxCompWithSupplierEmail()),
				maturity: "Minimum",
			},
		},
		{
			name:   "SPDX Comp with Supplier Name and Email",
			actual: fsctPackageSupplier(spdxCompWithSupplierNameAndEmail()),
			expected: desired{
				score:    10.0,
				result:   "Jane Doe, jane.doe@example.com",
				key:      COMP_SUPPLIER,
				id:       common.UniqueElementID(spdxCompWithSupplierNameAndEmail()),
				maturity: "Minimum",
			},
		},
		{
			name:   "CDX Comp with Supplier Name",
			actual: fsctPackageSupplier(cdxCompWithSupplierName()),
			expected: desired{
				score:    10.0,
				result:   "Acme, Inc",
				key:      COMP_SUPPLIER,
				id:       common.UniqueElementID(cdxCompWithSupplierName()),
				maturity: "Minimum",
			},
		},
		{
			name:   "CDX Comp with Supplier URL",
			actual: fsctPackageSupplier(cdxCompWithSupplierURL()),
			expected: desired{
				score:    10.0,
				result:   "https://example.com",
				key:      COMP_SUPPLIER,
				id:       common.UniqueElementID(cdxCompWithSupplierURL()),
				maturity: "Minimum",
			},
		},
		{
			name:   "CDX Comp with Supplier Name and URL",
			actual: fsctPackageSupplier(cdxCompWithSupplierNameAndURL()),
			expected: desired{
				score:    10.0,
				result:   "Acme, Inc, https://example.com",
				key:      COMP_SUPPLIER,
				id:       common.UniqueElementID(cdxCompWithSupplierNameAndURL()),
				maturity: "Minimum",
			},
		},
		{
			name:   "CDX Comp with Supplier Contact Info Only",
			actual: fsctPackageSupplier(cdxCompWithSupplierContactInfo()),
			expected: desired{
				score:    10.0,
				result:   "(Acme Distribution, distribution@example.com)",
				key:      COMP_SUPPLIER,
				id:       common.UniqueElementID(cdxCompWithSupplierContactInfo()),
				maturity: "Minimum",
			},
		},
		{
			name:   "CDX Comp with Supplier and Contact Info",
			actual: fsctPackageSupplier(cdxCompWithSupplierAndContactInfo()),
			expected: desired{
				score:    10.0,
				result:   "Acme, Inc, https://example.com, (Acme Distribution, distribution@example.com)",
				key:      COMP_SUPPLIER,
				id:       common.UniqueElementID(cdxCompWithSupplierAndContactInfo()),
				maturity: "Minimum",
			},
		},
		{
			name:   "SPDX Comp with small content copyright",
			actual: fsctPackageCopyright(compWithSmallContentCopyright()),
			expected: desired{
				score:    10.0,
				result:   "2013-2023 The Cobra Authors",
				key:      COMP_COPYRIGHT,
				id:       common.UniqueElementID(compWithSmallContentCopyright()),
				maturity: "Minimum",
			},
		},
		{
			name:   "SPDX Comp with small content copyright",
			actual: fsctPackageCopyright(compWithBigContentCopyright()),
			expected: desired{
				score:    10.0,
				result:   "2014 Sam Ghods\n staring in 2011 when the project w...",
				key:      COMP_COPYRIGHT,
				id:       common.UniqueElementID(compWithBigContentCopyright()),
				maturity: "Minimum",
			},
		},
		{
			name:   "spdxCompWithNoAssertionCopyright",
			actual: fsctPackageCopyright(compWithNoAssertion()),
			expected: desired{
				score:    0.0,
				result:   "",
				key:      COMP_COPYRIGHT,
				id:       common.UniqueElementID(compWithNoAssertion()),
				maturity: "None",
			},
		},
	}
	for _, test := range testCases {
		assert.Equal(t, test.expected.score, test.actual.Score, "Score mismatch for %s", test.name)
		assert.Equal(t, test.expected.key, test.actual.CheckKey, "Key mismatch for %s", test.name)
		assert.Equal(t, test.expected.id, test.actual.ID, "ID mismatch for %s", test.name)
		assert.Equal(t, test.expected.result, test.actual.CheckValue, "Result mismatch for %s", test.name)
		assert.Equal(t, test.expected.maturity, test.actual.Maturity, "Maturity mismatch for %s", test.name)
	}
}

func primaryCompWithHigherChecksum() (sbom.Document, sbom.GetComponent) {
	primary := sbom.PrimaryComp{}

	chks := []sbom.GetChecksum{}

	ck1 := sbom.Checksum{}
	ck1.Alg = "SHA256"
	ck1.Content = "11b6d3ee554eedf79299905a98f9b9a04e498210b59f15094c916c91d150efcd"

	ck2 := sbom.Checksum{}
	ck2.Alg = "SHA1"
	ck2.Content = "85ed0817af83a24ad8da68c2b5094de69833983c"

	chks = append(chks, ck1, ck2)

	comp := sbom.Component{
		Spdxid:    "DocumentRoot-File-sbomqs-linux-amd64",
		Name:      "sbomqs-linux-amd64",
		Checksums: chks,
	}

	primary.Present = true
	primary.ID = "SPDXRef-DocumentRoot-File-sbomqs-linux-amd64"

	doc := sbom.SpdxDoc{
		PrimaryComponent: primary,
		// Comps:            []sbom.GetComponent{comp},
	}

	return doc, comp
}

func primaryCompWithLowerChecksum() (sbom.Document, sbom.GetComponent) {
	primary := sbom.PrimaryComp{}

	chks := []sbom.GetChecksum{}

	ck1 := sbom.Checksum{}
	ck1.Alg = "MD5"
	ck1.Content = "624c1abb3664f4b35547e7c73864ad24"

	ck2 := sbom.Checksum{}
	ck2.Alg = "SHA1"
	ck2.Content = "85ed0817af83a24ad8da68c2b5094de69833983c"

	chks = append(chks, ck1, ck2)

	comp := sbom.Component{
		Spdxid:    "DocumentRoot-File-sbomqs-linux-amd64",
		Name:      "sbomqs-linux-amd64",
		Checksums: chks,
	}

	primary.Present = true
	primary.ID = "SPDXRef-DocumentRoot-File-sbomqs-linux-amd64"

	doc := sbom.SpdxDoc{
		PrimaryComponent: primary,
	}

	return doc, comp
}

func compWithHigherChecksum() (sbom.Document, sbom.GetComponent) {
	primary := sbom.PrimaryComp{}
	chks := []sbom.GetChecksum{}

	ck1 := sbom.Checksum{}
	ck1.Alg = "SHA256"
	ck1.Content = "11b6d3ee554eedf79299905a98f9b9a04e498210b59f15094c916c91d150efcd"

	ck2 := sbom.Checksum{}
	ck2.Alg = "SHA1"
	ck2.Content = "85ed0817af83a24ad8da68c2b5094de69833983c"

	chks = append(chks, ck1, ck2)

	comp := sbom.Component{
		Spdxid:    "SPDXRef-Package-go-module-stdlib-2dfa88209de0bd8b",
		Name:      "stdlib",
		Checksums: chks,
	}

	primary.Present = true
	primary.ID = "SPDXRef-DocumentRoot-File-sbomqs-linux-amd64"

	doc := sbom.SpdxDoc{
		PrimaryComponent: primary,
	}
	return doc, comp
}

func compWithLowerChecksum() (sbom.Document, sbom.GetComponent) {
	primary := sbom.PrimaryComp{}
	chks := []sbom.GetChecksum{}

	ck1 := sbom.Checksum{}
	ck1.Alg = "MD5"
	ck1.Content = "624c1abb3664f4b35547e7c73864ad24"

	ck2 := sbom.Checksum{}
	ck2.Alg = "SHA1"
	ck2.Content = "85ed0817af83a24ad8da68c2b5094de69833983c"

	chks = append(chks, ck1, ck2)

	comp := sbom.Component{
		Spdxid:    "SPDXRef-Package-go-module-stdlib-2dfa88209de0bd8b",
		Name:      "stdlib",
		Checksums: chks,
	}

	primary.Present = true
	primary.ID = "SPDXRef-DocumentRoot-File-sbomqs-linux-amd64"

	doc := sbom.SpdxDoc{
		PrimaryComponent: primary,
	}
	return &doc, comp
}

func TestFsctChecksums(t *testing.T) {
	_, pch := primaryCompWithHigherChecksum()
	_, pcl := primaryCompWithLowerChecksum()
	_, nch := compWithHigherChecksum()
	_, ncl := compWithLowerChecksum()
	testCases := []struct {
		name     string
		actual   *db.Record
		expected desired
	}{
		{
			name:   "SPDX primary Comp with higher Checksum",
			actual: fsctPackageHash(primaryCompWithHigherChecksum()),
			expected: desired{
				score:    12.0,
				result:   "SHA256, SHA1",
				key:      COMP_CHECKSUM,
				id:       common.UniqueElementID(pch),
				maturity: "Recommended",
			},
		},
		{
			name:   "SPDX primary Comp with lower Checksum",
			actual: fsctPackageHash(primaryCompWithLowerChecksum()),
			expected: desired{
				score:    10.0,
				result:   "MD5, SHA1",
				key:      COMP_CHECKSUM,
				id:       common.UniqueElementID(pcl),
				maturity: "Minimum",
			},
		},
		{
			name:   "SPDX Comp with higher Checksum",
			actual: fsctPackageHash(compWithHigherChecksum()),
			expected: desired{
				score:    10.0,
				result:   "SHA256, SHA1",
				key:      COMP_CHECKSUM,
				id:       common.UniqueElementID(nch),
				maturity: "Minimum",
			},
		},
		{
			name:   "SPDX Comp with lower Checksum",
			actual: fsctPackageHash(compWithLowerChecksum()),
			expected: desired{
				score:    10.0,
				result:   "MD5, SHA1",
				key:      COMP_CHECKSUM,
				id:       common.UniqueElementID(ncl),
				maturity: "Minimum",
			},
		},
	}
	for _, test := range testCases {
		assert.Equal(t, test.expected.score, test.actual.Score, "Score mismatch for %s", test.name)
		assert.Equal(t, test.expected.key, test.actual.CheckKey, "Key mismatch for %s", test.name)
		assert.Equal(t, test.expected.id, test.actual.ID, "ID mismatch for %s", test.name)
		assert.Equal(t, test.expected.result, test.actual.CheckValue, "Result mismatch for %s", test.name)
		assert.Equal(t, test.expected.maturity, test.actual.Maturity, "Maturity mismatch for %s", test.name)
	}
}

type ElementRefID struct {
	ID string
}
type Relationship struct {
	Relationship string
	RefA         ElementRefID
	RefB         ElementRefID
}

func cdxCompIsPartOfPrimaryCompDependency() (sbom.Document, sbom.GetComponent) {
	rel1 := Relationship{
		RefA: ElementRefID{ID: "custom+46261/git@github.com:viveksahu26/sbomqs.git$14e7376fa2b00c102a9ba89fd5ccc7cf26f2f255"},
		RefB: ElementRefID{ID: "pkg:github/google/go-github@0a6474043f9f14c77ba6fa77d1b377a7538a4c8c"},
	}

	comp := sbom.Component{}

	pc := sbom.PrimaryComp{}
	pc.ID = "custom+46261/git@github.com:viveksahu26/sbomqs.git$14e7376fa2b00c102a9ba89fd5ccc7cf26f2f255"
	pc.Present = true
	pc.AllDependencies = append(pc.AllDependencies, rel1.RefB.ID)

	comp.PrimaryCompt = pc
	comp.ID = "pkg:github/google/go-github@0a6474043f9f14c77ba6fa77d1b377a7538a4c8c"
	comp.Name = "go-github"

	spec := sbom.NewSpec()
	spec.SpecType = "cyclonedx"
	doc := sbom.CdxDoc{
		CdxSpec: spec,
	}

	CompIDWithName[rel1.RefB.ID] = "go-github"

	ComponentList[rel1.RefB.ID] = true

	GetAllPrimaryCompDependencies = common.GetAllPrimaryComponentDependencies(doc)
	RelationshipProvidedForPrimaryComp = true
	GetAllPrimaryDependenciesByName = common.GetDependenciesByName(GetAllPrimaryCompDependencies, CompIDWithName)
	ValidRelationshipProvidedForPrimaryComp = true

	return doc, comp
}

func cdxCompWithOneDirectDepAndPartOfPrimaryCompDependency() (sbom.Document, sbom.GetComponent) {
	rel1 := Relationship{
		RefA: ElementRefID{ID: "custom+46261/git@github.com:viveksahu26/sbomqs.git$14e7376fa2b00c102a9ba89fd5ccc7cf26f2f255"},
		RefB: ElementRefID{ID: "pkg:github/google/go-github@0a6474043f9f14c77ba6fa77d1b377a7538a4c8c"},
	}

	rel2 := Relationship{
		RefA: ElementRefID{ID: "pkg:github/google/go-github@0a6474043f9f14c77ba6fa77d1b377a7538a4c8c"},
		RefB: ElementRefID{ID: "pkg:github/ProtonMail/go-crypto@afb1ddc0824ce0052d72ac0d6917f144a1207424"},
	}

	comp := sbom.Component{}

	pc := sbom.PrimaryComp{}
	pc.ID = "custom+46261/git@github.com:viveksahu26/sbomqs.git$14e7376fa2b00c102a9ba89fd5ccc7cf26f2f255"
	pc.Present = true
	pc.AllDependencies = append(pc.AllDependencies, rel1.RefB.ID)

	comp.PrimaryCompt = pc
	comp.ID = "pkg:github/google/go-github@0a6474043f9f14c77ba6fa77d1b377a7538a4c8c"
	comp.Name = "go-github"

	dependencies := make(map[string][]string)
	dependencies[rel1.RefA.ID] = append(dependencies[rel1.RefA.ID], rel1.RefB.ID)
	dependencies[rel2.RefA.ID] = append(dependencies[rel2.RefA.ID], rel2.RefB.ID)

	spec := sbom.NewSpec()
	spec.SpecType = "cyclonedx"
	doc := sbom.CdxDoc{
		CdxSpec:          spec,
		Dependencies:     dependencies,
		PrimaryComponent: pc,
	}

	CompIDWithName[rel1.RefB.ID] = "go-github"
	CompIDWithName[rel2.RefB.ID] = "go-crypto"

	ComponentList[rel1.RefB.ID] = true

	GetAllPrimaryCompDependencies = common.GetAllPrimaryComponentDependencies(doc)
	RelationshipProvidedForPrimaryComp = true
	GetAllPrimaryDependenciesByName = common.GetDependenciesByName(GetAllPrimaryCompDependencies, CompIDWithName)
	ValidRelationshipProvidedForPrimaryComp = true

	return doc, comp
}

func cdxCompWithTwoDirectDepAndPartOfPrimaryCompDependency() (sbom.Document, sbom.GetComponent) {
	rel1 := Relationship{
		RefA: ElementRefID{ID: "custom+46261/git@github.com:viveksahu26/sbomqs.git$14e7376fa2b00c102a9ba89fd5ccc7cf26f2f255"},
		RefB: ElementRefID{ID: "pkg:github/google/go-github@0a6474043f9f14c77ba6fa77d1b377a7538a4c8c"},
	}

	rel2 := Relationship{
		RefA: ElementRefID{ID: "pkg:github/google/go-github@0a6474043f9f14c77ba6fa77d1b377a7538a4c8c"},
		RefB: ElementRefID{ID: "pkg:github/ProtonMail/go-crypto@afb1ddc0824ce0052d72ac0d6917f144a1207424"},
	}

	rel3 := Relationship{
		RefA: ElementRefID{ID: "pkg:github/google/go-github@0a6474043f9f14c77ba6fa77d1b377a7538a4c8c"},
		RefB: ElementRefID{ID: "pkg:golang/github.com/google/go-querystring@v1.1.0"},
	}

	comp := sbom.Component{}

	pc := sbom.PrimaryComp{}
	pc.ID = "custom+46261/git@github.com:viveksahu26/sbomqs.git$14e7376fa2b00c102a9ba89fd5ccc7cf26f2f255"
	pc.Present = true
	pc.AllDependencies = append(pc.AllDependencies, rel1.RefB.ID)

	comp.PrimaryCompt = pc
	comp.ID = "pkg:github/google/go-github@0a6474043f9f14c77ba6fa77d1b377a7538a4c8c"
	comp.Name = "go-github"

	dependencies := make(map[string][]string)
	dependencies[rel1.RefA.ID] = append(dependencies[rel1.RefA.ID], rel1.RefB.ID)
	dependencies[rel2.RefA.ID] = append(dependencies[rel2.RefA.ID], rel2.RefB.ID)
	dependencies[rel3.RefA.ID] = append(dependencies[rel3.RefA.ID], rel3.RefB.ID)

	spec := sbom.NewSpec()
	spec.SpecType = "cyclonedx"
	doc := sbom.CdxDoc{
		CdxSpec:          spec,
		Dependencies:     dependencies,
		PrimaryComponent: pc,
	}

	CompIDWithName[rel1.RefB.ID] = "go-github"
	CompIDWithName[rel2.RefB.ID] = "go-crypto"
	CompIDWithName[rel3.RefB.ID] = "go-querystring"

	ComponentList[rel1.RefB.ID] = true

	GetAllPrimaryCompDependencies = common.GetAllPrimaryComponentDependencies(doc)
	RelationshipProvidedForPrimaryComp = true
	GetAllPrimaryDependenciesByName = common.GetDependenciesByName(GetAllPrimaryCompDependencies, CompIDWithName)
	ValidRelationshipProvidedForPrimaryComp = true

	return doc, comp
}

func spdxCompWithOneDirectDepAndPartOfPrimaryCompDependency() (sbom.Document, sbom.GetComponent) {
	rel1 := Relationship{
		RefA: ElementRefID{ID: "SPDXRef-custom-46261-git-github.com-viveksahu26-sbomqs.git-14e7376fa2b00c102a9ba89fd5ccc7cf26f2f255"},
		RefB: ElementRefID{ID: "SPDXRef-git-github.com-package-url-packageurl-go-7cb81af9593b9512bb946c55c85609948c48aab9"},
	}

	comp := sbom.Component{}

	pc := sbom.PrimaryComp{}
	pc.ID = "SPDXRef-custom-46261-git-github.com-viveksahu26-sbomqs.git-14e7376fa2b00c102a9ba89fd5ccc7cf26f2f255"
	pc.Present = true
	pc.AllDependencies = append(pc.AllDependencies, sbom.CleanKey(rel1.RefB.ID))

	comp.PrimaryCompt = pc
	comp.Spdxid = "git-github.com-package-url-packageurl-go-7cb81af9593b9512bb946c55c85609948c48aab9"
	comp.Name = "packageurl-go"

	dependencies := make(map[string][]string)
	dependencies[sbom.CleanKey(rel1.RefA.ID)] = append(dependencies[sbom.CleanKey(rel1.RefA.ID)], sbom.CleanKey(rel1.RefB.ID))

	spec := sbom.NewSpec()
	spec.SpecType = "spdx"
	doc := sbom.SpdxDoc{
		Dependencies:     dependencies,
		SpdxSpec:         spec,
		PrimaryComponent: pc,
	}

	CompIDWithName[rel1.RefB.ID] = "packageurl-go"

	ComponentList[rel1.RefB.ID] = true

	GetAllPrimaryCompDependencies = common.GetAllPrimaryComponentDependencies(doc)
	RelationshipProvidedForPrimaryComp = true
	GetAllPrimaryDependenciesByName = common.GetDependenciesByName(GetAllPrimaryCompDependencies, CompIDWithName)
	ValidRelationshipProvidedForPrimaryComp = true

	return doc, comp
}

func spdxCompWithTwoDirectDepAndPartOfPrimaryCompDependency() (sbom.Document, sbom.GetComponent) {
	rel1 := Relationship{
		RefA: ElementRefID{ID: "SPDXRef-custom-46261-git-github.com-viveksahu26-sbomqs.git-14e7376fa2b00c102a9ba89fd5ccc7cf26f2f255"},
		RefB: ElementRefID{ID: "SPDXRef-git-github.com-package-url-packageurl-go-7cb81af9593b9512bb946c55c85609948c48aab9"},
	}

	rel2 := Relationship{
		RefA: ElementRefID{ID: "SPDXRef-git-github.com-package-url-packageurl-go-7cb81af9593b9512bb946c55c85609948c48aab9"},
		RefB: ElementRefID{ID: "SPDXRef-git-github.com-samber-lo-151a075ecca084ddbb519fafd513002df0632716"},
	}

	rel3 := Relationship{
		RefA: ElementRefID{ID: "SPDXRef-git-github.com-package-url-packageurl-go-7cb81af9593b9512bb946c55c85609948c48aab9"},
		RefB: ElementRefID{ID: "SPDXRef-git-github.com-github-go-spdx-eacf4f37582f0c1b8f0086816ad1afea74d1ac3f"},
	}

	comp := sbom.Component{}

	pc := sbom.PrimaryComp{}
	pc.ID = "SPDXRef-custom-46261-git-github.com-viveksahu26-sbomqs.git-14e7376fa2b00c102a9ba89fd5ccc7cf26f2f255"
	pc.Present = true
	pc.AllDependencies = append(pc.AllDependencies, sbom.CleanKey(rel1.RefB.ID))

	comp.PrimaryCompt = pc
	comp.Spdxid = "git-github.com-package-url-packageurl-go-7cb81af9593b9512bb946c55c85609948c48aab9"
	comp.Name = "packageurl-go"

	dependencies := make(map[string][]string)
	dependencies[sbom.CleanKey(rel1.RefA.ID)] = append(dependencies[sbom.CleanKey(rel1.RefA.ID)], sbom.CleanKey(rel1.RefB.ID))
	dependencies[sbom.CleanKey(rel2.RefA.ID)] = append(dependencies[sbom.CleanKey(rel2.RefA.ID)], sbom.CleanKey(rel2.RefB.ID))
	dependencies[sbom.CleanKey(rel3.RefA.ID)] = append(dependencies[sbom.CleanKey(rel3.RefA.ID)], sbom.CleanKey(rel3.RefB.ID))

	spec := sbom.NewSpec()
	spec.SpecType = "spdx"
	doc := sbom.SpdxDoc{
		Dependencies:     dependencies,
		SpdxSpec:         spec,
		PrimaryComponent: pc,
	}

	CompIDWithName[rel1.RefB.ID] = "packageurl-go"
	CompIDWithName[rel2.RefB.ID] = "lo"
	CompIDWithName[rel3.RefB.ID] = "go-spdx"

	ComponentList[rel1.RefB.ID] = true

	GetAllPrimaryCompDependencies = common.GetAllPrimaryComponentDependencies(doc)
	RelationshipProvidedForPrimaryComp = true
	GetAllPrimaryDependenciesByName = common.GetDependenciesByName(GetAllPrimaryCompDependencies, CompIDWithName)
	ValidRelationshipProvidedForPrimaryComp = true
	return doc, comp
}

func TestFsctDependencies(t *testing.T) {
	_, a := spdxCompWithOneDirectDepAndPartOfPrimaryCompDependency()
	_, b := spdxCompWithTwoDirectDepAndPartOfPrimaryCompDependency()
	_, c := cdxCompIsPartOfPrimaryCompDependency()
	_, d := cdxCompWithOneDirectDepAndPartOfPrimaryCompDependency()
	_, e := cdxCompWithTwoDirectDepAndPartOfPrimaryCompDependency()
	testCases := []struct {
		name     string
		actual   *db.Record
		expected desired
	}{
		{
			name:   "spdxCompWithZeroDirectDependenciesAsWellAsPartOfPrimaryCompDependencies",
			actual: fsctPackageDependencies(spdxCompWithOneDirectDepAndPartOfPrimaryCompDependency()),
			expected: desired{
				score:    10.0,
				result:   "",
				key:      COMP_RELATIONSHIP,
				id:       common.UniqueElementID(a),
				maturity: "Minimum",
			},
		},
		{
			name:   "spdxCompWithTwoDirectDependenciesAsWellAsPartOfPrimaryCompDependencies",
			actual: fsctPackageDependencies(spdxCompWithTwoDirectDepAndPartOfPrimaryCompDependency()),
			expected: desired{
				score:    12.0,
				result:   "lo, go-spdx",
				key:      COMP_RELATIONSHIP,
				id:       common.UniqueElementID(b),
				maturity: "Recommended",
			},
		},
		{
			name:   "cdxCompWithZeroDirectDependenciesAsWellAsPartOfPrimaryCompDependencies",
			actual: fsctPackageDependencies(cdxCompIsPartOfPrimaryCompDependency()),
			expected: desired{
				score:    10.0,
				result:   "",
				key:      COMP_RELATIONSHIP,
				id:       common.UniqueElementID(c),
				maturity: "Minimum",
			},
		},
		{
			name:   "cdxCompWithOneDirectDependenciesAsWellAsPartOfPrimaryCompDependencies",
			actual: fsctPackageDependencies(cdxCompWithOneDirectDepAndPartOfPrimaryCompDependency()),
			expected: desired{
				score:    12.0,
				result:   "go-crypto",
				key:      COMP_RELATIONSHIP,
				id:       common.UniqueElementID(d),
				maturity: "Recommended",
			},
		},
		{
			name:   "cdxCompWithTwoDirectDependenciesAsWellAsPartOfPrimaryCompDependencies",
			actual: fsctPackageDependencies(cdxCompWithTwoDirectDepAndPartOfPrimaryCompDependency()),
			expected: desired{
				score:    12.0,
				result:   "go-crypto, go-querystring",
				key:      COMP_RELATIONSHIP,
				id:       common.UniqueElementID(e),
				maturity: "Recommended",
			},
		},
	}
	for _, test := range testCases {
		assert.Equal(t, test.expected.score, test.actual.Score, "Score mismatch for %s", test.name)
		assert.Equal(t, test.expected.key, test.actual.CheckKey, "Key mismatch for %s", test.name)
		assert.Equal(t, test.expected.id, test.actual.ID, "ID mismatch for %s", test.name)
		assert.Equal(t, test.expected.result, test.actual.CheckValue, "Result mismatch for %s", test.name)
		assert.Equal(t, test.expected.maturity, test.actual.Maturity, "Maturity mismatch for %s", test.name)
	}
}

type externalRef struct {
	refCategory string
	refType     string
	refLocator  string
}

func spdxCompWithPurl() sbom.GetComponent {
	urls := []purl.PURL{}
	comp := sbom.NewComponent()

	comp.Name = "go-crypto"
	comp.Spdxid = "SPDXRef-git-github.com-ProtonMail-go-crypto-afb1ddc0824ce0052d72ac0d6917f144a1207424"

	ext := externalRef{
		refCategory: "PACKAGE-MANAGER",
		refType:     "purls",
		refLocator:  "pkg:github/ProtonMail/go-crypto@afb1ddc0824ce0052d72ac0d6917f144a1207424",
	}

	prl := purl.NewPURL(ext.refLocator)
	urls = append(urls, prl)
	comp.Purls = urls

	return comp
}

func spdxCompWithCpes() sbom.GetComponent {
	urls := []cpe.CPE{}
	comp := sbom.NewComponent()

	comp.Name = "glibc"
	comp.Spdxid = "SPDXRef-git-github.com-glibc-afb1ddc0824ce0052d72ac0d6917f144a1207424"

	ext := externalRef{
		refCategory: "SECURITY",
		refType:     "cpe23Type",
		refLocator:  "cpe:2.3:a:pivotal_software:spring_framework:4.1.0:*:*:*:*:*:*:*",
	}

	prl := cpe.NewCPE(ext.refLocator)
	urls = append(urls, prl)
	comp.Cpes = urls
	return comp
}

func cdxCompWithPurl() sbom.GetComponent {
	comp := sbom.NewComponent()
	comp.Name = "acme"
	PackageURL := "pkg:npm/acme/component@1.0.0"

	prl := purl.NewPURL(PackageURL)
	comp.Purls = []purl.PURL{prl}

	return comp
}

// type SWHID string

func cdxCompWithSwhid() sbom.GetComponent {
	comp := sbom.NewComponent()
	comp.Name = "packageurl-go"
	swh := "swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2"

	nswhid := swhid.NewSWHID(swh)
	comp.Swhid = append(comp.Swhid, nswhid)

	return comp
}

func cdxCompWithSwid() sbom.GetComponent {
	comp := sbom.NewComponent()
	comp.Name = "packageurl-go"
	swidTagID := "swidgen-242eb18a-503e-ca37-393b-cf156ef09691_9.1.1"
	swidName := "Acme Application"

	nswid := swid.NewSWID(swidTagID, swidName)
	comp.Swid = []swid.SWID{nswid}

	return comp
}

func cdxCompWithOmniBorID() sbom.GetComponent {
	comp := sbom.NewComponent()
	comp.Name = "packageurl-go"
	omniBorID := "gitoid:blob:sha1:a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"

	omni := omniborid.NewOmni(omniBorID)
	comp.OmniID = append(comp.OmniID, omni)

	return comp
}

func cdxCompWithPurlOmniSwhidAndSwid() sbom.GetComponent {
	comp := sbom.NewComponent()
	comp.Name = "acme"

	PackageURL := "pkg:npm/acme/component@1.0.0"
	swh := "swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2"
	swidTagID := "swidgen-242eb18a-503e-ca37-393b-cf156ef09691_9.1.1"
	swidName := "Acme Application"
	omniBorID := "gitoid:blob:sha1:a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"

	prl := purl.NewPURL(PackageURL)
	comp.Purls = []purl.PURL{prl}

	nswhid := swhid.NewSWHID(swh)
	comp.Swhid = append(comp.Swhid, nswhid)

	nswid := swid.NewSWID(swidTagID, swidName)
	comp.Swid = []swid.SWID{nswid}

	omni := omniborid.NewOmni(omniBorID)
	comp.OmniID = append(comp.OmniID, omni)

	return comp
}

func TestFsctUniqIDs(t *testing.T) {
	testCases := []struct {
		name     string
		actual   *db.Record
		expected desired
	}{
		{
			name:   "spdxWithPurl",
			actual: fsctPackageUniqIDs(spdxCompWithPurl()),
			expected: desired{
				score:    10.0,
				result:   "pkg:github/ProtonMail/go-crypto@afb1ddc0824ce0052d72ac0d6917f144a1207424",
				key:      COMP_UNIQ_ID,
				id:       common.UniqueElementID(spdxCompWithPurl()),
				maturity: "Minimum",
			},
		},
		{
			name:   "spdxWithCpe",
			actual: fsctPackageUniqIDs(spdxCompWithCpes()),
			expected: desired{
				score:    10.0,
				result:   "cpe:2.3:a:pivotal_software:spring_framework:4.1.0:*:*:*:*:*:*:*",
				key:      COMP_UNIQ_ID,
				id:       common.UniqueElementID(spdxCompWithCpes()),
				maturity: "Minimum",
			},
		},
		{
			name:   "cdxWithPurl",
			actual: fsctPackageUniqIDs(cdxCompWithPurl()),
			expected: desired{
				score:    10.0,
				result:   "pkg:npm/acme/component@1.0.0",
				key:      COMP_UNIQ_ID,
				id:       common.UniqueElementID(cdxCompWithPurl()),
				maturity: "Minimum",
			},
		},
		{
			name:   "cdxCompWithSwhid",
			actual: fsctPackageUniqIDs(cdxCompWithSwhid()),
			expected: desired{
				score:    10.0,
				result:   "swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2",
				key:      COMP_UNIQ_ID,
				id:       common.UniqueElementID(cdxCompWithSwhid()),
				maturity: "Minimum",
			},
		},
		{
			name:   "cdxCompWithSwid",
			actual: fsctPackageUniqIDs(cdxCompWithSwid()),
			expected: desired{
				score:    10.0,
				result:   "swidgen-242eb18a-503e-ca37-393b-cf156ef09691_9.1.1, Acme Application",
				key:      COMP_UNIQ_ID,
				id:       common.UniqueElementID(cdxCompWithSwid()),
				maturity: "Minimum",
			},
		},
		{
			name:   "cdxCompWithOmniborID",
			actual: fsctPackageUniqIDs(cdxCompWithOmniBorID()),
			expected: desired{
				score:    10.0,
				result:   "gitoid:blob:sha1:a94a8fe5ccb19ba61c4c0873d391e987982fbbd3",
				key:      COMP_UNIQ_ID,
				id:       common.UniqueElementID(cdxCompWithOmniBorID()),
				maturity: "Minimum",
			},
		},
		{
			name:   "cdxCompWithPurlOmniSwhidAndSwid",
			actual: fsctPackageUniqIDs(cdxCompWithPurlOmniSwhidAndSwid()),
			expected: desired{
				score:    10.0,
				result:   "pkg:npm/acme/component@1.0.0, gitoid:blob:sha1:a94a8fe5ccb19ba61c4c0873d391e987982fbbd3, swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2, swidgen-242eb18a-503e-ca37-393b-cf156ef09691_9.1.1, Acme Application",
				key:      COMP_UNIQ_ID,
				id:       common.UniqueElementID(cdxCompWithPurlOmniSwhidAndSwid()),
				maturity: "Minimum",
			},
		},
	}

	for _, test := range testCases {
		assert.Equal(t, test.expected.score, test.actual.Score, "Score mismatch for %s", test.name)
		assert.Equal(t, test.expected.key, test.actual.CheckKey, "Key mismatch for %s", test.name)
		assert.Equal(t, test.expected.id, test.actual.ID, "ID mismatch for %s", test.name)
		assert.Equal(t, test.expected.result, test.actual.CheckValue, "Result mismatch for %s", test.name)
		assert.Equal(t, test.expected.maturity, test.actual.Maturity, "Maturity mismatch for %s", test.name)
	}
}
