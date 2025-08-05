package compliance

import (
	"testing"

	"github.com/interlynk-io/sbomqs/pkg/compliance/common"
	db "github.com/interlynk-io/sbomqs/pkg/compliance/db"
	"github.com/interlynk-io/sbomqs/pkg/purl"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"gotest.tools/assert"
)

func createSpdxDummyDocumentCustom() sbom.Document {
	// Create a dummy SPDX document for testing
	s := sbom.NewSpec()
	s.Version = "SPDX-2.3"
	s.SpecType = "spdx"
	s.Format = "json"
	s.CreationTimestamp = "2023-05-04T09:33:40Z"

	var creators []sbom.GetTool
	creator := sbom.Tool{
		Name: "syft",
	}
	creators = append(creators, creator)

	pack := sbom.NewComponent()
	pack.Version = "v0.7.1"
	pack.Name = "tool-golang"
	pack.ID = "github/spdx/tools-golang@9db247b854b9634d0109153d515fd1a9efd5a1b1"

	supplier := sbom.Supplier{
		Email: "hello@interlynk.io",
	}
	pack.Supplier = supplier

	extRef := sbom.ExternalReference{
		RefType: "purl",
	}

	var externalReferences []sbom.GetExternalReference
	externalReferences = append(externalReferences, extRef)
	pack.ExternalRefs = externalReferences

	var packages []sbom.GetComponent
	packages = append(packages, pack)

	relationships := make(map[string][]string)
	relationships[sbom.CleanKey("github/spdx/tools-golang@9db247b854b9634d0109153d515fd1a9efd5a1b1")] = append(relationships[sbom.CleanKey("github/spdx/tools-golang@9db247b854b9634d0109153d515fd1a9efd5a1b1")], sbom.CleanKey("github/spdx/gordf@b735bd5aac89fe25cad4ef488a95bc00ea549edd"))

	var primary sbom.PrimaryComp
	primary.ID = pack.ID
	primary.Dependecies = 1
	primary.Present = true
	pack.PrimaryCompt = primary

	compIDWithName["github/spdx/gordf@b735bd5aac89fe25cad4ef488a95bc00ea549edd"] = "gordf"

	doc := sbom.SpdxDoc{
		SpdxSpec:         s,
		Comps:            packages,
		SpdxTools:        creators,
		Dependencies:     relationships,
		PrimaryComponent: primary,
	}
	return doc
}

func TestCustomCompliancePass(t *testing.T) {
	doc := createSpdxDummyDocumentCustom()
	testCases := []struct {
		name     string
		actual   *db.Record
		expected desiredNtia
	}{
		{
			name:   "CoreComponentData",
			actual: coreComponentDataCompliance(doc),
			expected: desiredNtia{
				score:  80.0,
				result: "Component name: tool-golang\nExact version: v0.7.1\nSupplier or vendor name: hello@interlynk.io\nOther Unique Identifiers: purl:(1/1)\nAuthor of SBOM data: \nComponent (Dependency) relationships: gordf\nComponent Hash (SHA 256): \nLicense(s) and usage terms: \nDownload or source repository URL: ",
				key:    CORE_COMPONENT_DATA,
				id:     "Core Component Data",
			},
		},
		{
			name:   "FormatStandardsMachineReadability",
			actual: formatStandardsMachineReadabilityCompliance(doc),
			expected: desiredNtia{
				score:  10.0,
				result: "Conformance to a recognized schema: 10.0\nStructured, machine-parsable format: 10.0\nNamespace, timestamp, and version of the SBOM spec: 10.0",
				key:    FORMAT_STANDARDS_MACHINE_READABILITY,
				id:     "Format, Standards, and Machine-Readability",
			},
		},
		{
			name:   "GovernanceTraceabilityUpdates",
			actual: governanceTraceabilityUpdatesCompliance(doc),
			expected: desiredNtia{
				score:  10.0,
				result: "Tool and tooling version: 10.0\nChange history: 10.0\nIntegration hooks for automated generation: 10.0\nReview cadence and update policy: 10.0\nSBOM integrity verification: 10.0",
				key:    GOVERNANCE_TRACEABILITY_UPDATES,
				id:     "Governance, Traceability, and Updates",
			},
		},
	}

	for _, test := range testCases {
		assert.Equal(t, test.expected.score, test.actual.Score, "Score mismatch for %s", test.name)
		assert.Equal(t, test.expected.key, test.actual.CheckKey, "Key mismatch for %s", test.name)
		assert.Equal(t, test.expected.id, test.actual.ID, "ID mismatch for %s", test.name)
		assert.Equal(t, test.expected.result, test.actual.CheckValue, "Result mismatch for %s", test.name)
	}
}
