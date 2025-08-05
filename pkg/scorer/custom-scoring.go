package scorer

import (
	"fmt"
	"strings"

	"github.com/interlynk-io/sbomqs/pkg/sbom"
)

// CustomScoring calculates the score for an SBOM document based on the custom scoring criteria
func CustomScoring(d sbom.Document) score {
	s := newScore()

	// Core Component Data (80%)
	coreComponentDataScore := calculateCoreComponentDataScore(d)
	s.setScore(s.getScore() + coreComponentDataScore)
	s.setDesc(s.getDesc() + "Core Component Data: " + fmt.Sprintf("%.2f", coreComponentDataScore) + "\n")

	// Format, Standards, and Machine-Readability (10%)
	formatStandardsMachineReadabilityScore := calculateFormatStandardsMachineReadabilityScore(d)
	s.setScore(s.getScore() + formatStandardsMachineReadabilityScore)
	s.setDesc(s.getDesc() + "Format, Standards, and Machine-Readability: " + fmt.Sprintf("%.2f", formatStandardsMachineReadabilityScore) + "\n")

	// Governance, Traceability, and Updates (10%)
	governanceTraceabilityUpdatesScore := calculateGovernanceTraceabilityUpdatesScore(d)
	s.setScore(s.getScore() + governanceTraceabilityUpdatesScore)
	s.setDesc(s.getDesc() + "Governance, Traceability, and Updates: " + fmt.Sprintf("%.2f", governanceTraceabilityUpdatesScore) + "\n")

	return *s
}

// calculateCoreComponentDataScore calculates the score for the Core Component Data category
func calculateCoreComponentDataScore(d sbom.Document) float64 {
	score := 0.0

	// Component name: 10%
	componentNameScore := calculateComponentNameScore(d)
	score += componentNameScore

	// Exact version: 10%
	exactVersionScore := calculateExactVersionScore(d)
	score += exactVersionScore

	// Supplier or vendor name: 10%
	supplierNameScore := calculateSupplierNameScore(d)
	score += supplierNameScore

	// Other Unique Identifiers (e.g., CPEs, purl, OSV IDs): 10%
	uniqueIdentifiersScore := calculateUniqueIdentifiersScore(d)
	score += uniqueIdentifiersScore

	// Author of SBOM data: 10%
	authorScore := calculateAuthorScore(d)
	score += authorScore

	// Component (Dependency) relationships: 10%
	componentRelationshipsScore := calculateComponentRelationshipsScore(d)
	score += componentRelationshipsScore

	// Component Hash (SHA 256): 10%
	componentHashScore := calculateComponentHashScore(d)
	score += componentHashScore

	// License(s) and usage terms: 5%
	licenseScore := calculateLicenseScore(d)
	score += licenseScore

	// Download or source repository URL: 5%
	downloadURLScore := calculateDownloadURLScore(d)
	score += downloadURLScore

	return score
}

// calculateFormatStandardsMachineReadabilityScore calculates the score for the Format, Standards, and Machine-Readability category
func calculateFormatStandardsMachineReadabilityScore(d sbom.Document) float64 {
	score := 0.0

	// Conformance to a recognized schema: 5%
	schemaConformanceScore := calculateSchemaConformanceScore(d)
	score += schemaConformanceScore

	// Structured, machine-parsable format: 2%
	machineParsableFormatScore := calculateMachineParsableFormatScore(d)
	score += machineParsableFormatScore

	// Namespace, timestamp, and version of the SBOM spec: 3%
	namespaceTimestampVersionScore := calculateNamespaceTimestampVersionScore(d)
	score += namespaceTimestampVersionScore

	return score
}

// calculateGovernanceTraceabilityUpdatesScore calculates the score for the Governance, Traceability, and Updates category
func calculateGovernanceTraceabilityUpdatesScore(d sbom.Document) float64 {
	score := 0.0

	// Tool and tooling version: 2%
	toolVersionScore := calculateToolVersionScore(d)
	score += toolVersionScore

	// Change history: 2%
	changeHistoryScore := calculateChangeHistoryScore(d)
	score += changeHistoryScore

	// Integration hooks for automated generation: 2%
	integrationHooksScore := calculateIntegrationHooksScore(d)
	score += integrationHooksScore

	// Review cadence and update policy: 2%
	reviewCadenceUpdatePolicyScore := calculateReviewCadenceUpdatePolicyScore(d)
	score += reviewCadenceUpdatePolicyScore

	// SBOM integrity verification: 2%
	integrityVerificationScore := calculateIntegrityVerificationScore(d)
	score += integrityVerificationScore

	return score
}

// calculateComponentNameScore calculates the score for the Component Name criterion
func calculateComponentNameScore(d sbom.Document) float64 {
	totalComponents := len(d.Components())
	componentsWithName := 0
	for _, component := range d.Components() {
		if component.GetName() != "" {
			componentsWithName++
		}
	}
	score := (float64(componentsWithName) / float64(totalComponents)) * 10.0
	return score
}

// calculateExactVersionScore calculates the score for the Exact Version criterion
func calculateExactVersionScore(d sbom.Document) float64 {
	totalComponents := len(d.Components())
	componentsWithExactVersion := 0
	for _, component := range d.Components() {
		if component.GetVersion() != "" {
			componentsWithExactVersion++
		}
	}
	score := (float64(componentsWithExactVersion) / float64(totalComponents)) * 10.0
	return score
}

// calculateSupplierNameScore calculates the score for the Supplier Name criterion
func calculateSupplierNameScore(d sbom.Document) float64 {
	totalComponents := len(d.Components())
	componentsWithSupplierName := 0
	for _, component := range d.Components() {
		if component.GetSupplier() != "" {
			componentsWithSupplierName++
		}
	}
	score := (float64(componentsWithSupplierName) / float64(totalComponents)) * 10.0
	return score
}

// calculateUniqueIdentifiersScore calculates the score for the Unique Identifiers criterion
func calculateUniqueIdentifiersScore(d sbom.Document) float64 {
	totalComponents := len(d.Components())
	componentsWithUniqueIdentifiers := 0
	for _, component := range d.Components() {
		if component.GetCpes() != nil || component.GetPurls() != nil || component.GetOsvIds() != nil {
			componentsWithUniqueIdentifiers++
		}
	}
	score := (float64(componentsWithUniqueIdentifiers) / float64(totalComponents)) * 10.0
	return score
}

// calculateAuthorScore calculates the score for the Author criterion
func calculateAuthorScore(d sbom.Document) float64 {
	totalComponents := len(d.Components())
	componentsWithAuthor := 0
	for _, component := range d.Components() {
		if component.GetAuthor() != "" {
			componentsWithAuthor++
		}
	}
	score := (float64(componentsWithAuthor) / float64(totalComponents)) * 10.0
	return score
}

// calculateComponentRelationshipsScore calculates the score for the Component Relationships criterion
func calculateComponentRelationshipsScore(d sbom.Document) float64 {
	totalComponents := len(d.Components())
	componentsWithRelationships := 0
	for _, component := range d.Components() {
		if component.GetDependencies() != nil {
			componentsWithRelationships++
		}
	}
	score := (float64(componentsWithRelationships) / float64(totalComponents)) * 10.0
	return score
}

// calculateComponentHashScore calculates the score for the Component Hash criterion
func calculateComponentHashScore(d sbom.Document) float64 {
	totalComponents := len(d.Components())
	componentsWithHash := 0
	for _, component := range d.Components() {
		if component.GetHash() != "" {
			componentsWithHash++
		}
	}
	score := (float64(componentsWithHash) / float64(totalComponents)) * 10.0
	return score
}

// calculateLicenseScore calculates the score for the License criterion
func calculateLicenseScore(d sbom.Document) float64 {
	totalComponents := len(d.Components())
	componentsWithLicense := 0
	for _, component := range d.Components() {
		if component.GetLicense() != "" {
			componentsWithLicense++
		}
	}
	score := (float64(componentsWithLicense) / float64(totalComponents)) * 5.0
	return score
}

// calculateDownloadURLScore calculates the score for the Download URL criterion
func calculateDownloadURLScore(d sbom.Document) float64 {
	totalComponents := len(d.Components())
	componentsWithDownloadURL := 0
	for _, component := range d.Components() {
		if component.GetDownloadURL() != "" {
			componentsWithDownloadURL++
		}
	}
	score := (float64(componentsWithDownloadURL) / float64(totalComponents)) * 5.0
	return score
}

// calculateSchemaConformanceScore calculates the score for the Schema Conformance criterion
func calculateSchemaConformanceScore(d sbom.Document) float64 {
	if d.GetSchema() != "" {
		return 5.0
	}
	return 0.0
}

// calculateMachineParsableFormatScore calculates the score for the Machine-Parsable Format criterion
func calculateMachineParsableFormatScore(d sbom.Document) float64 {
	if d.GetFormat() == "json" || d.GetFormat() == "xml" {
		return 2.0
	}
	return 0.0
}

// calculateNamespaceTimestampVersionScore calculates the score for the Namespace, Timestamp, and Version criterion
func calculateNamespaceTimestampVersionScore(d sbom.Document) float64 {
	if d.GetNamespace() != "" && d.GetTimestamp() != "" && d.GetVersion() != "" {
		return 3.0
	}
	return 0.0
}

// calculateToolVersionScore calculates the score for the Tool Version criterion
func calculateToolVersionScore(d sbom.Document) float64 {
	if d.GetTool() != "" && d.GetToolVersion() != "" {
		return 2.0
	}
	return 0.0
}

// calculateChangeHistoryScore calculates the score for the Change History criterion
func calculateChangeHistoryScore(d sbom.Document) float64 {
	if d.GetChangeHistory() != "" {
		return 2.0
	}
	return 0.0
}

// calculateIntegrationHooksScore calculates the score for the Integration Hooks criterion
func calculateIntegrationHooksScore(d sbom.Document) float64 {
	if d.GetIntegrationHooks() != "" {
		return 2.0
	}
	return 0.0
}

// calculateReviewCadenceUpdatePolicyScore calculates the score for the Review Cadence and Update Policy criterion
func calculateReviewCadenceUpdatePolicyScore(d sbom.Document) float64 {
	if d.GetReviewCadence() != "" && d.GetUpdatePolicy() != "" {
		return 2.0
	}
	return 0.0
}

// calculateIntegrityVerificationScore calculates the score for the Integrity Verification criterion
func calculateIntegrityVerificationScore(d sbom.Document) float64 {
	if d.GetIntegrityVerification() != "" {
		return 2.0
	}
	return 0.0
}
