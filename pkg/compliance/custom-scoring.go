package compliance

import (
	"context"
	"fmt"
	"strings"

	"github.com/interlynk-io/sbomqs/pkg/compliance/common"
	db "github.com/interlynk-io/sbomqs/pkg/compliance/db"
	"github.com/interlynk-io/sbomqs/pkg/logger"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/samber/lo"
)

const (
	CORE_COMPONENT_DATA = iota
	FORMAT_STANDARDS_MACHINE_READABILITY
	GOVERNANCE_TRACEABILITY_UPDATES
)

var (
	validCustomSpdxVersions = []string{"SPDX-2.3"}
	validCustomCdxVersions  = []string{"1.4", "1.5", "1.6"}
	validFormats            = []string{"json", "xml", "yaml", "yml", "tag-value"}
)

func customComplianceResult(ctx context.Context, doc sbom.Document, fileName string, outFormat string, colorOutput bool) {
	log := logger.FromContext(ctx)
	log.Debug("compliance.customComplianceResult()")

	dtb := db.NewDB()

	dtb.AddRecord(coreComponentDataCompliance(doc))
	dtb.AddRecord(formatStandardsMachineReadabilityCompliance(doc))
	dtb.AddRecord(governanceTraceabilityUpdatesCompliance(doc))

	if outFormat == "json" {
		customComplianceJSONReport(dtb, fileName)
	}

	if outFormat == "basic" {
		customComplianceBasicReport(dtb, fileName)
	}

	if outFormat == "detailed" {
		customComplianceDetailedReport(dtb, fileName, colorOutput)
	}
}

func coreComponentDataCompliance(doc sbom.Document) *db.Record {
	score := 0.0
	result := ""

	// Component name
	componentNameScore := componentNameCompliance(doc)
	score += componentNameScore
	result += "Component name: " + fmt.Sprintf("%.2f", componentNameScore) + "\n"

	// Exact version
	exactVersionScore := exactVersionCompliance(doc)
	score += exactVersionScore
	result += "Exact version: " + fmt.Sprintf("%.2f", exactVersionScore) + "\n"

	// Supplier or vendor name
	supplierNameScore := supplierNameCompliance(doc)
	score += supplierNameScore
	result += "Supplier or vendor name: " + fmt.Sprintf("%.2f", supplierNameScore) + "\n"

	// Other Unique Identifiers (e.g., CPEs, purl, OSV IDs)
	uniqueIdentifiersScore := uniqueIdentifiersCompliance(doc)
	score += uniqueIdentifiersScore
	result += "Other Unique Identifiers: " + fmt.Sprintf("%.2f", uniqueIdentifiersScore) + "\n"

	// Author of SBOM data
	authorScore := authorCompliance(doc)
	score += authorScore
	result += "Author of SBOM data: " + fmt.Sprintf("%.2f", authorScore) + "\n"

	// Component (Dependency) relationships
	componentRelationshipsScore := componentRelationshipsCompliance(doc)
	score += componentRelationshipsScore
	result += "Component (Dependency) relationships: " + fmt.Sprintf("%.2f", componentRelationshipsScore) + "\n"

	// Component Hash (SHA 256)
	componentHashScore := componentHashCompliance(doc)
	score += componentHashScore
	result += "Component Hash (SHA 256): " + fmt.Sprintf("%.2f", componentHashScore) + "\n"

	// License(s) and usage terms
	licenseScore := licenseCompliance(doc)
	score += licenseScore
	result += "License(s) and usage terms: " + fmt.Sprintf("%.2f", licenseScore) + "\n"

	// Download or source repository URL
	downloadURLScore := downloadURLCompliance(doc)
	score += downloadURLScore
	result += "Download or source repository URL: " + fmt.Sprintf("%.2f", downloadURLScore) + "\n"

	return db.NewRecordStmt(CORE_COMPONENT_DATA, "Core Component Data", result, score, "")
}

func formatStandardsMachineReadabilityCompliance(doc sbom.Document) *db.Record {
	score := 0.0
	result := ""

	// Conformance to a recognized schema
	schemaConformanceScore := schemaConformanceCompliance(doc)
	score += schemaConformanceScore
	result += "Conformance to a recognized schema: " + fmt.Sprintf("%.2f", schemaConformanceScore) + "\n"

	// Structured, machine-parsable format
	machineParsableFormatScore := machineParsableFormatCompliance(doc)
	score += machineParsableFormatScore
	result += "Structured, machine-parsable format: " + fmt.Sprintf("%.2f", machineParsableFormatScore) + "\n"

	// Namespace, timestamp, and version of the SBOM spec
	namespaceTimestampVersionScore := namespaceTimestampVersionCompliance(doc)
	score += namespaceTimestampVersionScore
	result += "Namespace, timestamp, and version of the SBOM spec: " + fmt.Sprintf("%.2f", namespaceTimestampVersionScore) + "\n"

	return db.NewRecordStmt(FORMAT_STANDARDS_MACHINE_READABILITY, "Format, Standards, and Machine-Readability", result, score, "")
}

func governanceTraceabilityUpdatesCompliance(doc sbom.Document) *db.Record {
	score := 0.0
	result := ""

	// Tool and tooling version
	toolVersionScore := toolVersionCompliance(doc)
	score += toolVersionScore
	result += "Tool and tooling version: " + fmt.Sprintf("%.2f", toolVersionScore) + "\n"

	// Change history
	changeHistoryScore := changeHistoryCompliance(doc)
	score += changeHistoryScore
	result += "Change history: " + fmt.Sprintf("%.2f", changeHistoryScore) + "\n"

	// Integration hooks for automated generation
	integrationHooksScore := integrationHooksCompliance(doc)
	score += integrationHooksScore
	result += "Integration hooks for automated generation: " + fmt.Sprintf("%.2f", integrationHooksScore) + "\n"

	// Review cadence and update policy
	reviewCadenceUpdatePolicyScore := reviewCadenceUpdatePolicyCompliance(doc)
	score += reviewCadenceUpdatePolicyScore
	result += "Review cadence and update policy: " + fmt.Sprintf("%.2f", reviewCadenceUpdatePolicyScore) + "\n"

	// SBOM integrity verification
	integrityVerificationScore := integrityVerificationCompliance(doc)
	score += integrityVerificationScore
	result += "SBOM integrity verification: " + fmt.Sprintf("%.2f", integrityVerificationScore) + "\n"

	return db.NewRecordStmt(GOVERNANCE_TRACEABILITY_UPDATES, "Governance, Traceability, and Updates", result, score, "")
}

func componentNameCompliance(doc sbom.Document) float64 {
	// implement logic to evaluate component name compliance
	// ...
}

func exactVersionCompliance(doc sbom.Document) float64 {
	// implement logic to evaluate exact version compliance
	// ...
}

func supplierNameCompliance(doc sbom.Document) float64 {
	// implement logic to evaluate supplier name compliance
	// ...
}

func uniqueIdentifiersCompliance(doc sbom.Document) float64 {
	// implement logic to evaluate unique identifiers compliance
	// ...
}

func authorCompliance(doc sbom.Document) float64 {
	// implement logic to evaluate author compliance
	// ...
}

func componentRelationshipsCompliance(doc sbom.Document) float64 {
	// implement logic to evaluate component relationships compliance
	// ...
}

func componentHashCompliance(doc sbom.Document) float64 {
	// implement logic to evaluate component hash compliance
	// ...
}

func licenseCompliance(doc sbom.Document) float64 {
	// implement logic to evaluate license compliance
	// ...
}

func downloadURLCompliance(doc sbom.Document) float64 {
	// implement logic to evaluate download URL compliance
	// ...
}

func schemaConformanceCompliance(doc sbom.Document) float64 {
	spec := doc.Spec().GetSpecType()
	version := doc.Spec().GetVersion()

	if spec == "spdx" {
		if lo.Contains(validCustomSpdxVersions, version) {
			return 10.0
		}
	} else if spec == "cyclonedx" {
		if lo.Contains(validCustomCdxVersions, version) {
			return 10.0
		}
	}

	return 0.0
}

func machineParsableFormatCompliance(doc sbom.Document) float64 {
	// implement logic to evaluate machine-parsable format compliance
	// ...
}

func namespaceTimestampVersionCompliance(doc sbom.Document) float64 {
	// implement logic to evaluate namespace, timestamp, and version compliance
	// ...
}

func toolVersionCompliance(doc sbom.Document) float64 {
	// implement logic to evaluate tool version compliance
	// ...
}

func changeHistoryCompliance(doc sbom.Document) float64 {
	// implement logic to evaluate change history compliance
	// ...
}

func integrationHooksCompliance(doc sbom.Document) float64 {
	// implement logic to evaluate integration hooks compliance
	// ...
}

func reviewCadenceUpdatePolicyCompliance(doc sbom.Document) float64 {
	// implement logic to evaluate review cadence and update policy compliance
	// ...
}

func integrityVerificationCompliance(doc sbom.Document) float64 {
	// implement logic to evaluate SBOM integrity verification compliance
	// ...
}
