package compliance

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/interlynk-io/sbomqs/pkg/compliance/common"
	"github.com/interlynk-io/sbomqs/pkg/compliance/db"
	"github.com/olekukonko/tablewriter"
	"sigs.k8s.io/release-utils/version"
)

var customSectionDetails = map[int]customSection{
	CORE_COMPONENT_DATA: {Title: "Core Component Data", ID: "1.1", Required: true, DataField: "Core Component Data"},
	FORMAT_STANDARDS_MACHINE_READABILITY: {Title: "Format, Standards, and Machine-Readability", ID: "2.1", Required: true, DataField: "Format, Standards, and Machine-Readability"},
	GOVERNANCE_TRACEABILITY_UPDATES: {Title: "Governance, Traceability, and Updates", ID: "3.1", Required: true, DataField: "Governance, Traceability, and Updates"},
}

type customSection struct {
	Title         string  `json:"section_title"`
	ID            string  `json:"section_id"`
	DataField     string  `json:"section_data_field"`
	Required      bool    `json:"required"`
	ElementID     string  `json:"element_id"`
	ElementResult string  `json:"element_result"`
	Score         float64 `json:"score"`
}

type customComplianceReport struct {
	Name     string        `json:"report_name"`
	Subtitle string        `json:"subtitle"`
	Revision string        `json:"revision"`
	Run      run           `json:"run"`
	Tool     tool          `json:"tool"`
	Summary  Summary       `json:"summary"`
	Sections []customSection `json:"sections"`
}

func newCustomJSONReport() *customComplianceReport {
	return &customComplianceReport{
		Name:     "Custom Compliance Report",
		Subtitle: "Part 1: Software Bill of Materials (SBOM)",
		Revision: "",
		Run: run{
			ID:            uuid.New().String(),
			GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
			FileName:      "",
			EngineVersion: "1",
		},
		Tool: tool{
			Name:    "sbomqs",
			Version: version.GetVersionInfo().GitVersion,
			Vendor:  "Interlynk (support@interlynk.io)",
		},
	}
}

func customJSONReport(db *db.DB, fileName string) {
	jr := newCustomJSONReport()
	jr.Run.FileName = fileName

	score := customAggregateScore(db)
	summary := Summary{}
	summary.MaxScore = 100.0
	summary.TotalScore = score.totalScore()
	summary.TotalRequiredScore = score.totalRequiredScore()
	summary.TotalOptionalScore = score.totalOptionalScore()

	jr.Summary = summary
	jr.Sections = customConstructSections(db)

	o, _ := json.MarshalIndent(jr, "", "  ")
	fmt.Println(string(o))
}

func customConstructSections(db *db.DB) []customSection {
	var sections []customSection
	allIDs := db.GetAllIDs()
	for _, id := range allIDs {
		records := db.GetRecordsByID(id)

		for _, r := range records {
			section := customSectionDetails[r.CheckKey]
			newSection := customSection{
				Title:     section.Title,
				ID:        section.ID,
				DataField: section.DataField,
				Required:  section.Required,
			}
			score := customKeyIDScore(db, r.CheckKey, r.ID)
			newSection.Score = score.totalScore()
			if r.ID == "doc" {
				newSection.ElementID = "sbom"
			} else {
				newSection.ElementID = r.ID
			}

			newSection.ElementResult = r.CheckValue

			sections = append(sections, newSection)
		}
	}
	// Group sections by ElementID
	sectionsByElementID := make(map[string][]customSection)
	for _, section := range sections {
		sectionsByElementID[section.ElementID] = append(sectionsByElementID[section.ElementID], section)
	}

	// Sort each group of sections by section.ID and ensure "SBOM Data Fields" comes first within its group if it exists
	var sortedSections []customSection
	var sbomLevelSections []customSection
	for elementID, group := range sectionsByElementID {
		sort.Slice(group, func(i, j int) bool {
			return group[i].ID < group[j].ID
		})
		if elementID == "SBOM Level" {
			sbomLevelSections = group
		} else {
			sortedSections = append(sortedSections, group...)
		}
	}

	// Place "SBOM Level" sections at the top
	sortedSections = append(sbomLevelSections, sortedSections...)

	return sortedSections
}

func customDetailedReport(db *db.DB, fileName string, colorOutput bool) {
	table := tablewriter.NewWriter(os.Stdout)
	score := customAggregateScore(db)

	fmt.Printf("Custom Compliance Report\n")
	fmt.Printf("Compliance score by Interlynk Score:%0.1f RequiredScore:%0.1f OptionalScore:%0.1f for %s\n", score.totalScore(), score.totalRequiredScore(), score.totalOptionalScore(), fileName)
	fmt.Printf("* indicates optional fields\n")
	table.SetHeader([]string{"ELEMENT ID", "Section ID", "Custom minimum elements", "Result", "Score"})
	table.SetRowLine(true)
	table.SetAutoMergeCellsByColumnIndex([]int{0})

	sections := customConstructSections(db)

	// Sort sections by ElementId and then by SectionId
	sort.Slice(sections, func(i, j int) bool {
		if sections[i].ElementID == sections[j].ElementID {
			return sections[i].ID < sections[j].ID
		}
		return sections[i].ElementID < sections[j].ElementID
	})

	for _, section := range sections {
		sectionID := section.ID
		if !section.Required {
			sectionID = sectionID + "*"
		}

		if colorOutput {
			// disable tablewriter's auto-wrapping
			table.SetAutoWrapText(false)
			columnWidth := 30
			common.SetHeaderColor(table, 5)

			table = common.ColorTable(table,
				section.ElementID,
				section.ID,
				section.ElementResult,
				section.DataField,
				section.Score,
				columnWidth)
		} else {
			table.Append([]string{section.ElementID, sectionID, section.DataField, section.ElementResult, fmt.Sprintf("%0.1f", section.Score)})
		}
	}
	table.Render()
}

func customBasicReport(db *db.DB, fileName string) {
	score := customAggregateScore(db)
	fmt.Printf("Custom Compliance Report\n")
	fmt.Printf("Score:%0.1f RequiredScore:%0.1f OptionalScore:%0.1f for %s\n", score.totalScore(), score.totalRequiredScore(), score.totalOptionalScore(), fileName)
}
