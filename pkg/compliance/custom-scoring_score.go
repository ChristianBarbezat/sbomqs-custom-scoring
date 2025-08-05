package compliance

import "github.com/interlynk-io/sbomqs/pkg/compliance/db"

type customScoreResult struct {
	id              string
	coreComponentDataScore   float64
	formatStandardsMachineReadabilityScore float64
	governanceTraceabilityUpdatesScore float64
}

func newCustomScoreResult(id string) *customScoreResult {
	return &customScoreResult{id: id}
}

func (r *customScoreResult) totalScore() float64 {
	return (r.coreComponentDataScore + r.formatStandardsMachineReadabilityScore + r.governanceTraceabilityUpdatesScore) / 3
}

func customKeyIDScore(db *db.DB, key int, id string) *customScoreResult {
	records := db.GetRecordsByKeyID(key, id)

	if len(records) == 0 {
		return newCustomScoreResult(id)
	}

	coreComponentDataScore := 0.0
	formatStandardsMachineReadabilityScore := 0.0
	governanceTraceabilityUpdatesScore := 0.0

	for _, r := range records {
		switch r.CheckKey {
		case CORE_COMPONENT_DATA:
			coreComponentDataScore += r.Score
		case FORMAT_STANDARDS_MACHINE_READABILITY:
			formatStandardsMachineReadabilityScore += r.Score
		case GOVERNANCE_TRACEABILITY_UPDATES:
			governanceTraceabilityUpdatesScore += r.Score
		}
	}

	return &customScoreResult{
		id:              id,
		coreComponentDataScore:   coreComponentDataScore,
		formatStandardsMachineReadabilityScore: formatStandardsMachineReadabilityScore,
		governanceTraceabilityUpdatesScore: governanceTraceabilityUpdatesScore,
	}
}

func customAggregateScore(db *db.DB) *customScoreResult {
	var results []customScoreResult
	var finalResult customScoreResult

	ids := db.GetAllIDs()
	for _, id := range ids {
		results = append(results, *customIDScore(db, id))
	}

	for _, r := range results {
		finalResult.coreComponentDataScore += r.coreComponentDataScore
		finalResult.formatStandardsMachineReadabilityScore += r.formatStandardsMachineReadabilityScore
		finalResult.governanceTraceabilityUpdatesScore += r.governanceTraceabilityUpdatesScore
	}

	return &finalResult
}

func customIDScore(db *db.DB, id string) *customScoreResult {
	records := db.GetRecordsByID(id)

	if len(records) == 0 {
		return newCustomScoreResult(id)
	}

	coreComponentDataScore := 0.0
	formatStandardsMachineReadabilityScore := 0.0
	governanceTraceabilityUpdatesScore := 0.0

	for _, r := range records {
		switch r.CheckKey {
		case CORE_COMPONENT_DATA:
			coreComponentDataScore += r.Score
		case FORMAT_STANDARDS_MACHINE_READABILITY:
			formatStandardsMachineReadabilityScore += r.Score
		case GOVERNANCE_TRACEABILITY_UPDATES:
			governanceTraceabilityUpdatesScore += r.Score
		}
	}

	return &customScoreResult{
		id:              id,
		coreComponentDataScore:   coreComponentDataScore,
		formatStandardsMachineReadabilityScore: formatStandardsMachineReadabilityScore,
		governanceTraceabilityUpdatesScore: governanceTraceabilityUpdatesScore,
	}
}
