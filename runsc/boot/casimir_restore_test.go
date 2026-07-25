package boot

import (
	"os"
	"testing"

	"gvisor.dev/gvisor/pkg/urpc"
)

func TestValidateCasimirRestoreCapabilities(t *testing.T) {
	files := []*os.File{{}, {}, {}}
	valid := RestoreOpts{
		FilePayload:               urpc.FilePayload{Files: files},
		HavePagesFile:             true,
		HaveBaseFile:              true,
		BaseFileIndex:             0,
		HaveCasimirFaultBaseFile:  true,
		CasimirFaultBaseFileIndex: 1,
		HaveCasimirDataFile:       true,
		CasimirDataFileIndex:      2,
	}
	if err := validateCasimirRestoreCapabilities(&valid); err != nil {
		t.Fatalf("valid capabilities rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*RestoreOpts)
	}{
		{"fault base without data", func(o *RestoreOpts) { o.HaveCasimirDataFile = false }},
		{"data without fault base", func(o *RestoreOpts) { o.HaveCasimirFaultBaseFile = false }},
		{"fault base without shared base", func(o *RestoreOpts) { o.HaveBaseFile = false }},
		{"fault base without async pages", func(o *RestoreOpts) { o.HavePagesFile = false }},
		{"fault base aliases shared base", func(o *RestoreOpts) { o.CasimirFaultBaseFileIndex = o.BaseFileIndex }},
		{"fault base aliases data", func(o *RestoreOpts) { o.CasimirFaultBaseFileIndex = o.CasimirDataFileIndex }},
		{"shared base aliases data", func(o *RestoreOpts) { o.BaseFileIndex = o.CasimirDataFileIndex }},
		{"fault base out of bounds", func(o *RestoreOpts) { o.CasimirFaultBaseFileIndex = len(o.Files) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := valid
			test.mutate(&candidate)
			if err := validateCasimirRestoreCapabilities(&candidate); err == nil {
				t.Fatal("invalid capability topology was admitted")
			}
		})
	}
}
