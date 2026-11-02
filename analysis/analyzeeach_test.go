package analysis

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestAnalyzeEachSkipsFilesThatPanicOrOverrun(t *testing.T) {
	defer func(b time.Duration) { AnalysisBudget = b }(AnalysisBudget)
	AnalysisBudget = 50 * time.Millisecond
	release := make(chan struct{})
	defer close(release)
	analyze := func(_ context.Context, files []File) ([]Finding, error) {
		switch files[0].Path {
		case "panics.go":
			var s []int
			_ = s[1:][0]
		case "stalls.go":
			<-release
		}
		return []Finding{{Rule: "r", Path: files[0].Path, Line: 1}}, nil
	}
	files := []File{{Path: "a.go"}, {Path: "panics.go"}, {Path: "stalls.go"}, {Path: "b.go"}}
	got, unanalyzed, err := analyzeEach(context.Background(), files, analyze)
	if err != nil {
		t.Fatal(err)
	}
	want := []Finding{{Rule: "r", Path: "a.go", Line: 1}, {Rule: "r", Path: "b.go", Line: 1}}
	if !reflect.DeepEqual(got, want) || unanalyzed != 2 {
		t.Errorf("got %v and %d unanalyzed, want %v and 2", got, unanalyzed, want)
	}
}

func TestAnalyzeEachReturnsAnalyzerErrors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	analyze := func(ctx context.Context, _ []File) ([]Finding, error) { return nil, ctx.Err() }
	if _, _, err := analyzeEach(ctx, []File{{Path: "a.go"}}, analyze); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

func TestParallelRunsEachIndexOnce(t *testing.T) {
	for _, n := range []int{0, 1, 1000} {
		var counts sync.Map
		parallel(n, func(i int) {
			v, _ := counts.LoadOrStore(i, new(atomic.Int32))
			v.(*atomic.Int32).Add(1)
		})
		seen := 0
		counts.Range(func(k, v any) bool {
			seen++
			if v.(*atomic.Int32).Load() != 1 {
				t.Errorf("n=%d: index %v ran %d times", n, k, v.(*atomic.Int32).Load())
			}
			return true
		})
		if seen != n {
			t.Errorf("n=%d: ran %d indexes", n, seen)
		}
	}
}
