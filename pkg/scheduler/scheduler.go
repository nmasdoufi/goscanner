package scheduler

import (
	"context"
	"time"

	"github.com/nmasdoufi/goscanner/pkg/config"
	"github.com/nmasdoufi/goscanner/pkg/logging"
)

// TaskRunner defines background work to execute.
type TaskRunner interface {
	Run(ctx context.Context) error
}

// Scheduler triggers scans based on config.
type Scheduler struct {
	cfg    config.SchedulerConfig
	runner TaskRunner
	log    *logging.Logger
}

// New creates scheduler.
func New(cfg config.SchedulerConfig, runner TaskRunner, log *logging.Logger) *Scheduler {
	return &Scheduler{cfg: cfg, runner: runner, log: log}
}

// Start launches periodic execution until ctx done.
func (s *Scheduler) Start(ctx context.Context) {
	if !s.cfg.Enabled {
		s.log.Infof("scheduler disabled")
		return
	}
	interval, err := time.ParseDuration(s.cfg.Tick)
	if err != nil {
		s.log.Errorf("invalid scheduler tick: %v", err)
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.runner.Run(ctx); err != nil {
				s.log.Errorf("scheduled run error: %v", err)
			}
		}
	}
}
