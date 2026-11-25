package application

import (
	"context"
	"log"
	"time"
)

type ApprovalExpiryWorker struct{ service *ApprovalService }

func NewApprovalExpiryWorker(service *ApprovalService) *ApprovalExpiryWorker {
	return &ApprovalExpiryWorker{service: service}
}

func (w *ApprovalExpiryWorker) Run(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		if _, err := w.service.ExpirePending(ctx); err != nil && ctx.Err() == nil {
			log.Printf("workflow-service: approval expiry sweep failed: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
