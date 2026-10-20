package identity

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/agentnameservice/ans-sdk-go/verify/scitt"
)

type keyRefresher struct {
	refresh func(context.Context) (bool, error)
	now     func() time.Time

	mu          sync.Mutex
	nextAttempt time.Time
}

func (r *keyRefresher) verify(ctx context.Context, validate func() error) error {
	err := validate()
	var sigErr *scitt.SignatureError
	if !errors.As(err, &sigErr) || sigErr.Type != scitt.SigErrUnknownKeyID {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err = validate(); err == nil {
		return nil
	}
	now := r.now()
	if now.Before(r.nextAttempt) {
		return err
	}
	// The SDK cools down successful refreshes; failed attempts need the same bound.
	r.nextAttempt = now.Add(scitt.DefaultOnDemandCooldown)
	if _, err := r.refresh(ctx); err != nil {
		return fmt.Errorf("refresh transparency log keys: %w", err)
	}
	return validate()
}

type validatingClient struct {
	scitt.Client
	validator *artifactValidator
	keys      *keyRefresher
}

func (c *validatingClient) FetchReceipt(ctx context.Context, agentID string) ([]byte, error) {
	raw, err := c.Client.FetchReceipt(ctx, agentID)
	if err != nil {
		return nil, err
	}
	if err := c.keys.verify(ctx, func() error { return c.validator.receipt(raw) }); err != nil {
		return nil, err
	}
	return raw, nil
}

func (c *validatingClient) FetchStatusToken(ctx context.Context, agentID string) ([]byte, error) {
	raw, err := c.Client.FetchStatusToken(ctx, agentID)
	if err != nil {
		return nil, err
	}
	if err := c.keys.verify(ctx, func() error {
		_, err := c.validator.status(raw)
		return err
	}); err != nil {
		return nil, err
	}
	return raw, nil
}
