package identity

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agentnameservice/ans-sdk-go/verify/scitt"

	"github.com/agentnameservice/ans-openshell/internal/testfixtures"
)

func TestKeyRefresher(t *testing.T) {
	t.Parallel()
	unknown := &scitt.SignatureError{Type: scitt.SigErrUnknownKeyID}
	badSignature := &scitt.SignatureError{Type: scitt.SigErrSignatureInvalid}
	for _, tt := range []struct {
		name                              string
		initial, afterRefresh, refreshErr error
		wantCalls                         int
		wantErr                           bool
	}{
		{name: "known key"},
		{name: "malformed artifact", initial: errors.New("invalid CBOR"), wantErr: true},
		{name: "bad signature", initial: badSignature, wantErr: true},
		{name: "new key", initial: unknown, wantCalls: 1},
		{name: "key still absent", initial: unknown, afterRefresh: unknown, wantCalls: 1, wantErr: true},
		{name: "refresh unavailable", initial: unknown, refreshErr: errors.New("offline"), wantCalls: 1, wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			current, calls := tt.initial, 0
			r := &keyRefresher{now: time.Now, refresh: func(context.Context) (bool, error) {
				calls++
				current = tt.afterRefresh
				return true, tt.refreshErr
			}}
			err := r.verify(t.Context(), func() error { return current })
			if (err != nil) != tt.wantErr || calls != tt.wantCalls {
				t.Fatalf("verify() = %v, refresh calls=%d; wantErr=%v calls=%d", err, calls, tt.wantErr, tt.wantCalls)
			}
		})
	}
}

func TestKeyRefresherFailureCooldown(t *testing.T) {
	t.Parallel()
	now := time.Now()
	calls := 0
	r := &keyRefresher{now: func() time.Time { return now }, refresh: func(context.Context) (bool, error) {
		calls++
		return false, context.DeadlineExceeded
	}}
	validate := func() error { return &scitt.SignatureError{Type: scitt.SigErrUnknownKeyID} }
	for range 2 {
		if err := r.verify(t.Context(), validate); err == nil {
			t.Fatal("unknown key accepted")
		}
	}
	if calls != 1 {
		t.Fatalf("refreshes within cooldown=%d", calls)
	}
	now = now.Add(scitt.DefaultOnDemandCooldown)
	if err := r.verify(t.Context(), validate); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("retry=%v", err)
	}
	if calls != 2 {
		t.Fatalf("refreshes after cooldown=%d", calls)
	}
}

func TestKeyRefresherConcurrentMisses(t *testing.T) {
	t.Parallel()
	var valid atomic.Bool
	var calls atomic.Int32
	arrived := make(chan struct{}, 2)
	release := make(chan struct{})
	r := &keyRefresher{now: time.Now, refresh: func(context.Context) (bool, error) {
		calls.Add(1)
		valid.Store(true)
		return true, nil
	}}
	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() {
			first := true
			err := r.verify(t.Context(), func() error {
				if first {
					first = false
					arrived <- struct{}{}
					<-release
					return &scitt.SignatureError{Type: scitt.SigErrUnknownKeyID}
				}
				if valid.Load() {
					return nil
				}
				return &scitt.SignatureError{Type: scitt.SigErrUnknownKeyID}
			})
			if err != nil {
				t.Errorf("verify: %v", err)
			}
		})
	}
	<-arrived
	<-arrived
	close(release)
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("refresh calls=%d", calls.Load())
	}
}

func TestValidatingClientRotation(t *testing.T) {
	t.Parallel()
	oldTL, newTL := testfixtures.MustNewTL(), testfixtures.MustNewTL()
	id := testfixtures.MustNewIdentity(testAgentID, testAnsName)
	upstream := scitt.NewMockClient().WithReceipt(id.AgentID, newTL.Receipt(id.AgentID, id.AnsName)).WithStatusToken(id.AgentID, newTL.FreshStatusToken(id)).WithRootKeys([]string{oldTL.RootKeyC2SP(), newTL.RootKeyC2SP()})
	keys := scitt.NewRefreshableKeyStore(oldTL.KeyStore(), upstream)
	client := &validatingClient{Client: upstream, validator: testValidator(t, keys, id, time.Now), keys: &keyRefresher{refresh: keys.RefreshIfCooldownElapsed, now: time.Now}}
	supplier := scitt.NewHeaderSupplier(id.AgentID, client, keys)
	source, err := NewSupplierSource(t.Context(), supplier)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if !source.Healthy() || keys.Len() != 2 {
		t.Fatalf("healthy=%v keys=%d", source.Healthy(), keys.Len())
	}
	before := source.Current()
	other := testfixtures.MustNewIdentity("other", "ans://v1.0.0.other.example")
	upstream.WithReceipt(id.AgentID, newTL.Receipt(other.AgentID, other.AnsName))
	if err := supplier.RefreshNow(t.Context()); err == nil {
		t.Fatal("accepted wrong-agent receipt")
	}
	if source.Current() != before {
		t.Fatal("bad receipt replaced validated snapshot")
	}
	upstream.WithReceipt(id.AgentID, newTL.Receipt(id.AgentID, id.AnsName)).WithStatusToken(id.AgentID, newTL.FreshStatusToken(other))
	if err := supplier.RefreshNow(t.Context()); err == nil {
		t.Fatal("accepted wrong-agent status")
	}
	if source.Current() != before {
		t.Fatal("bad status replaced validated snapshot")
	}
}

func TestValidatingClientFetchFailures(t *testing.T) {
	t.Parallel()
	tl := testfixtures.MustNewTL()
	id := testfixtures.MustNewIdentity(testAgentID, testAnsName)
	upstream := scitt.NewMockClient().WithError(id.AgentID, context.Canceled)
	keys := scitt.NewRefreshableKeyStore(tl.KeyStore(), upstream)
	client := &validatingClient{Client: upstream, validator: testValidator(t, keys, id, time.Now), keys: &keyRefresher{refresh: keys.RefreshIfCooldownElapsed, now: time.Now}}
	if _, err := client.FetchReceipt(t.Context(), id.AgentID); !errors.Is(err, context.Canceled) {
		t.Fatalf("receipt: %v", err)
	}
	if _, err := client.FetchStatusToken(t.Context(), id.AgentID); !errors.Is(err, context.Canceled) {
		t.Fatalf("status: %v", err)
	}
}
