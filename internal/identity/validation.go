package identity

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/agentnameservice/ans-sdk-go/verify"
	"github.com/agentnameservice/ans-sdk-go/verify/scitt"
)

type artifactValidator struct {
	keys scitt.KeyLookup
	cert *x509.Certificate
	cfg  Config
	name *verify.AnsName
	now  func() time.Time
}

func (v *artifactValidator) receipt(raw []byte) error {
	receipt, err := scitt.VerifyReceipt(raw, v.keys)
	if err != nil {
		return fmt.Errorf("receipt: %w", err)
	}
	return v.receiptIdentity(receipt.EventBytes)
}

func (v *artifactValidator) receiptIdentity(raw []byte) error {
	var leaf struct {
		Payload struct {
			Producer struct {
				Event struct {
					AnsID   string `json:"ansId"`
					AgentID string `json:"agentId"`
					AnsName string `json:"ansName"`
				} `json:"event"`
			} `json:"producer"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(raw, &leaf); err != nil {
		return fmt.Errorf("receipt event: %w", err)
	}
	event := leaf.Payload.Producer.Event
	if event.AnsID != "" && event.AgentID != "" && event.AnsID != event.AgentID {
		return errors.New("receipt event has conflicting agent identifiers")
	}
	agentID := event.AnsID
	if agentID == "" {
		agentID = event.AgentID
	}
	if agentID != v.cfg.AgentID {
		return fmt.Errorf("receipt names agent %q, configured agent_id is %q", agentID, v.cfg.AgentID)
	}
	name, err := verify.ParseAnsName(event.AnsName)
	if err != nil {
		return fmt.Errorf("receipt ans name: %w", err)
	}
	if canonicalAnsName(name) != canonicalAnsName(v.name) {
		return fmt.Errorf("receipt names %s, configured ans_name is %s", event.AnsName, v.cfg.AnsName)
	}
	return nil
}

func (v *artifactValidator) status(raw []byte) (*scitt.VerifiedStatusToken, error) {
	now := v.now()
	token, err := verifyStatusToken(raw, v.keys, v.cert, v.cfg, v.name, now)
	if err != nil {
		return nil, err
	}
	if now.Unix() >= token.Payload.Exp {
		return nil, errors.New("status token has expired")
	}
	return token, nil
}
