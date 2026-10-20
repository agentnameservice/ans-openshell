package middleware

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"google.golang.org/protobuf/types/known/structpb"

	"github.com/agentnameservice/ans-openshell/internal/vetting"
)

// Signing modes a policy selects with its "mode" key.
const (
	// ModeSign attaches the identity's proof and artifacts; the default.
	ModeSign = "sign"
	// ModeStrip removes any DPoP and SCITT headers and attaches nothing.
	ModeStrip = "strip"
)

// Keys of the policy config block.
const (
	keyMode              = "mode"
	keyIdentity          = "identity"
	keyDestinationPolicy = "destination_policy"
)

// PolicyConfig is a sandbox policy's network_middlewares[].config block for
// this middleware, parsed.
type PolicyConfig struct {
	Mode              string
	Identity          string
	DestinationPolicy vetting.Mode
}

// ParsePolicy decodes a policy config, rejecting unknown keys, non-string
// values and unknown mode or destination_policy values. Whether the named
// identity exists and whether destination vetting is configured is the
// Service's check.
func ParsePolicy(cfg *structpb.Struct) (PolicyConfig, error) {
	if cfg == nil {
		return PolicyConfig{}, errors.New("config is required")
	}
	p := PolicyConfig{Mode: ModeSign}
	fields := cfg.GetFields()
	for _, key := range slices.Sorted(maps.Keys(fields)) {
		str, isString := fields[key].GetKind().(*structpb.Value_StringValue)
		var err error
		switch {
		case key != keyMode && key != keyIdentity && key != keyDestinationPolicy:
			err = fmt.Errorf("unknown field %q", key)
		case !isString:
			err = fmt.Errorf("%s must be a string", key)
		case key == keyMode:
			p.Mode, err = parseMode(str.StringValue)
		case key == keyIdentity:
			p.Identity = strings.TrimSpace(str.StringValue)
		default:
			p.DestinationPolicy, err = vetting.ParseMode(str.StringValue)
		}
		if err != nil {
			return PolicyConfig{}, err
		}
	}
	return p, nil
}

func parseMode(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", ModeSign:
		return ModeSign, nil
	case ModeStrip:
		return ModeStrip, nil
	}
	return "", fmt.Errorf("unknown mode %q (want sign or strip)", s)
}
