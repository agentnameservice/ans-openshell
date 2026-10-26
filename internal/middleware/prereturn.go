package middleware

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"slices"

	"github.com/agentnameservice/ans-openshell/gen/openshell/middlewarev1"
)

// PreReturnService implements HttpResponsePreReturn: detects the seller's
// structured capability error (error.data.required_capabilities) and injects
// a top-level middleware_hint for the caller. Uses Inspect+Transform when
// WHOLE_BODY_BYTES is permitted, else Skip (pass-through).
type PreReturnService struct {
	middlewarev1.UnimplementedHttpResponsePreReturnServer
	log *slog.Logger
}

// NewPreReturnService constructs a PreReturnService.
func NewPreReturnService(log *slog.Logger) *PreReturnService {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &PreReturnService{log: log}
}

// Evaluate processes the bidirectional event stream: preflight→Inspect/Skip,
// body→Transform/PassThrough, trailers→empty result, session_end→no reply.
// Per-stream state (inspecting flag, maxPayloadBytes) is local to this call.
func (s *PreReturnService) Evaluate(stream middlewarev1.HttpResponsePreReturn_EvaluateServer) error {
	ctx := stream.Context()
	// Per-stream-local state: are we inspecting this stream? what's the max payload?
	var inspecting bool
	var maxPayloadBytes uint64

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		ev, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}

		result := s.onEvent(ev, &inspecting, &maxPayloadBytes)
		// session_end: no reply
		if result == nil {
			continue
		}

		if err := stream.Send(result); err != nil {
			return err
		}
	}
}

// onEvent decides the result for one event: preflight→Inspect/Skip,
// body→Transform/PassThrough, trailers→empty result, session_end→nil.
// inspecting and maxPayloadBytes are pointers to per-stream-local state.
func (s *PreReturnService) onEvent(
	ev *middlewarev1.HttpResponseEvent,
	inspecting *bool,
	maxPayloadBytes *uint64,
) *middlewarev1.HttpResponseEventResult {
	if preflight := ev.GetPreflight(); preflight != nil {
		return s.onPreflightEvent(preflight, inspecting, maxPayloadBytes)
	}

	if body := ev.GetBody(); body != nil {
		return s.onBodyEvent(body, *inspecting, *maxPayloadBytes)
	}

	if ev.GetTrailers() != nil {
		return &middlewarev1.HttpResponseEventResult{
			Result: &middlewarev1.HttpResponseEventResult_TrailersResult{
				TrailersResult: &middlewarev1.HttpResponseTrailersResult{},
			},
		}
	}

	// session_end or unknown event type: no reply (defensive).
	return nil
}

// onPreflightEvent handles preflight events: Inspect if WHOLE_BODY_BYTES is permitted, else Skip.
func (s *PreReturnService) onPreflightEvent(
	preflight *middlewarev1.HttpResponsePreflight,
	inspecting *bool,
	maxPayloadBytes *uint64,
) *middlewarev1.HttpResponseEventResult {
	// Check if WHOLE_BODY_BYTES is permitted
	canInspect := slices.Contains(
		preflight.GetPermittedBodyModes(),
		middlewarev1.HttpResponseBodyMode_HTTP_RESPONSE_BODY_MODE_WHOLE_BODY_BYTES,
	)

	if canInspect {
		// Inspect with WHOLE_BODY_BYTES mode
		*inspecting = true
		*maxPayloadBytes = preflight.GetMaxPayloadBytes()
		return &middlewarev1.HttpResponseEventResult{
			Result: &middlewarev1.HttpResponseEventResult_PreflightResult{
				PreflightResult: &middlewarev1.HttpResponsePreflightResult{
					Action: &middlewarev1.HttpResponsePreflightResult_Inspect{
						Inspect: &middlewarev1.HttpResponsePreflightInspect{
							BodyMode: middlewarev1.HttpResponseBodyMode_HTTP_RESPONSE_BODY_MODE_WHOLE_BODY_BYTES,
						},
					},
				},
			},
		}
	}

	// Fall back to Skip
	*inspecting = false
	return &middlewarev1.HttpResponseEventResult{
		Result: &middlewarev1.HttpResponseEventResult_PreflightResult{
			PreflightResult: &middlewarev1.HttpResponsePreflightResult{
				Action: &middlewarev1.HttpResponsePreflightResult_Skip{
					Skip: &middlewarev1.HttpResponsePreflightSkip{},
				},
			},
		},
	}
}

// onBodyEvent handles body events: Transform if capability error detected, else PassThrough.
func (s *PreReturnService) onBodyEvent(
	body *middlewarev1.HttpResponseBodyUnit,
	inspecting bool,
	maxPayloadBytes uint64,
) *middlewarev1.HttpResponseEventResult {
	// Guard: pass through if not inspecting or no data
	if !inspecting || body.GetData() == nil {
		return &middlewarev1.HttpResponseEventResult{
			Result: &middlewarev1.HttpResponseEventResult_BodyResult{
				BodyResult: &middlewarev1.HttpResponseBodyResult{
					Sequence: body.GetSequence(),
					Action: &middlewarev1.HttpResponseBodyResult_PassThrough{
						PassThrough: &middlewarev1.HttpResponseBodyPassThrough{},
					},
				},
			},
		}
	}

	// Inspect the body for capability error
	bodyData := body.GetData()
	newBody, changed := surfaceCapabilityError(bodyData)

	// Guard: pass through if unchanged
	if !changed {
		return &middlewarev1.HttpResponseEventResult{
			Result: &middlewarev1.HttpResponseEventResult_BodyResult{
				BodyResult: &middlewarev1.HttpResponseBodyResult{
					Sequence: body.GetSequence(),
					Action: &middlewarev1.HttpResponseBodyResult_PassThrough{
						PassThrough: &middlewarev1.HttpResponseBodyPassThrough{},
					},
				},
			},
		}
	}

	// Guard: pass through if transformed exceeds MaxPayloadBytes
	if maxPayloadBytes > 0 && uint64(len(newBody)) > maxPayloadBytes {
		s.log.Warn("transformed body exceeds MaxPayloadBytes, passing through",
			"original_size", len(bodyData),
			"transformed_size", len(newBody),
			"max_payload_bytes", maxPayloadBytes)
		return &middlewarev1.HttpResponseEventResult{
			Result: &middlewarev1.HttpResponseEventResult_BodyResult{
				BodyResult: &middlewarev1.HttpResponseBodyResult{
					Sequence: body.GetSequence(),
					Action: &middlewarev1.HttpResponseBodyResult_PassThrough{
						PassThrough: &middlewarev1.HttpResponseBodyPassThrough{},
					},
				},
			},
		}
	}

	// Transform: inject the modified body
	return &middlewarev1.HttpResponseEventResult{
		Result: &middlewarev1.HttpResponseEventResult_BodyResult{
			BodyResult: &middlewarev1.HttpResponseBodyResult{
				Sequence: body.GetSequence(),
				Action: &middlewarev1.HttpResponseBodyResult_Transform{
					Transform: &middlewarev1.HttpResponseBodyTransform{
						Replacement: &middlewarev1.HttpResponseBodyTransform_Data{
							Data: newBody,
						},
					},
				},
			},
		},
	}
}

// surfaceCapabilityError detects a seller's structured capability error
// (error.data.required_capabilities non-empty array) and injects a top-level
// middleware_hint, preserving the original error object verbatim.
// Returns (newBody, true) if a hint was added, (respBody, false) otherwise.
// Never panics; malformed/non-JSON bodies return (respBody, false).
func surfaceCapabilityError(respBody []byte) ([]byte, bool) {
	// Parse as JSON into a map
	var m map[string]json.RawMessage
	if err := json.Unmarshal(respBody, &m); err != nil {
		// Malformed JSON → unchanged
		return respBody, false
	}

	// Check for error.data.required_capabilities
	errorRaw, ok := m["error"]
	if !ok {
		return respBody, false
	}

	var errorObj map[string]json.RawMessage
	if err := json.Unmarshal(errorRaw, &errorObj); err != nil {
		return respBody, false
	}

	dataRaw, ok := errorObj["data"]
	if !ok {
		return respBody, false
	}

	var dataObj map[string]json.RawMessage
	if err := json.Unmarshal(dataRaw, &dataObj); err != nil {
		return respBody, false
	}

	requiredCapsRaw, ok := dataObj["required_capabilities"]
	if !ok {
		return respBody, false
	}

	// Parse required_capabilities as an array
	var requiredCaps []string
	if err := json.Unmarshal(requiredCapsRaw, &requiredCaps); err != nil {
		return respBody, false
	}

	// Must be non-empty
	if len(requiredCaps) == 0 {
		return respBody, false
	}

	// Inject middleware_hint at the top level
	hint := map[string]any{
		"missing_capabilities": requiredCaps,
		"source":               "ans-egress",
	}
	hintBytes, err := json.Marshal(hint)
	if err != nil {
		// Should never happen with our simple struct
		return respBody, false
	}

	// Add middleware_hint to the top-level map
	m["middleware_hint"] = hintBytes

	// Re-marshal the entire response
	newBodyBytes, err := json.Marshal(m)
	if err != nil {
		return respBody, false
	}

	return newBodyBytes, true
}
