package syncer

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/n24q02m/skret/internal/provider"
)

// SyncState tracks per-secret SHA256(value) hashes for drift detection.
type SyncState struct {
	Target  string            `json:"target"`
	ID      string            `json:"id"`
	Hashes  map[string]string `json:"hashes"`
	Updated time.Time         `json:"updated"`

	// Mutation identity is persisted before an external write. It contains
	// target scope plus a value-free source digest, never secret values.
	OperationMethod string `json:"operation_method,omitempty"`
	SourceIdentity  string `json:"source_identity,omitempty"`
	SourceDigest    string `json:"source_digest,omitempty"`

	OperationID string                `json:"operation_id,omitempty"`
	Phase       OperationPhase        `json:"phase,omitempty"`
	Intent      string                `json:"intent,omitempty"`
	StartedAt   *time.Time            `json:"started_at,omitempty"`
	CompletedAt *time.Time            `json:"completed_at,omitempty"`
	LastSuccess *time.Time            `json:"last_success,omitempty"`
	Outcomes    map[string]KeyOutcome `json:"outcomes,omitempty"`
}

type OutcomeStatus string

const (
	OutcomePending             OutcomeStatus = "pending"
	OutcomeSucceeded           OutcomeStatus = "succeeded"
	OutcomeNeedsReconciliation OutcomeStatus = "needs_reconciliation"
)

type OperationPhase string

const (
	OperationPhasePending              OperationPhase = "pending"
	OperationPhaseAwaitingVerification OperationPhase = "awaiting_verification"
	OperationPhaseSucceeded            OperationPhase = "succeeded"
	OperationPhaseNeedsReconciliation  OperationPhase = "needs_reconciliation"
)

type KeyOutcome struct {
	Status           OutcomeStatus      `json:"status"`
	OperationID      string             `json:"operation_id,omitempty"`
	UpdatedAt        time.Time          `json:"updated_at"`
	Metadata         *OperationMetadata `json:"metadata,omitempty"`
	AcknowledgedHash string             `json:"acknowledged_hash,omitempty"`
}

// OperationMetadata contains only non-secret metadata needed to retain and
// reconcile one target operation. Secret-value hashes remain outside it.
type OperationMetadata struct {
	OldGeneration       uint64              `json:"old_generation,omitempty"`
	CurrentGeneration   uint64              `json:"current_generation"`
	IntendedGeneration  uint64              `json:"intended_generation"`
	LifecycleLabel      string              `json:"lifecycle_label"`
	KMSEnvelopeRef      string              `json:"kms_envelope_ref"`
	Capability          provider.Capability `json:"capability"`
	Deadline            *time.Time          `json:"deadline,omitempty"`
	Attempts            int                 `json:"attempts"`
	ReconciliationState ReconciliationState `json:"reconciliation_state,omitempty"`
	CanaryState         VerificationState   `json:"canary_state"`
	PostconditionState  VerificationState   `json:"postcondition_state"`
}

type ReconciliationState string

const (
	ReconciliationStatePending           ReconciliationState = "pending"
	ReconciliationStateOwnerRiskRequired ReconciliationState = "owner_risk_required"
	ReconciliationStateApproved          ReconciliationState = "approved"
)

type VerificationState string

const (
	VerificationStatePending VerificationState = "pending"
	VerificationStatePassed  VerificationState = "passed"
	VerificationStateFailed  VerificationState = "failed"
)

const maxOperationAttempts = 3

var (
	ErrOperationMismatch                  = errors.New("sync operation mismatch")
	ErrOperationKeyMismatch               = errors.New("sync operation key mismatch")
	ErrOperationPhaseMismatch             = errors.New("sync operation phase mismatch")
	ErrOperationEmpty                     = errors.New("sync operation has no owned keys")
	ErrOperationCapabilityInvalid         = errors.New("sync operation capability is invalid")
	ErrOperationCapabilityBlocked         = errors.New("sync operation capability is blocked")
	ErrOperationOwnerRiskApprovalRequired = errors.New("sync operation requires owner-risk reconciliation")
	ErrOperationVerificationRequired      = errors.New("sync operation requires canary and postcondition verification")
	ErrOperationDeadlineExceeded          = errors.New("sync operation deadline exceeded")
	ErrOperationNeedsReconciliation       = errors.New("sync operation needs provider reconciliation")
)

// NewOperationID returns a non-secret identifier for one sync attempt.
func NewOperationID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate sync operation id: %w", err)
	}
	return "op-" + hex.EncodeToString(raw[:]), nil
}

const OperationIntentRotate = "rotate"

func (s *SyncState) BeginOperation(operationID string, secrets []*provider.Secret, started time.Time) error {
	return s.beginOperation(operationID, "", secrets, started, nil)
}

func (s *SyncState) BeginOperationWithIntent(operationID, intent string, secrets []*provider.Secret, started time.Time) error {
	return s.beginOperation(operationID, intent, secrets, started, nil)
}

// BeginOperationWithMetadata starts an operation whose generation and
// capability metadata must survive until all owned keys acknowledge success.
// The metadata contains references only; it never stores a secret value.
func (s *SyncState) BeginOperationWithMetadata(operationID string, metadata OperationMetadata, secrets []*provider.Secret, started time.Time) error {
	return s.beginOperation(operationID, "", secrets, started, &metadata)
}

func (s *SyncState) beginOperation(operationID, intent string, secrets []*provider.Secret, started time.Time, metadata *OperationMetadata) error {
	if s.hasRetainedMetadataOperation() {
		return ErrOperationPhaseMismatch
	}
	if metadata != nil {
		normalized := cloneOperationMetadata(metadata)
		if normalized.OldGeneration == 0 {
			normalized.OldGeneration = normalized.CurrentGeneration
		}
		if normalized.CanaryState == "" {
			normalized.CanaryState = VerificationStatePending
		}
		if normalized.PostconditionState == "" {
			normalized.PostconditionState = VerificationStatePending
		}
		if err := normalized.validate(started); err != nil {
			return err
		}
		metadata = normalized
	}
	if strings.TrimSpace(operationID) == "" {
		return fmt.Errorf("sync operation id is required")
	}
	for _, secret := range secrets {
		if secret == nil {
			return fmt.Errorf("sync operation contains nil secret")
		}
	}
	if s.Outcomes == nil {
		s.Outcomes = make(map[string]KeyOutcome)
	}
	if s.operationPending() {
		previousOperationID := s.OperationID
		for key, outcome := range s.Outcomes {
			if outcome.Status != OutcomePending ||
				(outcome.OperationID != "" && outcome.OperationID != previousOperationID) {
				continue
			}
			outcome.Status = OutcomeNeedsReconciliation
			if outcome.OperationID == "" {
				outcome.OperationID = previousOperationID
			}
			if outcome.Metadata != nil {
				outcome.Metadata.ReconciliationState = reconciliationStateFor(outcome.Metadata.Capability)
			}
			outcome.UpdatedAt = started
			s.Outcomes[key] = outcome
		}
	}
	s.OperationID = operationID
	s.Phase = OperationPhasePending
	s.Intent = intent
	s.StartedAt = timePtr(started)
	s.CompletedAt = nil
	for _, secret := range secrets {
		s.Outcomes[secret.Key] = KeyOutcome{
			Status:      OutcomePending,
			OperationID: operationID,
			UpdatedAt:   started,
			Metadata:    cloneOperationMetadata(metadata),
		}
	}
	return nil
}

func (s *SyncState) RecordSuccess(operationID string, secrets []*provider.Secret, completed time.Time) error {
	if err := s.checkOperation(operationID); err != nil {
		return err
	}
	if err := s.validateBatch(operationID, secrets, OutcomeSucceeded); err != nil {
		return err
	}
	for _, secret := range secrets {
		if err := s.recordKeySuccess(operationID, secret, completed); err != nil {
			return err
		}
	}
	return s.FinalizeOperation(operationID, completed)
}

func (s *SyncState) RecordNeedsReconciliation(operationID string, secrets []*provider.Secret, completed time.Time) error {
	if err := s.checkOperation(operationID); err != nil {
		return err
	}
	if err := s.validateBatch(operationID, secrets, OutcomeNeedsReconciliation); err != nil {
		return err
	}
	for _, secret := range secrets {
		if err := s.recordKeyNeedsReconciliation(operationID, secret, completed); err != nil {
			return err
		}
	}
	return nil
}

// RecordKeySuccess records one owned target acknowledgement. Metadata-aware
// operations defer the drift-cache update until verification also passes.
func (s *SyncState) RecordKeySuccess(operationID string, secret *provider.Secret, completed time.Time) error {
	if err := s.checkOperation(operationID); err != nil {
		return err
	}
	return s.recordKeySuccess(operationID, secret, completed)
}

func (s *SyncState) recordKeySuccess(operationID string, secret *provider.Secret, completed time.Time) error {
	outcome, err := s.ownedOutcome(operationID, secret)
	if err != nil {
		return err
	}
	if outcome.Metadata != nil {
		if err := outcome.Metadata.validatePersisted(outcome.Status); err != nil {
			return err
		}
	}
	acknowledgedHash := hashSecret(secret.Value)
	if outcome.Status == OutcomeSucceeded {
		if outcome.Metadata != nil && outcome.AcknowledgedHash != acknowledgedHash {
			return ErrOperationKeyMismatch
		}
		return nil
	}
	if outcome.Metadata != nil &&
		outcome.Metadata.Deadline != nil &&
		completed.After(*outcome.Metadata.Deadline) {
		return s.rejectCapability(secret.Key, outcome, completed, ErrOperationDeadlineExceeded)
	}
	if outcome.Metadata != nil {
		switch outcome.Metadata.Capability {
		case provider.CapabilityNativeCAS, provider.CapabilityEnforcedExclusive:
		case provider.CapabilityOwnerRiskGate:
			if !ownerRiskApproved(outcome) {
				return s.rejectCapability(secret.Key, outcome, completed, ErrOperationOwnerRiskApprovalRequired)
			}
		case provider.CapabilityBlocked:
			return s.rejectCapability(secret.Key, outcome, completed, ErrOperationCapabilityBlocked)
		default:
			return s.rejectCapability(secret.Key, outcome, completed, ErrOperationCapabilityInvalid)
		}
	}
	if outcome.Status == OutcomeNeedsReconciliation && !ownerRiskApproved(outcome) {
		return ErrOperationPhaseMismatch
	}
	outcome.Status = OutcomeSucceeded
	outcome.UpdatedAt = completed
	if outcome.Metadata != nil {
		outcome.AcknowledgedHash = acknowledgedHash
	} else {
		s.Update([]*provider.Secret{secret})
	}
	s.Outcomes[secret.Key] = outcome
	return nil
}

// RecordKeyNeedsReconciliation records one owned secret acknowledgement that
// cannot be treated as successful. It never updates that secret's hash.
func (s *SyncState) RecordKeyNeedsReconciliation(operationID string, secret *provider.Secret, completed time.Time) error {
	if err := s.checkOperation(operationID); err != nil {
		return err
	}
	return s.recordKeyNeedsReconciliation(operationID, secret, completed)
}

func (s *SyncState) recordKeyNeedsReconciliation(operationID string, secret *provider.Secret, completed time.Time) error {
	outcome, err := s.ownedOutcome(operationID, secret)
	if err != nil {
		return err
	}
	if outcome.Metadata != nil {
		if err := outcome.Metadata.validatePersisted(outcome.Status); err != nil {
			return err
		}
	}
	if outcome.Status == OutcomeSucceeded {
		return ErrOperationPhaseMismatch
	}
	if outcome.Status == OutcomeNeedsReconciliation {
		return nil
	}
	outcome.Status = OutcomeNeedsReconciliation
	outcome.UpdatedAt = completed
	if outcome.Metadata != nil {
		outcome.Metadata.ReconciliationState = reconciliationStateFor(outcome.Metadata.Capability)
	}
	s.Outcomes[secret.Key] = outcome
	s.Phase = OperationPhaseNeedsReconciliation
	s.CompletedAt = timePtr(completed)
	return nil
}

// ApproveOwnerRiskReconciliation records the explicit owner-risk decision
// needed before an ambiguous target can be acknowledged as success.
func (s *SyncState) ApproveOwnerRiskReconciliation(operationID, key string, approvedAt time.Time) error {
	if err := s.checkOperation(operationID); err != nil {
		return err
	}
	outcome, ok := s.Outcomes[key]
	if !ok || outcome.OperationID != operationID {
		return ErrOperationKeyMismatch
	}
	if outcome.Status != OutcomeNeedsReconciliation || outcome.Metadata == nil {
		return ErrOperationPhaseMismatch
	}
	if err := outcome.Metadata.validatePersisted(outcome.Status); err != nil {
		return err
	}
	if outcome.Metadata.Capability != provider.CapabilityOwnerRiskGate {
		return ErrOperationCapabilityInvalid
	}
	if outcome.Metadata.ReconciliationState == ReconciliationStateApproved {
		return nil
	}
	outcome.Metadata.ReconciliationState = ReconciliationStateApproved
	outcome.UpdatedAt = approvedAt
	s.Outcomes[key] = outcome
	return nil
}

func (s *SyncState) rejectCapability(key string, outcome KeyOutcome, completed time.Time, rejection error) error {
	if outcome.Status != OutcomeNeedsReconciliation {
		outcome.Status = OutcomeNeedsReconciliation
		outcome.UpdatedAt = completed
		if outcome.Metadata != nil {
			outcome.Metadata.ReconciliationState = reconciliationStateFor(outcome.Metadata.Capability)
		}
		s.Outcomes[key] = outcome
		s.Phase = OperationPhaseNeedsReconciliation
		s.CompletedAt = timePtr(completed)
	}
	return rejection
}

func ownerRiskApproved(outcome KeyOutcome) bool {
	return outcome.Metadata != nil &&
		outcome.Metadata.Capability == provider.CapabilityOwnerRiskGate &&
		outcome.Metadata.ReconciliationState == ReconciliationStateApproved
}

func reconciliationStateFor(capability provider.Capability) ReconciliationState {
	if capability == provider.CapabilityOwnerRiskGate {
		return ReconciliationStateOwnerRiskRequired
	}
	return ReconciliationStatePending
}

func cloneOperationMetadata(metadata *OperationMetadata) *OperationMetadata {
	if metadata == nil {
		return nil
	}
	clone := *metadata
	if metadata.Deadline != nil {
		deadline := *metadata.Deadline
		clone.Deadline = &deadline
	}
	return &clone
}

func (metadata *OperationMetadata) validate(started time.Time) error {
	if metadata == nil {
		return nil
	}
	if metadata.IntendedGeneration <= metadata.CurrentGeneration ||
		metadata.OldGeneration > metadata.CurrentGeneration {
		return fmt.Errorf("sync operation generation order is invalid")
	}
	if metadata.Capability == "" || !metadata.Capability.Valid() {
		return fmt.Errorf("%w: %q", ErrOperationCapabilityInvalid, metadata.Capability)
	}
	if !validOperationReference(metadata.LifecycleLabel) {
		return fmt.Errorf("sync operation lifecycle label is invalid")
	}
	if !validOperationReference(metadata.KMSEnvelopeRef) {
		return fmt.Errorf("sync operation KMS envelope reference is invalid")
	}
	if metadata.Deadline == nil || !metadata.Deadline.After(started) {
		return fmt.Errorf("sync operation deadline must follow its start")
	}
	if metadata.Attempts < 0 || metadata.Attempts > maxOperationAttempts {
		return fmt.Errorf("sync operation attempts are out of range")
	}
	if metadata.ReconciliationState != "" {
		return fmt.Errorf("sync operation reconciliation state must start empty")
	}
	if metadata.CanaryState != VerificationStatePending ||
		metadata.PostconditionState != VerificationStatePending {
		return fmt.Errorf("sync operation verification state must start pending")
	}
	return nil
}

func (metadata *OperationMetadata) validatePersisted(status OutcomeStatus) error {
	if metadata == nil {
		return nil
	}
	switch status {
	case OutcomePending, OutcomeSucceeded, OutcomeNeedsReconciliation:
	default:
		return fmt.Errorf("sync operation outcome status is invalid")
	}
	if !metadata.Capability.Valid() {
		return fmt.Errorf("%w: persisted operation metadata", ErrOperationCapabilityInvalid)
	}
	if metadata.Attempts < 0 || metadata.Attempts > maxOperationAttempts {
		return fmt.Errorf("sync operation attempts are out of range")
	}
	if !metadata.validVerificationStates() {
		return fmt.Errorf("sync operation verification state is invalid")
	}
	retained := metadata.referencesRetained()
	promoted := metadata.generationPromoted()
	if retained == promoted {
		return fmt.Errorf("sync operation generation retention state is invalid")
	}
	if promoted {
		if status != OutcomeSucceeded || !metadata.verificationPassed() {
			return fmt.Errorf("promoted sync operation is not verified")
		}
	} else if status == OutcomePending && metadata.CanaryState != VerificationStatePending {
		return fmt.Errorf("pending sync operation cannot have verification evidence")
	}
	switch metadata.ReconciliationState {
	case "":
		if metadata.Capability == provider.CapabilityOwnerRiskGate &&
			status == OutcomeNeedsReconciliation {
			return fmt.Errorf("owner-risk metadata requires explicit reconciliation state")
		}
	case ReconciliationStatePending:
		if metadata.Capability == provider.CapabilityOwnerRiskGate ||
			status != OutcomeNeedsReconciliation {
			return fmt.Errorf("pending reconciliation state is not valid for this capability")
		}
	case ReconciliationStateOwnerRiskRequired:
		if metadata.Capability != provider.CapabilityOwnerRiskGate ||
			status != OutcomeNeedsReconciliation {
			return fmt.Errorf("owner-risk reconciliation state is not pending")
		}
	case ReconciliationStateApproved:
		if metadata.Capability != provider.CapabilityOwnerRiskGate ||
			(status != OutcomeNeedsReconciliation && status != OutcomeSucceeded) {
			return fmt.Errorf("owner-risk approval state is not valid")
		}
	default:
		return fmt.Errorf("sync operation reconciliation state is invalid")
	}
	if metadata.Capability == provider.CapabilityBlocked && status == OutcomeSucceeded {
		return ErrOperationCapabilityBlocked
	}
	return nil
}

func (metadata *OperationMetadata) referencesRetained() bool {
	return metadata.IntendedGeneration > metadata.CurrentGeneration &&
		metadata.OldGeneration <= metadata.CurrentGeneration &&
		validOperationReference(metadata.LifecycleLabel) &&
		validOperationReference(metadata.KMSEnvelopeRef) &&
		metadata.Deadline != nil &&
		!metadata.Deadline.IsZero()
}

func (metadata *OperationMetadata) generationPromoted() bool {
	return metadata.IntendedGeneration > 0 &&
		metadata.CurrentGeneration == metadata.IntendedGeneration &&
		metadata.OldGeneration == 0 &&
		metadata.LifecycleLabel == "" &&
		metadata.KMSEnvelopeRef == "" &&
		metadata.Deadline == nil
}

func (metadata *OperationMetadata) validVerificationStates() bool {
	switch metadata.CanaryState {
	case VerificationStatePending:
		return metadata.PostconditionState == VerificationStatePending
	case VerificationStateFailed:
		return metadata.PostconditionState == VerificationStatePending
	case VerificationStatePassed:
		switch metadata.PostconditionState {
		case VerificationStatePending, VerificationStatePassed, VerificationStateFailed:
			return true
		}
	}
	return false
}

func (metadata *OperationMetadata) verificationPassed() bool {
	return metadata.CanaryState == VerificationStatePassed &&
		metadata.PostconditionState == VerificationStatePassed
}

func (metadata *OperationMetadata) verificationFailed() bool {
	return metadata.CanaryState == VerificationStateFailed ||
		metadata.PostconditionState == VerificationStateFailed
}

func validOperationReference(value string) bool {
	if value == "" || len(value) > 512 {
		return false
	}
	for index := range len(value) {
		character := value[index]
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') {
			continue
		}
		switch character {
		case '-', '_', '.', ':', '/':
			continue
		default:
			return false
		}
	}
	return true
}

func outcomeCapabilityAllowsSuccess(outcome KeyOutcome) bool {
	if outcome.Metadata == nil {
		return true
	}
	switch outcome.Metadata.Capability {
	case provider.CapabilityNativeCAS, provider.CapabilityEnforcedExclusive:
		return true
	case provider.CapabilityOwnerRiskGate:
		return ownerRiskApproved(outcome)
	default:
		return false
	}
}

func promoteMetadata(metadata *OperationMetadata) {
	if metadata == nil {
		return
	}
	metadata.CurrentGeneration = metadata.IntendedGeneration
	metadata.OldGeneration = 0
	metadata.LifecycleLabel = ""
	metadata.KMSEnvelopeRef = ""
	metadata.Deadline = nil
	if metadata.Capability != provider.CapabilityOwnerRiskGate {
		metadata.ReconciliationState = ""
	}
}

func (s *SyncState) validateBatch(operationID string, secrets []*provider.Secret, status OutcomeStatus) error {
	if len(secrets) == 0 {
		return ErrOperationEmpty
	}
	for _, secret := range secrets {
		outcome, err := s.ownedOutcome(operationID, secret)
		if err != nil {
			return err
		}
		switch {
		case status == OutcomeSucceeded &&
			outcome.Status == OutcomeNeedsReconciliation &&
			!ownerRiskApproved(outcome):
			return ErrOperationPhaseMismatch
		case status == OutcomeNeedsReconciliation && outcome.Status == OutcomeSucceeded:
			return ErrOperationPhaseMismatch
		}
	}
	return nil
}

func (s *SyncState) ownedOutcome(operationID string, secret *provider.Secret) (KeyOutcome, error) {
	if secret == nil {
		return KeyOutcome{}, fmt.Errorf("sync operation contains nil secret")
	}
	if strings.TrimSpace(secret.Key) == "" {
		return KeyOutcome{}, fmt.Errorf("sync operation key is required")
	}
	outcome, ok := s.Outcomes[secret.Key]
	if !ok || outcome.OperationID != operationID {
		return KeyOutcome{}, ErrOperationKeyMismatch
	}
	return outcome, nil
}

// RecordOperationVerification records the canary and postcondition result for
// an operation whose target acknowledgements are already complete.
func (s *SyncState) RecordOperationVerification(
	operationID string,
	canaryPassed bool,
	postconditionsPassed bool,
	completed time.Time,
) error {
	if err := s.checkOperation(operationID); err != nil {
		return err
	}
	if s.Phase != OperationPhaseAwaitingVerification {
		return ErrOperationPhaseMismatch
	}
	owned := 0
	deadlineExceeded := false
	for _, outcome := range s.Outcomes {
		if outcome.OperationID == operationID &&
			outcome.Metadata != nil &&
			outcome.Metadata.Deadline != nil &&
			completed.After(*outcome.Metadata.Deadline) {
			deadlineExceeded = true
			break
		}
	}
	if deadlineExceeded {
		canaryPassed = false
		postconditionsPassed = false
	}
	for key, outcome := range s.Outcomes {
		if outcome.OperationID != operationID {
			continue
		}
		owned++
		if outcome.Status != OutcomeSucceeded || outcome.Metadata == nil ||
			!validAcknowledgedHash(outcome.AcknowledgedHash) {
			return ErrOperationPhaseMismatch
		}
		if canaryPassed {
			outcome.Metadata.CanaryState = VerificationStatePassed
			if postconditionsPassed {
				outcome.Metadata.PostconditionState = VerificationStatePassed
			} else {
				outcome.Metadata.PostconditionState = VerificationStateFailed
			}
		} else {
			outcome.Metadata.CanaryState = VerificationStateFailed
			outcome.Metadata.PostconditionState = VerificationStatePending
		}
		outcome.UpdatedAt = completed
		if !canaryPassed || !postconditionsPassed {
			outcome.Status = OutcomeNeedsReconciliation
			outcome.Metadata.ReconciliationState = reconciliationStateFor(outcome.Metadata.Capability)
		}
		s.Outcomes[key] = outcome
	}
	if owned == 0 {
		return ErrOperationEmpty
	}
	if !canaryPassed || !postconditionsPassed {
		s.Phase = OperationPhaseNeedsReconciliation
		s.CompletedAt = timePtr(completed)
		if deadlineExceeded {
			return ErrOperationDeadlineExceeded
		}
		return nil
	}
	return s.FinalizeOperation(operationID, completed)
}

func validAcknowledgedHash(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for index := range len(value) {
		character := value[index]
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func (s *SyncState) FinalizeOperation(operationID string, completed time.Time) error {
	if err := s.checkOperation(operationID); err != nil {
		return err
	}
	owned := 0
	metadataOwned := 0
	hasPending := false
	hasNeedsReconciliation := false
	verificationPending := false
	verificationFailed := false
	for key, outcome := range s.Outcomes {
		if outcome.OperationID != operationID {
			continue
		}
		owned++
		if outcome.Metadata != nil {
			metadataOwned++
			if err := outcome.Metadata.validatePersisted(outcome.Status); err != nil {
				return fmt.Errorf("validate sync operation outcome %q: %w", key, err)
			}
			if outcome.Status == OutcomeSucceeded &&
				outcome.Metadata.referencesRetained() &&
				!validAcknowledgedHash(outcome.AcknowledgedHash) {
				return fmt.Errorf("validate sync operation outcome %q: missing acknowledgement hash", key)
			}
			verificationPending = verificationPending || !outcome.Metadata.verificationPassed()
			verificationFailed = verificationFailed || outcome.Metadata.verificationFailed()
		}
		switch outcome.Status {
		case OutcomeSucceeded:
			if !outcomeCapabilityAllowsSuccess(outcome) {
				outcome.Status = OutcomeNeedsReconciliation
				outcome.UpdatedAt = completed
				if outcome.Metadata != nil {
					outcome.Metadata.ReconciliationState = reconciliationStateFor(outcome.Metadata.Capability)
				}
				s.Outcomes[key] = outcome
				hasNeedsReconciliation = true
			}
		case OutcomeNeedsReconciliation:
			hasNeedsReconciliation = true
		default:
			hasPending = true
		}
	}
	if owned == 0 {
		return ErrOperationEmpty
	}
	if metadataOwned != 0 && metadataOwned != owned {
		return ErrOperationPhaseMismatch
	}
	if hasNeedsReconciliation || verificationFailed {
		s.Phase = OperationPhaseNeedsReconciliation
		if s.CompletedAt == nil {
			s.CompletedAt = timePtr(completed)
		}
		return nil
	}
	if hasPending {
		s.Phase = OperationPhasePending
		s.CompletedAt = nil
		return nil
	}
	if metadataOwned > 0 && verificationPending {
		s.Phase = OperationPhaseAwaitingVerification
		s.CompletedAt = nil
		return nil
	}
	if s.Phase == OperationPhaseSucceeded {
		return nil
	}
	if s.Hashes == nil {
		s.Hashes = make(map[string]string)
	}
	for key, outcome := range s.Outcomes {
		if outcome.OperationID != operationID || outcome.Status != OutcomeSucceeded {
			continue
		}
		if outcome.Metadata != nil {
			s.Hashes[key] = outcome.AcknowledgedHash
			outcome.AcknowledgedHash = ""
			promoteMetadata(outcome.Metadata)
			s.Outcomes[key] = outcome
		}
	}
	s.Phase = OperationPhaseSucceeded
	s.CompletedAt = timePtr(completed)
	s.LastSuccess = timePtr(completed)
	return nil
}

func (s *SyncState) operationPending() bool {
	if s.OperationID == "" {
		return false
	}
	if s.Phase == OperationPhasePending ||
		s.Phase == OperationPhaseAwaitingVerification ||
		(s.Phase == "" && s.CompletedAt == nil) {
		return true
	}
	for _, outcome := range s.Outcomes {
		if outcome.OperationID == s.OperationID && outcome.Status == OutcomePending {
			return true
		}
	}
	return false
}

// RequiresReconciliation reports whether starting another external mutation
// would replay an incomplete or ambiguous operation. A pending operation whose
// every owned key already succeeded is the sole recoverable case: callers may
// finalize it without issuing provider requests.
func (s *SyncState) RequiresReconciliation() bool {
	if s == nil || s.OperationID == "" || s.Phase == OperationPhaseSucceeded {
		return false
	}
	switch s.Phase {
	case OperationPhaseNeedsReconciliation, OperationPhaseAwaitingVerification:
		return true
	}
	for _, outcome := range s.Outcomes {
		if outcome.OperationID == s.OperationID && outcome.Status != OutcomeSucceeded {
			return true
		}
	}
	return false
}

func (s *SyncState) hasRetainedMetadataOperation() bool {
	if s.OperationID == "" || s.Phase == OperationPhaseSucceeded {
		return false
	}
	for _, outcome := range s.Outcomes {
		if outcome.OperationID == s.OperationID &&
			outcome.Metadata != nil &&
			!outcome.Metadata.generationPromoted() {
			return true
		}
	}
	return false
}

func (s *SyncState) checkOperation(operationID string) error {
	if operationID == "" || operationID != s.OperationID {
		return fmt.Errorf("%w: got %q, want %q", ErrOperationMismatch, operationID, s.OperationID)
	}
	return nil
}

func timePtr(value time.Time) *time.Time {
	copyOfValue := value
	return &copyOfValue
}

// StatePathFor returns the on-disk path for the given target+id.
// Exposed for testing; production code uses LoadSyncState/SaveSyncState.
func StatePathFor(target, id string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("user home dir: %w", err)
	}

	baseDir := filepath.Join(home, ".skret", "sync-state")
	expectedName := "v1-" + encodeStatePath(target, id) + ".json"
	constructedPath := filepath.Join(baseDir, expectedName)

	rel, err := filepath.Rel(baseDir, constructedPath)
	if err != nil || rel != expectedName || filepath.Base(rel) != rel {
		return "", fmt.Errorf("sync state path traversal attempt detected")
	}

	return constructedPath, nil
}

// encodeStatePath is an injective, filename-safe encoding of both state
// identity components. Encoding the pair as one JSON array avoids delimiter
// collisions even when either component contains separators or punctuation.
func encodeStatePath(target, id string) string {
	data, _ := json.Marshal([2]string{target, id})
	return base64.RawURLEncoding.EncodeToString(data)
}

func (s *SyncState) validatePersistedOperationMetadata() error {
	if s.OperationMethod != "" && !validOperationReference(s.OperationMethod) {
		return fmt.Errorf("validate sync state operation method: invalid operation method")
	}
	if len(s.SourceIdentity) > 512 {
		return fmt.Errorf("validate sync state source identity: too long")
	}
	if s.SourceDigest != "" && !validAcknowledgedHash(s.SourceDigest) {
		return fmt.Errorf("validate sync state source digest: invalid digest")
	}
	currentMetadata := 0
	for key, outcome := range s.Outcomes {
		if outcome.Metadata == nil {
			if outcome.AcknowledgedHash != "" {
				return fmt.Errorf("validate sync state outcome %q: unexpected acknowledgement hash", key)
			}
			continue
		}
		if err := outcome.Metadata.validatePersisted(outcome.Status); err != nil {
			return fmt.Errorf("validate sync state outcome %q: %w", key, err)
		}
		if outcome.AcknowledgedHash != "" && !validAcknowledgedHash(outcome.AcknowledgedHash) {
			return fmt.Errorf("validate sync state outcome %q: invalid acknowledgement hash", key)
		}
		if outcome.Metadata.referencesRetained() && outcome.OperationID != s.OperationID {
			return fmt.Errorf("validate sync state outcome %q: orphaned retained generation", key)
		}
		if outcome.OperationID != s.OperationID {
			continue
		}
		currentMetadata++
		switch s.Phase {
		case OperationPhaseSucceeded:
			if !outcome.Metadata.generationPromoted() || outcome.AcknowledgedHash != "" {
				return fmt.Errorf("validate sync state outcome %q: success is not promoted", key)
			}
		case OperationPhaseAwaitingVerification:
			if outcome.Status != OutcomeSucceeded ||
				!outcome.Metadata.referencesRetained() ||
				!validAcknowledgedHash(outcome.AcknowledgedHash) ||
				outcome.Metadata.verificationFailed() {
				return fmt.Errorf("validate sync state outcome %q: invalid verification wait", key)
			}
		default:
			if outcome.Metadata.generationPromoted() {
				return fmt.Errorf("validate sync state outcome %q: premature generation promotion", key)
			}
		}
	}
	if s.Phase == OperationPhaseAwaitingVerification && currentMetadata == 0 {
		return ErrOperationVerificationRequired
	}
	return nil
}

// LoadSyncState reads the state file for target+id, returning an empty
// state if the file does not exist (first-run case).
func LoadSyncState(target, id string) (*SyncState, error) {
	path, err := StatePathFor(target, id)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &SyncState{Target: target, ID: id, Hashes: map[string]string{}}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read sync state %q: %w", path, err)
	}
	var s SyncState
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse sync state %q: %w", path, err)
	}
	if s.Target != target || s.ID != id {
		return nil, fmt.Errorf("sync state identity mismatch: stored %q/%q, requested %q/%q", s.Target, s.ID, target, id)
	}
	if s.Hashes == nil {
		s.Hashes = map[string]string{}
	}
	if err := s.validatePersistedOperationMetadata(); err != nil {
		return nil, err
	}
	return &s, nil
}

var syncStateSaveMu sync.Mutex

// SaveSyncState writes the state atomically. The directory is created with
// 0700 and the file with 0600 so secret-name presence is owner-only readable.
func SaveSyncState(s *SyncState) error {
	syncStateSaveMu.Lock()
	defer syncStateSaveMu.Unlock()
	if err := s.validatePersistedOperationMetadata(); err != nil {
		return err
	}

	path, err := StatePathFor(s.Target, s.ID)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create sync state dir: %w", err)
	}
	s.Updated = time.Now().UTC()
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal sync state: %w", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create sync state temp: %w", err)
	}
	tmpPath := tmp.Name()
	keepTemp := false
	defer func() {
		_ = tmp.Close()
		if !keepTemp {
			_ = os.Remove(tmpPath)
		}
	}()

	if err := tmp.Chmod(0o600); err != nil {
		return fmt.Errorf("chmod sync state temp: %w", err)
	}
	n, err := tmp.Write(data)
	if err != nil {
		return fmt.Errorf("write sync state: %w", err)
	}
	if n != len(data) {
		return fmt.Errorf("write sync state: short write (%d/%d bytes)", n, len(data))
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync sync state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close sync state: %w", err)
	}
	if err := durableReplace(tmpPath, path, filepath.Dir(path)); err != nil {
		return fmt.Errorf("rename sync state: %w", err)
	}
	keepTemp = true
	return nil
}

// SourceDigest returns a deterministic value-free digest for a source batch.
// It binds each source key to its SHA256(value), then sorts the pairs so
// caller ordering cannot change the operation identity.
func SourceDigest(secrets []*provider.Secret) string {
	pairs := make([]string, 0, len(secrets))
	for _, secret := range secrets {
		if secret == nil {
			pairs = append(pairs, "<nil>")
			continue
		}
		pairs = append(pairs, secret.Key+"\x00"+hashSecret(secret.Value))
	}
	sort.Strings(pairs)
	digest := sha256.Sum256([]byte(strings.Join(pairs, "\x00")))
	return hex.EncodeToString(digest[:])
}

// hashSecret returns hex-encoded SHA256 of the secret value.
func hashSecret(value string) string {
	h := sha256.Sum256([]byte(value))
	return hex.EncodeToString(h[:])
}

// FilterUnchanged returns only the secrets whose hash differs from the state.
// Secrets not present in the state are included (treated as new).
func (s *SyncState) FilterUnchanged(secrets []*provider.Secret) []*provider.Secret {
	out := make([]*provider.Secret, 0, len(secrets))
	for _, sec := range secrets {
		if s.Hashes[sec.Key] != hashSecret(sec.Value) {
			out = append(out, sec)
		}
	}
	return out
}

// Update records the hashes of the given secrets in-place.
func (s *SyncState) Update(secrets []*provider.Secret) {
	if s.Hashes == nil {
		s.Hashes = map[string]string{}
	}
	for _, sec := range secrets {
		s.Hashes[sec.Key] = hashSecret(sec.Value)
	}
}
