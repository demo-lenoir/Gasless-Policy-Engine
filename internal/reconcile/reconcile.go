package reconcile

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/big"
	"time"

	"github.com/demo-lenoir/gasless-policy-engine/internal/policy"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"go.opentelemetry.io/otel"
)

var EventTopic = crypto.Keccak256Hash([]byte("UserOperationEvent(bytes32,address,address,uint256,bool,uint256,uint256)"))
var ErrStaleCheckpoint = errors.New("reconciliation checkpoint changed")
var ErrManualIntervention = errors.New("settlement requires manual intervention")

type Stream struct {
	ChainID             policy.ChainID
	EntryPoint          policy.Address
	Paymaster           policy.Address
	ID                  string
	Confirmations       uint64
	MaxReorgDepth       uint64
	MaxBlocks           uint64
	ExpectedCodeHash    common.Hash
	ExpectedGenesisHash common.Hash
	Recovering          bool
}

func (s Stream) Validate() error {
	if s.ChainID.IsZero() || s.EntryPoint.IsZero() || s.Paymaster.IsZero() || len(s.ID) == 0 || len(s.ID) > 64 || s.Confirmations == 0 || s.Confirmations > math.MaxInt64 || s.MaxReorgDepth == 0 || s.MaxReorgDepth > math.MaxInt64 || s.MaxBlocks == 0 || s.MaxBlocks > 1000 {
		return errors.New("invalid reconciliation stream")
	}
	return nil
}

type Checkpoint struct {
	Number uint64
	Hash   common.Hash
	Time   time.Time
	State  string
	Exists bool
}

type Event struct {
	UserOpHash                          common.Hash
	Sender, Paymaster                   common.Address
	Nonce, ActualGasCost, ActualGasUsed *big.Int
	Success                             bool
	BlockHash                           common.Hash
	BlockNumber                         uint64
	TxHash                              common.Hash
	LogIndex                            uint
}

func DecodeEvent(log types.Log, s Stream) (Event, error) {
	if log.Address != common.Address(s.EntryPoint) || log.Removed || len(log.Topics) != 4 || log.Topics[0] != EventTopic || len(log.Data) != 128 || log.BlockHash == (common.Hash{}) || log.TxHash == (common.Hash{}) {
		return Event{}, errors.New("invalid EntryPoint event identity")
	}
	sender := common.BytesToAddress(log.Topics[2].Bytes())
	paymaster := common.BytesToAddress(log.Topics[3].Bytes())
	if log.Topics[2] != common.BytesToHash(sender.Bytes()) || log.Topics[3] != common.BytesToHash(paymaster.Bytes()) || paymaster != common.Address(s.Paymaster) {
		return Event{}, errors.New("event paymaster or indexed address differs")
	}
	if new(big.Int).SetBytes(log.Data[32:64]).Cmp(big.NewInt(1)) > 0 {
		return Event{}, errors.New("invalid event success encoding")
	}
	return Event{UserOpHash: log.Topics[1], Sender: sender, Paymaster: paymaster,
		Nonce: new(big.Int).SetBytes(log.Data[:32]), Success: log.Data[63] == 1,
		ActualGasCost: new(big.Int).SetBytes(log.Data[64:96]), ActualGasUsed: new(big.Int).SetBytes(log.Data[96:128]),
		BlockHash: log.BlockHash, BlockNumber: log.BlockNumber, TxHash: log.TxHash, LogIndex: log.Index}, nil
}

type Reader interface {
	ChainID(context.Context) (*big.Int, error)
	CodeAt(context.Context, common.Address, *big.Int) ([]byte, error)
	HeaderByNumber(context.Context, *big.Int) (*types.Header, error)
	FilterLogs(context.Context, ethereum.FilterQuery) ([]types.Log, error)
}

type Repository interface {
	Checkpoint(context.Context, Stream) (Checkpoint, error)
	CheckpointAt(context.Context, Stream, uint64) (common.Hash, error)
	ApplyBlock(context.Context, Stream, Checkpoint, *types.Header, []Event, time.Time) error
	RollbackTo(context.Context, Stream, Checkpoint, uint64, common.Hash, time.Time) error
	Settle(context.Context, Stream, time.Time, int) (int, error)
	MarkManual(context.Context, Stream, string, time.Time) error
}

type Worker struct {
	Stream     Stream
	Reader     Reader
	Repository Repository
	Observer   interface{ ReconciliationProgress(uint64, uint64, bool) }
}

func (w Worker) Readiness(ctx context.Context) error {
	if err := w.VerifyReader(ctx); err != nil {
		return err
	}
	checkpoint, err := w.Repository.Checkpoint(ctx, w.Stream)
	if err != nil {
		return err
	}
	if !checkpoint.Exists || checkpoint.State != "HEALTHY" {
		return ErrManualIntervention
	}
	return nil
}

func (w Worker) VerifyReader(ctx context.Context) error {
	if err := w.Stream.Validate(); err != nil {
		return err
	}
	if w.Reader == nil || w.Repository == nil {
		return errors.New("reader and repository required")
	}
	chain, err := w.Reader.ChainID(ctx)
	if err != nil {
		return err
	}
	if chain.Cmp(w.Stream.ChainID.Big()) != 0 {
		return errors.New("wrong RPC chain")
	}
	code, err := w.Reader.CodeAt(ctx, common.Address(w.Stream.EntryPoint), nil)
	if err != nil {
		return err
	}
	if len(code) == 0 {
		return errors.New("EntryPoint code absent")
	}
	if w.Stream.ExpectedCodeHash != (common.Hash{}) && crypto.Keccak256Hash(code) != w.Stream.ExpectedCodeHash {
		return errors.New("EntryPoint runtime code hash differs")
	}
	header, err := w.Reader.HeaderByNumber(ctx, nil)
	if err != nil {
		return err
	}
	if header == nil || !header.Number.IsUint64() || header.Number.Uint64() > math.MaxInt64 {
		return errors.New("invalid RPC head")
	}
	hash := header.Hash()
	if _, err = w.Reader.FilterLogs(ctx, ethereum.FilterQuery{BlockHash: &hash, Addresses: []common.Address{common.Address(w.Stream.EntryPoint)}, Topics: [][]common.Hash{{EventTopic}, nil, nil, {common.BytesToHash(w.Stream.Paymaster[:])}}}); err != nil {
		return err
	}
	if w.Stream.ExpectedGenesisHash != (common.Hash{}) {
		genesis, err := w.Reader.HeaderByNumber(ctx, big.NewInt(0))
		if err != nil {
			return err
		}
		if genesis == nil || genesis.Hash() != w.Stream.ExpectedGenesisHash {
			return errors.New("genesis anchor differs")
		}
	}
	return nil
}

func (w Worker) RunOnce(ctx context.Context, now time.Time) error {
	ctx, span := otel.Tracer("gasless/reconcile").Start(ctx, "reconciliation.rpc_scan")
	defer span.End()
	if now.IsZero() {
		return errors.New("explicit observation time required")
	}
	if err := w.VerifyReader(ctx); err != nil {
		return err
	}
	checkpoint, err := w.Repository.Checkpoint(ctx, w.Stream)
	if err != nil {
		return err
	}
	if checkpoint.State == "MANUAL_INTERVENTION" && !w.Stream.Recovering {
		return ErrManualIntervention
	}
	reorged := false
	head, err := w.Reader.HeaderByNumber(ctx, nil)
	if err != nil {
		return err
	}
	if head == nil {
		return errors.New("nil RPC head")
	}
	if !head.Number.IsUint64() || head.Number.Uint64() > math.MaxInt64 {
		return errors.New("head number exceeds uint64")
	}
	headNumber := head.Number.Uint64()
	if checkpoint.Exists {
		matches := false
		if checkpoint.Number <= headNumber {
			current, err := w.Reader.HeaderByNumber(ctx, new(big.Int).SetUint64(checkpoint.Number))
			if err != nil {
				return err
			}
			if current == nil {
				return errors.New("missing checkpoint header")
			}
			matches = current.Hash() == checkpoint.Hash
		}
		if !matches {
			ancestor := checkpoint.Number
			found := false
			var ancestorHash common.Hash
			for depth := uint64(1); depth <= w.Stream.MaxReorgDepth && ancestor > 0; depth++ {
				ancestor--
				if ancestor > headNumber {
					continue
				}
				old, err := w.Repository.CheckpointAt(ctx, w.Stream, ancestor)
				if err != nil {
					return err
				}
				newHeader, err := w.Reader.HeaderByNumber(ctx, new(big.Int).SetUint64(ancestor))
				if err != nil {
					return err
				}
				if newHeader == nil {
					return errors.New("missing ancestor header")
				}
				if old == newHeader.Hash() {
					found = true
					ancestorHash = old
					break
				}
			}
			if !found {
				if err := w.Repository.MarkManual(ctx, w.Stream, "DEEP_REORG", now); err != nil {
					return err
				}
				return ErrManualIntervention
			}
			if err := w.Repository.RollbackTo(ctx, w.Stream, checkpoint, ancestor, ancestorHash, now); err != nil {
				return err
			}
			reorged = true
			checkpoint, err = w.Repository.Checkpoint(ctx, w.Stream)
			if err != nil {
				return err
			}
		}
	}
	start := uint64(0)
	if checkpoint.Exists {
		start = checkpoint.Number + 1
	}
	for height, count := start, uint64(0); height <= headNumber && count < w.Stream.MaxBlocks; height, count = height+1, count+1 {
		header, err := w.Reader.HeaderByNumber(ctx, new(big.Int).SetUint64(height))
		if err != nil {
			return err
		}
		if header == nil {
			return errors.New("missing catch-up header")
		}
		if !header.Number.IsUint64() || header.Number.Uint64() != height || (checkpoint.Exists && header.ParentHash != checkpoint.Hash) {
			return errors.New("noncontiguous RPC header")
		}
		blockHash := header.Hash()
		logs, err := w.Reader.FilterLogs(ctx, ethereum.FilterQuery{BlockHash: &blockHash, Addresses: []common.Address{common.Address(w.Stream.EntryPoint)}, Topics: [][]common.Hash{{EventTopic}, nil, nil, {common.BytesToHash(w.Stream.Paymaster[:])}}})
		if err != nil {
			return err
		}
		events := make([]Event, 0, len(logs))
		for _, log := range logs {
			if log.BlockHash != blockHash || log.BlockNumber != height {
				return errors.New("RPC log does not belong to requested block")
			}
			if len(log.Topics) == 4 && log.Topics[0] == EventTopic && log.Topics[3] != common.BytesToHash(w.Stream.Paymaster[:]) {
				continue
			}
			event, err := DecodeEvent(log, w.Stream)
			if err != nil {
				return err
			}
			events = append(events, event)
		}
		if err := w.Repository.ApplyBlock(ctx, w.Stream, checkpoint, header, events, now); err != nil {
			if errors.Is(err, ErrStaleCheckpoint) {
				return nil
			}
			return err
		}
		checkpoint = Checkpoint{Number: height, Hash: blockHash, Time: time.Unix(int64(header.Time), 0).UTC(), State: checkpoint.State, Exists: true}
		if checkpoint.State == "" {
			checkpoint.State = "HEALTHY"
		}
	}
	if w.Stream.Recovering {
		if w.Observer != nil {
			w.Observer.ReconciliationProgress(headNumber, checkpoint.Number, reorged)
		}
		return nil
	}
	_, err = w.Repository.Settle(ctx, w.Stream, now, 100)
	if err != nil {
		return err
	}
	if w.Observer != nil {
		w.Observer.ReconciliationProgress(headNumber, checkpoint.Number, reorged)
	}
	return nil
}

func Confirmations(head, event uint64) uint64 {
	if event > head {
		return 0
	}
	return head - event + 1
}

func (w Worker) Run(ctx context.Context, interval time.Duration, now func() time.Time) error {
	if interval <= 0 || now == nil {
		return errors.New("invalid watcher schedule")
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := w.RunOnce(ctx, now()); err != nil {
			return fmt.Errorf("reconciliation stopped: %w", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
