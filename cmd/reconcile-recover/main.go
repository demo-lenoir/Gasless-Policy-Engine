package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/demo-lenoir/gasless-policy-engine/internal/admission"
	"github.com/demo-lenoir/gasless-policy-engine/internal/policy"
	"github.com/demo-lenoir/gasless-policy-engine/internal/reconcile"
	"github.com/demo-lenoir/gasless-policy-engine/internal/store"
	"github.com/ethereum/go-ethereum/ethclient"
)

func main() {
	var height uint64
	var apply bool
	var configPath string
	flag.Uint64Var(&height, "height", 0, "last trusted common-ancestor block")
	flag.BoolVar(&apply, "apply", false, "perform bounded replay after a safe dry run")
	flag.StringVar(&configPath, "admission", "config/admission.example.json", "admission configuration with the current issuance profile")
	flag.Parse()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if err := run(ctx, configPath, height, apply); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, path string, height uint64, apply bool) error {
	dsn, rpcURL := os.Getenv("GASLESS_PG_DSN"), os.Getenv("GASLESS_RPC_URL")
	if dsn == "" || rpcURL == "" {
		return errors.New("GASLESS_PG_DSN and GASLESS_RPC_URL are required")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	cfg, err := admission.ReadConfigJSON(raw)
	if err != nil {
		return err
	}
	if len(cfg.IssuanceProfiles) != 1 {
		return errors.New("one issuance profile required")
	}
	profile := cfg.IssuanceProfiles[0]
	id, err := policy.ParseUint256(profile.ChainID)
	if err != nil {
		return err
	}
	entry, err := policy.ParseAddress(profile.EntryPoint)
	if err != nil {
		return err
	}
	paymaster, err := policy.ParseAddress(profile.Paymaster)
	if err != nil {
		return err
	}
	s := reconcile.Stream{ChainID: policy.ChainID{Uint256: id}, EntryPoint: entry, Paymaster: paymaster, ID: "local-v0.9", Confirmations: 3, MaxReorgDepth: 8, MaxBlocks: 1000}
	db, err := store.Open(ctx, dsn, 4, 5*time.Second)
	if err != nil {
		return err
	}
	defer db.Close()
	rpc, err := ethclient.DialContext(ctx, rpcURL)
	if err != nil {
		return err
	}
	defer rpc.Close()
	w := reconcile.Worker{Stream: s, Reader: rpc, Repository: db}
	if err := w.VerifyReader(ctx); err != nil {
		return err
	}
	remote, err := rpc.HeaderByNumber(ctx, new(big.Int).SetUint64(height))
	if err != nil {
		return err
	}
	if remote == nil {
		return errors.New("proposed remote block absent")
	}
	plan, err := db.PlanRecovery(ctx, s, height, remote.Hash())
	if err != nil {
		return err
	}
	if err := json.NewEncoder(os.Stdout).Encode(plan); err != nil {
		return err
	}
	if !apply {
		return nil
	}
	if !plan.Safe {
		return reconcile.ErrManualIntervention
	}
	cp, err := db.Checkpoint(ctx, s)
	if err != nil {
		return err
	}
	recovery := s
	recovery.Recovering = true
	if err := db.RollbackTo(ctx, recovery, cp, height, remote.Hash(), time.Now().UTC()); err != nil {
		return err
	}
	w.Stream = recovery
	for attempt := 0; attempt < 100; attempt++ {
		if err := w.RunOnce(ctx, time.Now().UTC()); err != nil {
			return err
		}
		cp, err = db.Checkpoint(ctx, s)
		if err != nil {
			return err
		}
		head, err := rpc.HeaderByNumber(ctx, nil)
		if err != nil {
			return err
		}
		if head != nil && head.Number.IsUint64() && cp.Number == head.Number.Uint64() && cp.Hash == head.Hash() {
			if err := db.CompleteRecovery(ctx, s, cp.Number, cp.Hash, time.Now().UTC()); err != nil {
				return err
			}
			w.Stream = s
			if err := w.RunOnce(ctx, time.Now().UTC()); err != nil {
				return err
			}
			fmt.Println("recovery complete: canonical scan converged")
			return nil
		}
	}
	return errors.New("bounded recovery did not converge")
}
