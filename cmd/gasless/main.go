package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/demo-lenoir/gasless-policy-engine/internal/admission"
	"github.com/demo-lenoir/gasless-policy-engine/internal/httpapi"
	"github.com/demo-lenoir/gasless-policy-engine/internal/issuance"
	"github.com/demo-lenoir/gasless-policy-engine/internal/policy"
	"github.com/demo-lenoir/gasless-policy-engine/internal/reconcile"
	"github.com/demo-lenoir/gasless-policy-engine/internal/signing"
	"github.com/demo-lenoir/gasless-policy-engine/internal/store"
	"github.com/demo-lenoir/gasless-policy-engine/internal/telemetry"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--selfcheck" {
		fmt.Printf("gasless runtime: %s/%s\n", runtime.GOOS, runtime.GOARCH)
		return
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, logger); err != nil {
		logger.Error("service stopped", "error", err)
		os.Exit(1)
	}
}

func required(name string) (string, error) {
	v := os.Getenv(name)
	if v == "" {
		return "", fmt.Errorf("%s is required", name)
	}
	return v, nil
}

func run(ctx context.Context, logger *slog.Logger) error {
	shutdownTrace, err := telemetry.ConfigureTracing(ctx)
	if err != nil {
		return err
	}
	defer func() {
		flush, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = shutdownTrace(flush)
	}()
	listen, err := required("GASLESS_LISTEN")
	if err != nil {
		return err
	}
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return err
	}
	if host != "127.0.0.1" && host != "localhost" && host != "::1" && os.Getenv("GASLESS_DEV_BIND_ANY") != "1" {
		return errors.New("development signer requires loopback listener")
	}
	dsn, err := required("GASLESS_PG_DSN")
	if err != nil {
		return err
	}
	rpcURL, err := required("GASLESS_RPC_URL")
	if err != nil {
		return err
	}
	token, err := required("GASLESS_API_TOKEN")
	if err != nil {
		return err
	}
	if len(token) < 32 {
		return errors.New("API token must contain at least 32 characters")
	}
	scope, err := required("GASLESS_CLIENT_SCOPE")
	if err != nil {
		return err
	}
	keyText, err := required("GASLESS_DEV_SIGNER_KEY")
	if err != nil {
		return err
	}
	keyBytes, err := hex.DecodeString(strings.TrimPrefix(keyText, "0x"))
	if err != nil || len(keyBytes) != 32 {
		return errors.New("invalid development signer key")
	}
	var key *ecdsa.PrivateKey
	key, err = crypto.ToECDSA(keyBytes)
	if err != nil {
		return errors.New("invalid development signer key")
	}
	signer, err := signing.NewDevLocalSigner(key, true)
	if err != nil {
		return err
	}
	policyPath, err := required("GASLESS_POLICY_FILE")
	if err != nil {
		return err
	}
	admissionPath, err := required("GASLESS_ADMISSION_FILE")
	if err != nil {
		return err
	}
	policyRaw, err := os.ReadFile(policyPath)
	if err != nil {
		return err
	}
	admissionRaw, err := os.ReadFile(admissionPath)
	if err != nil {
		return err
	}
	config, err := admission.ReadConfigJSON(admissionRaw)
	if err != nil {
		return err
	}
	if len(config.IssuanceProfiles) != 1 {
		return errors.New("local service requires one issuance profile")
	}
	profile := config.IssuanceProfiles[0]
	chainValue, err := policy.ParseUint256(profile.ChainID)
	if err != nil {
		return err
	}
	chain := policy.ChainID{Uint256: chainValue}
	entry, err := policy.ParseAddress(profile.EntryPoint)
	if err != nil {
		return err
	}
	paymaster, err := policy.ParseAddress(profile.Paymaster)
	if err != nil {
		return err
	}
	expectedSigner, err := policy.ParseAddress(profile.ExpectedSigner)
	if err != nil {
		return err
	}
	if signerAddress, err := signer.Address(ctx); err != nil || signerAddress != expectedSigner {
		return errors.New("development signer identity differs from configured profile")
	}
	accountHash := common.HexToHash(profile.AccountCodeHash)
	if accountHash == (common.Hash{}) {
		return errors.New("account code hash required")
	}
	snapshot, err := policy.ReadSnapshotJSON(policyRaw)
	if err != nil {
		return err
	}
	startup, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	database, err := store.Open(startup, dsn, 16, 5*time.Second)
	if err != nil {
		return err
	}
	defer database.Close()
	rpc, err := ethclient.DialContext(startup, rpcURL)
	if err != nil {
		return err
	}
	defer rpc.Close()
	registry := prometheus.NewRegistry()
	metrics, err := telemetry.New(registry)
	if err != nil {
		return err
	}
	admitter, err := admission.NewService(policyRaw, config, database)
	if err != nil {
		return err
	}
	issuer, err := issuance.NewService(issuance.Config{PolicyVersion: snapshot.Version(), ChainID: chain, EntryPoint: entry, Paymaster: paymaster, AccountCodeHash: accountHash, ExpectedSigner: expectedSigner, ClaimLease: 20 * time.Second, SignerTimeout: 5 * time.Second}, database, signer, time.Now)
	if err != nil {
		return err
	}
	database.SetObserver(metrics)
	admitter.SetObserver(metrics)
	issuer.SetObserver(metrics)
	stream := reconcile.Stream{ChainID: chain, EntryPoint: entry, Paymaster: paymaster, ID: "local-v0.9", Confirmations: 3, MaxReorgDepth: 8, MaxBlocks: 1000}
	watcher := reconcile.Worker{Stream: stream, Reader: rpc, Repository: database, Observer: metrics}
	deposit := func(ctx context.Context) (string, error) {
		selector := crypto.Keccak256([]byte("balanceOf(address)"))[:4]
		data := make([]byte, 36)
		copy(data[:4], selector)
		copy(data[16:], paymaster[:])
		to := common.Address(entry)
		out, err := rpc.CallContract(ctx, ethereum.CallMsg{To: &to, Data: data}, nil)
		if err != nil {
			return "", err
		}
		if len(out) != 32 {
			return "", errors.New("invalid EntryPoint deposit response")
		}
		balance := new(big.Int).SetBytes(out).String()
		metrics.PaymasterBalance(balance)
		return balance, nil
	}
	api := &httpapi.Server{Admitter: admitter, Issuer: issuer, Store: database, Stream: stream, Reader: rpc, Watcher: watcher, Signer: signer, ExpectedSigner: expectedSigner, Deposit: deposit, DepositLowWei: "100000000000000000", DepositCriticalWei: "10000000000000000", AuthToken: token, ClientScope: scope, Now: time.Now, Metrics: promhttp.HandlerFor(registry, promhttp.HandlerOpts{}), Logger: logger}
	handler, err := api.Handler()
	if err != nil {
		return err
	}
	if err := metrics.RefreshFromLedger(startup, database, time.Now().UTC(), config.GlobalDailyBudgetWei); err != nil {
		return err
	}
	if err := watcher.RunOnce(startup, time.Now().UTC()); err != nil {
		logger.Warn("initial reconciliation delayed", "reason", err.Error())
	}
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				work, stop := context.WithTimeout(ctx, 5*time.Second)
				if err := watcher.RunOnce(work, time.Now().UTC()); err != nil {
					logger.Warn("reconciliation delayed", "reason", err.Error())
				}
				if err := metrics.RefreshFromLedger(work, database, time.Now().UTC(), config.GlobalDailyBudgetWei); err != nil {
					logger.Warn("metric refresh failed")
				}
				stop()
			}
		}
	}()
	server := &http.Server{Addr: listen, Handler: handler, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 8 * time.Second, WriteTimeout: 12 * time.Second, IdleTimeout: 30 * time.Second}
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		shutdown, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		_ = server.Shutdown(shutdown)
	}()
	logger.Info("service listening", "address", listen)
	err = server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
