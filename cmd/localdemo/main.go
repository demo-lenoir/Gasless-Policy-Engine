package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/demo-lenoir/gasless-policy-engine/internal/admission"
	"github.com/demo-lenoir/gasless-policy-engine/internal/httpapi"
	"github.com/demo-lenoir/gasless-policy-engine/internal/issuance"
	"github.com/demo-lenoir/gasless-policy-engine/internal/policy"
	"github.com/demo-lenoir/gasless-policy-engine/internal/reconcile"
	"github.com/demo-lenoir/gasless-policy-engine/internal/signing"
	"github.com/demo-lenoir/gasless-policy-engine/internal/store"
	"github.com/demo-lenoir/gasless-policy-engine/internal/telemetry"
	"github.com/demo-lenoir/gasless-policy-engine/internal/userop"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type contractArtifact struct {
	ABI      json.RawMessage `json:"abi"`
	Bytecode struct {
		Object string `json:"object"`
	} `json:"bytecode"`
}

type contract struct {
	address common.Address
	abi     abi.ABI
	code    []byte
}

type chain struct {
	rpc *rpc.Client
	eth *ethclient.Client
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if err := run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	rpcURL, dsn, output := os.Getenv("LOCAL_ANVIL_RPC_URL"), os.Getenv("LOCAL_PG_DSN"), os.Getenv("LOCAL_DEPLOYMENT_METADATA")
	bundlerURL := os.Getenv("LOCAL_BUNDLER_RPC_URL")
	mode := os.Getenv("LOCAL_DEMO_MODE")
	if mode == "" {
		mode = "success"
	}
	if mode != "success" && mode != "reverted" && mode != "unused" && mode != "unknown-no-inclusion" && mode != "response-lost" {
		return errors.New("unsupported local scenario")
	}
	if rpcURL == "" || dsn == "" || output == "" {
		return errors.New("local Anvil, PostgreSQL, and metadata path are required")
	}
	rawRPC, err := rpc.DialContext(ctx, rpcURL)
	if err != nil {
		return err
	}
	defer rawRPC.Close()
	c := chain{rpc: rawRPC, eth: ethclient.NewClient(rawRPC)}
	chainID, err := c.eth.ChainID(ctx)
	if err != nil || chainID.Cmp(big.NewInt(31337)) != 0 {
		return errors.New("local chain ID must be 31337")
	}
	var accounts []common.Address
	if err := c.rpc.CallContext(ctx, &accounts, "eth_accounts"); err != nil || len(accounts) < 2 {
		return errors.New("Anvil must expose two unlocked local accounts")
	}
	deployer, relayer := accounts[0], accounts[1]
	ownerKey, err := testKey(2)
	if err != nil {
		return err
	}
	owner := crypto.PubkeyToAddress(ownerKey.PublicKey)
	sponsorKey, err := testKey(1)
	if err != nil {
		return err
	}
	sponsorSigner, err := signing.NewDevLocalSigner(sponsorKey, true)
	if err != nil {
		return err
	}
	sponsor := crypto.PubkeyToAddress(sponsorKey.PublicKey)

	entrySource, err := loadContract("out/EntryPoint.sol/EntryPoint.json")
	if err != nil {
		return err
	}
	accountSource, err := loadContract("out/DemoAccount.sol/DemoAccount.json")
	if err != nil {
		return err
	}
	counterSource, err := loadContract("out/DemoCounter.sol/DemoCounter.json")
	if err != nil {
		return err
	}
	paymasterSource, err := loadContract("out/PolicyPaymaster.sol/PolicyPaymaster.json")
	if err != nil {
		return err
	}
	var entry contract
	var entryReceipt *types.Receipt
	if bundlerURL == "" {
		entry, entryReceipt, err = c.deploy(ctx, deployer, entrySource)
		if err != nil {
			return fmt.Errorf("deploy EntryPoint: %w", err)
		}
	} else {
		entry = entrySource
		entry.address = common.HexToAddress("0x433709009B8330FDa32311DF1C2AFA402eD8D009")
		entryReceipt, err = c.eth.TransactionReceipt(ctx, common.HexToHash(os.Getenv("LOCAL_ENTRYPOINT_DEPLOYMENT_TX")))
		if err != nil || entryReceipt.Status != types.ReceiptStatusSuccessful {
			return errors.New("canonical EntryPoint deployment receipt missing")
		}
		code, codeErr := c.eth.CodeAt(ctx, entry.address, nil)
		if codeErr != nil || len(code) == 0 {
			return errors.New("canonical EntryPoint has no deployed code")
		}
	}
	entryCode, err := c.eth.CodeAt(ctx, entry.address, nil)
	if err != nil || len(entryCode) == 0 {
		return errors.New("EntryPoint has no deployed code")
	}
	entryCodeHash := crypto.Keccak256Hash(entryCode)
	if bundlerURL != "" && entryCodeHash != common.HexToHash("0x94c969b899cb2a68ac9c124d8ee104a047771ee988f155b4e4683c254291f805") {
		return errors.New("canonical local EntryPoint runtime code hash differs from pinned fixture")
	}
	account, accountReceipt, err := c.deploy(ctx, deployer, accountSource, entry.address, owner)
	if err != nil {
		return fmt.Errorf("deploy account: %w", err)
	}
	accountCode, err := c.eth.CodeAt(ctx, account.address, nil)
	if err != nil || len(accountCode) == 0 {
		return errors.New("deployed account has no code")
	}
	accountCodeHash := crypto.Keccak256Hash(accountCode)
	counter, counterReceipt, err := c.deploy(ctx, deployer, counterSource)
	if err != nil {
		return fmt.Errorf("deploy counter: %w", err)
	}
	paymaster, paymasterReceipt, err := c.deploy(ctx, deployer, paymasterSource,
		entry.address, deployer, sponsor, accountCodeHash)
	if err != nil {
		return fmt.Errorf("deploy paymaster: %w", err)
	}
	zeroBalance, err := c.eth.BalanceAt(ctx, account.address, nil)
	if err != nil || zeroBalance.Sign() != 0 {
		return errors.New("smart account must begin with zero native balance")
	}
	depositCall, err := paymaster.abi.Pack("deposit")
	if err != nil {
		return err
	}
	depositReceipt, err := c.send(ctx, deployer, &paymaster.address, depositCall, new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
	if err != nil {
		return fmt.Errorf("fund EntryPoint deposit: %w", err)
	}
	depositBefore, err := c.uintView(ctx, paymaster, "getDeposit")
	if err != nil || depositBefore.Cmp(new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)) != 0 {
		return errors.New("paymaster EntryPoint deposit was not funded")
	}

	inner, err := counter.abi.Pack("increment", [32]byte{1})
	if mode == "reverted" {
		inner, err = counter.abi.Pack("fail")
	}
	if err != nil {
		return err
	}
	outer, err := account.abi.Pack("execute", counter.address, big.NewInt(0), inner)
	if err != nil {
		return err
	}
	selector := "0x" + hex.EncodeToString(inner[:4])
	staticRaw, err := os.ReadFile("config/policy.example.json")
	if err != nil {
		return err
	}
	var static policy.Config
	if err := json.Unmarshal(staticRaw, &static); err != nil {
		return err
	}
	static.Chains[0].EntryPoint = entry.address.Hex()
	static.Chains[0].Targets = []policy.TargetConfig{{Address: counter.address.Hex(), Selectors: []string{selector}}}
	static.MaxPaymasterVerificationGas = "500000"
	staticJSON, err := json.Marshal(static)
	if err != nil {
		return err
	}
	accounting := admission.Config{
		NativeAsset: "ETH", GlobalDailyBudgetWei: "1000000000000000000",
		Chains: []admission.ChainLimit{{ChainID: "31337", NativeAsset: "ETH", DailyBudgetWei: "500000000000000000", SenderDailyWei: "100000000000000000", SenderDailyCount: 20}},
		IssuanceProfiles: []admission.IssuerProfileConfig{{ChainID: "31337", Paymaster: paymaster.address.Hex(), EntryPoint: entry.address.Hex(),
			AccountCodeHash: accountCodeHash.Hex(), ExpectedSigner: sponsor.Hex()}},
	}
	database, err := store.Open(ctx, dsn, 8, 5*time.Second)
	if err != nil {
		return err
	}
	defer database.Close()
	admitter, err := admission.NewService(staticJSON, accounting, database)
	if err != nil {
		return err
	}
	header, err := c.eth.HeaderByNumber(ctx, nil)
	if err != nil {
		return err
	}
	// EntryPoint requires block.timestamp to be strictly greater than validAfter.
	decisionTime := time.Unix(int64(header.Time)-1, 0).UTC()
	input := policy.RequestInput{
		ChainID: "31337", EntryPoint: entry.address.Hex(), Sender: account.address.Hex(), Nonce: "0",
		CallData: "0x" + hex.EncodeToString(outer), CallGasLimit: "300000", VerificationGasLimit: "300000",
		PreVerificationGas: "50000", PaymasterVerificationGasLimit: "300000", PaymasterPostOpGasLimit: "0",
		MaxFeePerGas: "10000000000", MaxPriorityFeePerGas: "1000000000",
	}
	issuer, err := issuance.NewService(issuance.Config{
		PolicyVersion: static.Version, ChainID: mustChainID(), Paymaster: toPolicyAddress(paymaster.address),
		EntryPoint: toPolicyAddress(entry.address), AccountCodeHash: accountCodeHash, ExpectedSigner: toPolicyAddress(sponsor),
		ClaimLease: 20 * time.Second, SignerTimeout: 5 * time.Second,
	}, database, sponsorSigner, func() time.Time { return decisionTime.Add(time.Second) })
	if err != nil {
		return err
	}
	stream := reconcile.Stream{ChainID: mustChainID(), EntryPoint: toPolicyAddress(entry.address), Paymaster: toPolicyAddress(paymaster.address), ID: "local-v0.9", Confirmations: 3, MaxReorgDepth: 8, MaxBlocks: 1000, ExpectedCodeHash: entryCodeHash}
	watcher := reconcile.Worker{Stream: stream, Reader: c.eth, Repository: database}
	var admitted admission.Result
	var issued issuance.Artifact
	var apiServer *httptest.Server
	var apiToken string
	var demoMetrics *telemetry.Metrics
	if os.Getenv("LOCAL_DEMO_API") == "1" {
		registry := prometheus.NewRegistry()
		demoMetrics, err = telemetry.New(registry)
		if err != nil {
			return err
		}
		admitter.SetObserver(demoMetrics)
		issuer.SetObserver(demoMetrics)
		database.SetObserver(demoMetrics)
		watcher.Observer = demoMetrics
		if err := watcher.RunOnce(ctx, time.Now().UTC()); err != nil {
			return err
		}
		var tokenBytes [32]byte
		if _, err := crand.Read(tokenBytes[:]); err != nil {
			return err
		}
		apiToken = hex.EncodeToString(tokenBytes[:])
		api := &httpapi.Server{Admitter: admitter, Issuer: issuer, Store: database, Stream: stream, Reader: c.eth, Watcher: watcher,
			Signer: sponsorSigner, ExpectedSigner: toPolicyAddress(sponsor), AuthToken: apiToken, ClientScope: "local-demo",
			DepositLowWei: "100000000000000000", DepositCriticalWei: "10000000000000000", Now: func() time.Time { return decisionTime },
			Deposit: func(ctx context.Context) (string, error) {
				value, err := c.uintView(ctx, paymaster, "getDeposit")
				if err != nil {
					return "", err
				}
				demoMetrics.PaymasterBalance(value.String())
				return value.String(), nil
			},
			Metrics: promhttp.HandlerFor(registry, promhttp.HandlerOpts{}), Logger: slog.New(slog.NewJSONHandler(io.Discard, nil))}
		handler, err := api.Handler()
		if err != nil {
			return err
		}
		apiServer = httptest.NewServer(handler)
		defer apiServer.Close()
		response, status, err := demoSponsorship(ctx, apiServer.URL, apiToken, "local-demo-request-0001", input)
		if err != nil || status != 201 || response.Decision != "approved" {
			return fmt.Errorf("HTTP sponsorship: %d %s %v", status, response.Reason, err)
		}
		admitted = admission.Result{Approved: true, Reason: admission.Approved, SponsorshipID: strings.TrimPrefix(response.SponsorshipID, "0x"), PolicyVersion: response.PolicyVersion, EstimatedUpperBoundWei: response.EstimatedUpperBoundWei, ValidAfter: response.ValidAfter, ValidUntil: response.ValidUntil}
		responseRetry, retryStatus, err := demoSponsorship(ctx, apiServer.URL, apiToken, "local-demo-request-0001", input)
		if err != nil || retryStatus != 200 || responseRetry.SponsorshipID != response.SponsorshipID || responseRetry.Authorization.PaymasterAndData != response.Authorization.PaymasterAndData {
			return errors.New("HTTP idempotent retry changed authorization")
		}
		if os.Getenv("LOCAL_DEMO_FULL") == "1" {
			const retries = 20
			var group sync.WaitGroup
			failures := make(chan error, retries)
			for range retries {
				group.Add(1)
				go func() {
					defer group.Done()
					got, status, err := demoSponsorship(ctx, apiServer.URL, apiToken, "local-demo-request-0001", input)
					if err != nil || status != 200 || got.SponsorshipID != response.SponsorshipID || got.Authorization.PaymasterAndData != response.Authorization.PaymasterAndData {
						failures <- fmt.Errorf("concurrent HTTP retry: status=%d err=%v", status, err)
					}
				}()
			}
			group.Wait()
			close(failures)
			for failure := range failures {
				return failure
			}
		}
		changedInput := input
		changedInput.Nonce = "1"
		_, conflictStatus, err := demoSponsorship(ctx, apiServer.URL, apiToken, "local-demo-request-0001", changedInput)
		if err != nil || conflictStatus != 409 {
			return errors.New("HTTP idempotency conflict was not rejected")
		}
		var id [32]byte
		decoded, _ := hex.DecodeString(admitted.SponsorshipID)
		copy(id[:], decoded)
		artifact, err := database.ReadAuthorization(ctx, id)
		if err != nil || artifact == nil {
			return errors.New("HTTP authorization artifact missing")
		}
		issued = *artifact
		if response.Authorization.PaymasterAndData != "0x"+hex.EncodeToString(issued.PaymasterAndData[:]) {
			return errors.New("HTTP artifact differs from durable authorization")
		}
	} else {
		admitted, err = admitter.Admit(ctx, "local-demo", "local-demo-request-0001", input, decisionTime)
		if err != nil || !admitted.Approved {
			return fmt.Errorf("admission denied: %s/%s: %v", admitted.Reason, admitted.PolicyReason, err)
		}
		var reason issuance.Reason
		issued, reason, err = issuer.Issue(ctx, admitted.SponsorshipID)
		if err != nil || reason != issuance.Issued {
			return fmt.Errorf("authorization unavailable: %s: %w", reason, err)
		}
	}
	normalized, err := policy.Normalize(input)
	if err != nil {
		return err
	}
	op, err := userop.Build(normalized, issued)
	if err != nil {
		return err
	}
	hashOutput, err := c.view(ctx, entry, "getUserOpHash", op)
	if err != nil || len(hashOutput) != 1 {
		return fmt.Errorf("getUserOpHash: %w", err)
	}
	userOpHash := hashOutput[0].([32]byte)
	computedHash, err := userop.Hash(op, mustChainID(), toPolicyAddress(entry.address))
	if err != nil || computedHash != userOpHash {
		return errors.New("local UserOperation hash differs from EntryPoint")
	}
	if mode == "unused" || mode == "unknown-no-inclusion" {
		if err := watcher.RunOnce(ctx, time.Now().UTC()); err != nil {
			return err
		}
		var ignored any
		if err := c.rpc.CallContext(ctx, &ignored, "evm_setNextBlockTimestamp", hexutil.EncodeUint64(uint64(issued.ValidUntil.Unix()+1))); err != nil {
			return err
		}
		if err := c.rpc.CallContext(ctx, &ignored, "anvil_mine", 3); err != nil {
			return err
		}
		if err := watcher.RunOnce(ctx, issued.ValidUntil.Add(2*time.Second)); err != nil {
			return err
		}
		var status, outcome, held string
		if err := database.Pool().QueryRow(ctx, `SELECT r.status,r.outcome_state,b.held_wei::text FROM sponsorship_reservations r JOIN budget_periods b ON b.chain_id=0 AND b.period_start=r.period_start AND b.scope='ALL_CHAINS' WHERE r.sponsorship_id=$1`, issued.SponsorshipID[:]).Scan(&status, &outcome, &held); err != nil || status != "EXPIRED" || outcome != "EXPIRED_UNUSED" || held != "0" {
			return fmt.Errorf("unused authorization accounting: %s/%s held=%s: %w", status, outcome, held, err)
		}
		return writeMetadata(output, map[string]any{"mode": mode, "sponsorship_id": admitted.SponsorshipID, "user_op_hash": common.BytesToHash(userOpHash[:]).Hex(), "reserved_upper_bound_wei": admitted.EstimatedUpperBoundWei, "settlement_status": status, "settlement_outcome": outcome, "budget_held_wei": held, "actual_gas_cost_wei": "0", "released_hold_wei": admitted.EstimatedUpperBoundWei})
	}
	accountSignature, err := crypto.Sign(userOpHash[:], ownerKey)
	if err != nil {
		return err
	}
	accountSignature[64] += 27
	op = op.WithAccountSignature(accountSignature)
	call, err := entry.abi.Pack("handleOps", []userop.Packed{op}, relayer)
	if err != nil {
		return err
	}
	// Before inclusion the owner may authorize a changed call, but the old sponsor artifact must reject it.
	changed := op.WithAccountSignature(accountSignature)
	changed.CallData[len(changed.CallData)-1] ^= 1
	changedHash, err := c.view(ctx, entry, "getUserOpHash", changed)
	if err != nil || len(changedHash) != 1 {
		return fmt.Errorf("mutated getUserOpHash: %w", err)
	}
	changedDigest := changedHash[0].([32]byte)
	changedSignature, err := crypto.Sign(changedDigest[:], ownerKey)
	if err != nil {
		return err
	}
	changedSignature[64] += 27
	changed.Signature = changedSignature
	mutatedCall, err := entry.abi.Pack("handleOps", []userop.Packed{changed}, relayer)
	if err != nil {
		return err
	}
	if _, err = c.eth.CallContract(ctx, ethereum.CallMsg{From: relayer, To: &entry.address, Data: mutatedCall, Gas: 8_000_000}, nil); err == nil {
		return errors.New("mutated calldata was accepted by EntryPoint")
	}
	if _, err = c.eth.CallContract(ctx, ethereum.CallMsg{From: relayer, To: &entry.address, Data: call, Gas: 8_000_000}, nil); err != nil {
		return fmt.Errorf("direct validation simulation: %w", err)
	}
	var receipt *types.Receipt
	if bundlerURL == "" {
		receipt, err = c.send(ctx, relayer, &entry.address, call, nil)
	} else {
		receipt, err = c.sendViaBundler(ctx, bundlerURL, entry.address, op, userOpHash, mode == "response-lost")
	}
	if err != nil {
		return fmt.Errorf("EntryPoint execution: %w", err)
	}
	if mode == "response-lost" {
		var heldStatus string
		if err := database.Pool().QueryRow(ctx, `SELECT status FROM sponsorship_reservations WHERE sponsorship_id=$1`, issued.SponsorshipID[:]).Scan(&heldStatus); err != nil || heldStatus != "RESERVED" {
			return fmt.Errorf("unknown submission released reservation: %s: %w", heldStatus, err)
		}
	}
	count, err := c.uintView(ctx, counter, "count")
	expectedCount := big.NewInt(1)
	if mode == "reverted" {
		expectedCount = big.NewInt(0)
	}
	if err != nil || count.Cmp(expectedCount) != 0 {
		return errors.New("allowed target did not execute exactly once")
	}
	depositAfter, err := c.uintView(ctx, paymaster, "getDeposit")
	if err != nil || depositAfter.Cmp(depositBefore) >= 0 {
		return errors.New("paymaster deposit did not pay gas")
	}
	endBalance, err := c.eth.BalanceAt(ctx, account.address, nil)
	if err != nil || endBalance.Sign() != 0 {
		return errors.New("smart account paid native gas")
	}
	if _, err := c.eth.CallContract(ctx, ethereum.CallMsg{From: relayer, To: &entry.address, Data: call, Gas: 8_000_000}, nil); err == nil {
		return errors.New("exact UserOperation replay was accepted")
	}
	if !hasSponsorshipEvent(receipt, paymaster.address, issued.SponsorshipID, userOpHash) {
		return errors.New("paymaster validation event missing")
	}
	actualGasCost, executionSuccess, ok := userOperationCost(receipt, entry.address, account.address, paymaster.address, userOpHash)
	if !ok || executionSuccess != (mode != "reverted") || actualGasCost.Cmp(new(big.Int).Sub(depositBefore, depositAfter)) != 0 {
		if !ok {
			return errors.New("EntryPoint operation event missing")
		}
		return fmt.Errorf("EntryPoint event mismatch: success=%t cost=%s deposit_delta=%s", executionSuccess, actualGasCost, new(big.Int).Sub(depositBefore, depositAfter))
	}
	if err := watcher.RunOnce(ctx, time.Now().UTC()); err != nil {
		return fmt.Errorf("observe UserOperation: %w", err)
	}
	var status, outcome string
	if err := database.Pool().QueryRow(ctx, `SELECT status,outcome_state FROM sponsorship_reservations WHERE sponsorship_id=$1`, issued.SponsorshipID[:]).Scan(&status, &outcome); err != nil || status != "RESERVED" || (outcome != "OBSERVED" && outcome != "CONFIRMING") {
		return fmt.Errorf("operation settled before finality: %s/%s: %w", status, outcome, err)
	}
	var mined any
	if err := c.rpc.CallContext(ctx, &mined, "anvil_mine", 2); err != nil {
		return fmt.Errorf("advance local finality: %w", err)
	}
	if err := watcher.RunOnce(ctx, time.Now().UTC()); err != nil {
		return fmt.Errorf("finalize UserOperation: %w", err)
	}
	var settledCost, held, consumed, released string
	if err := database.Pool().QueryRow(ctx, `SELECT r.status,r.outcome_state,r.actual_cost_wei::text,b.held_wei::text,b.consumed_wei::text,l.released_wei::text FROM sponsorship_reservations r JOIN budget_periods b ON b.chain_id=0 AND b.period_start=r.period_start AND b.scope='ALL_CHAINS' JOIN actual_spend_ledger l ON l.sponsorship_id=r.sponsorship_id WHERE r.sponsorship_id=$1`, issued.SponsorshipID[:]).Scan(&status, &outcome, &settledCost, &held, &consumed, &released); err != nil || status != "CONSUMED" || outcome != "FINAL" || settledCost != actualGasCost.String() || held != "0" || consumed != settledCost {
		return fmt.Errorf("settlement ledger mismatch: %s/%s cost=%s held=%s consumed=%s: %w", status, outcome, settledCost, held, consumed, err)
	}
	metadata := map[string]any{
		"chain_id": "31337", "entry_point_version": "v0.9.0", "entry_point_source_revision": "b36a1ed52ae00da6f8a4c8d50181e2877e4fa410",
		"entry_point_local_address": entry.address.Hex(), "entry_point_code_hash": entryCodeHash.Hex(),
		"paymaster": paymaster.address.Hex(), "smart_account": account.address.Hex(),
		"target": counter.address.Hex(), "authorization_signer": sponsor.Hex(), "account_owner": owner.Hex(),
		"entry_point_deployment_tx": entryReceipt.TxHash.Hex(), "account_deployment_tx": accountReceipt.TxHash.Hex(),
		"target_deployment_tx": counterReceipt.TxHash.Hex(), "paymaster_deployment_tx": paymasterReceipt.TxHash.Hex(),
		"deposit_tx": depositReceipt.TxHash.Hex(), "operation_tx": receipt.TxHash.Hex(), "deployment_block": entryReceipt.BlockNumber.String(),
		"policy_version": admitted.PolicyVersion, "sponsorship_id": admitted.SponsorshipID,
		"reserved_upper_bound_wei": admitted.EstimatedUpperBoundWei,
		"sponsorship_digest":       "0x" + hex.EncodeToString(issued.Digest[:]), "user_op_hash": common.BytesToHash(userOpHash[:]).Hex(),
		"account_balance_before_wei": zeroBalance.String(), "account_balance_after_wei": endBalance.String(),
		"paymaster_deposit_before_wei": depositBefore.String(), "paymaster_deposit_after_wei": depositAfter.String(),
		"actual_gas_cost_wei": actualGasCost.String(), "execution_success": executionSuccess, "mode": mode,
		"settlement_status": status, "settlement_outcome": outcome, "budget_held_wei": held,
		"budget_consumed_wei": consumed, "released_hold_wei": released,
		"target_count": count.String(), "compiler": "solc 0.8.37", "execution_path": executionPath(bundlerURL),
		"openzeppelin_version": "v5.7.0", "openzeppelin_revision": "cab19933c33c2ad1d4c7a84864a3601dddfd16f3",
		"foundry_version": "1.8.4", "anvil_version": "1.8.4",
	}
	if bundlerURL != "" {
		metadata["external_bundler_revision"] = "96529592b67a69be23c013359cbc9990657af64a"
		metadata["external_bundler_submission"] = "eth_sendUserOperation"
	}
	if os.Getenv("LOCAL_DEMO_FULL") == "1" {
		if apiServer == nil || demoMetrics == nil || mode != "success" || bundlerURL == "" {
			return errors.New("full demo requires API and external bundler success path")
		}
		deniedInput := input
		deniedCall, err := account.abi.Pack("execute", deployer, big.NewInt(0), inner)
		if err != nil {
			return err
		}
		deniedInput.CallData = "0x" + hex.EncodeToString(deniedCall)
		denied, deniedStatus, err := demoSponsorship(ctx, apiServer.URL, apiToken, "local-demo-denied-0002", deniedInput)
		if err != nil || deniedStatus != 422 || denied.Reason != "TARGET_NOT_ALLOWED" {
			return fmt.Errorf("policy denial: %d %s %v", deniedStatus, denied.Reason, err)
		}
		unusedInput := input
		unusedInput.Nonce = "1"
		unused, unusedStatus, err := demoSponsorship(ctx, apiServer.URL, apiToken, "local-demo-unused-0003", unusedInput)
		if err != nil || unusedStatus != 201 || unused.Decision != "approved" {
			return fmt.Errorf("unused authorization: %d %s %v", unusedStatus, unused.Reason, err)
		}
		var ignored any
		if err := c.rpc.CallContext(ctx, &ignored, "evm_setNextBlockTimestamp", hexutil.EncodeUint64(uint64(unused.ValidUntil.Unix()+1))); err != nil {
			return err
		}
		if err := c.rpc.CallContext(ctx, &ignored, "anvil_mine", 3); err != nil {
			return err
		}
		if err := watcher.RunOnce(ctx, unused.ValidUntil.Add(2*time.Second)); err != nil {
			return err
		}
		unusedView, err := demoGET(ctx, apiServer.URL, apiToken, "/v1/sponsorships/"+unused.SponsorshipID)
		if err != nil || unusedView["reservation_state"] != "EXPIRED" || unusedView["outcome_state"] != "EXPIRED_UNUSED" {
			return fmt.Errorf("unused HTTP state: %v %v", unusedView, err)
		}
		consumedView, err := demoGET(ctx, apiServer.URL, apiToken, "/v1/sponsorships/0x"+admitted.SponsorshipID)
		if err != nil || consumedView["reservation_state"] != "CONSUMED" || consumedView["outcome_state"] != "FINAL" {
			return fmt.Errorf("consumed HTTP state: %v %v", consumedView, err)
		}
		if err := demoMetrics.RefreshFromLedger(ctx, database, unused.ValidUntil.Add(2*time.Second), accounting.GlobalDailyBudgetWei); err != nil {
			return err
		}
		statusView, err := demoGET(ctx, apiServer.URL, apiToken, "/v1/status")
		if err != nil || statusView["ready"] != true {
			return fmt.Errorf("operational status: %v %v", statusView, err)
		}
		metricText, err := demoText(ctx, apiServer.URL, apiToken, "/metrics")
		if err != nil || !strings.Contains(metricText, "gasless_actual_spend_wei") || !strings.Contains(metricText, "gasless_paymaster_balance_wei") {
			return fmt.Errorf("accounting metrics unavailable: %v", err)
		}
		var requestCount, reservationCount, ledgerCount int
		if err := database.Pool().QueryRow(ctx, `SELECT (SELECT count(*) FROM sponsorship_requests),(SELECT count(*) FROM sponsorship_reservations),(SELECT count(*) FROM actual_spend_ledger)`).Scan(&requestCount, &reservationCount, &ledgerCount); err != nil {
			return err
		}
		if requestCount != 3 || reservationCount != 2 || ledgerCount != 1 {
			return fmt.Errorf("unexpected accounting cardinality: requests=%d reservations=%d ledger=%d", requestCount, reservationCount, ledgerCount)
		}
		totalReserved := new(big.Int)
		firstReserved, _ := new(big.Int).SetString(admitted.EstimatedUpperBoundWei, 10)
		secondReserved, _ := new(big.Int).SetString(unused.EstimatedUpperBoundWei, 10)
		if firstReserved == nil || secondReserved == nil {
			return errors.New("invalid reserved Wei")
		}
		totalReserved.Add(firstReserved, secondReserved)
		actual, _ := new(big.Int).SetString(settledCost, 10)
		firstReleased, _ := new(big.Int).SetString(released, 10)
		conserved := new(big.Int).Add(actual, firstReleased)
		conserved.Add(conserved, secondReserved)
		if conserved.Cmp(totalReserved) != 0 {
			return errors.New("final accounting checksum does not conserve Wei")
		}
		canonical := fmt.Sprintf("requests=%d;reservations=%d;consumed=1;expired=1;reserved=%s;actual=%s;released=%s;open=0", requestCount, reservationCount, totalReserved.String(), actual.String(), new(big.Int).Add(firstReleased, secondReserved).String())
		checksum := sha256.Sum256([]byte(canonical))
		metadata["final_checksum_sha256"] = "0x" + hex.EncodeToString(checksum[:])
		metadata["final_accounting"] = canonical
		metadata["unused_sponsorship_id"] = unused.SponsorshipID
		metadata["request_count"] = requestCount
		metadata["reservation_count"] = reservationCount
		metadata["actual_spend_record_count"] = ledgerCount
		metadata["unused_status"] = "EXPIRED_UNUSED"
		fmt.Printf("APPROVED artifact issued; UserOperation included; CONSUMED actualGasCost=%s; unused RESERVED -> EXPIRED; checksum=%x\n", actual.String(), checksum)
	}
	if err := writeMetadata(output, metadata); err != nil {
		return err
	}
	fmt.Printf("%s EntryPoint E2E passed: account=%s target_count=%s deposit_delta_wei=%s\n",
		executionPath(bundlerURL), account.address.Hex(), count.String(), new(big.Int).Sub(depositBefore, depositAfter).String())
	return nil
}

func writeMetadata(path string, metadata map[string]any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(encoded, '\n'), 0o644)
}

type demoAPIResponse struct {
	Decision               string               `json:"decision"`
	Reason                 string               `json:"reason"`
	SponsorshipID          string               `json:"sponsorship_id"`
	PolicyVersion          policy.PolicyVersion `json:"policy_version"`
	EstimatedUpperBoundWei string               `json:"estimated_upper_bound_wei"`
	ValidAfter             time.Time            `json:"valid_after"`
	ValidUntil             time.Time            `json:"valid_until"`
	Authorization          struct {
		PaymasterAndData string `json:"paymaster_and_data"`
	} `json:"authorization"`
}

func demoSponsorship(ctx context.Context, endpoint, token, key string, input policy.RequestInput) (demoAPIResponse, int, error) {
	payload := map[string]any{"chain_id": input.ChainID, "entry_point": input.EntryPoint, "user_operation": map[string]string{
		"sender": input.Sender, "nonce": input.Nonce, "call_data": input.CallData, "call_gas_limit": input.CallGasLimit,
		"verification_gas_limit": input.VerificationGasLimit, "pre_verification_gas": input.PreVerificationGas,
		"max_fee_per_gas": input.MaxFeePerGas, "max_priority_fee_per_gas": input.MaxPriorityFeePerGas,
		"paymaster_verification_gas_limit": input.PaymasterVerificationGasLimit, "paymaster_post_op_gas_limit": input.PaymasterPostOpGasLimit}}
	if input.RequestedLifetimeSeconds != "" {
		payload["requested_lifetime_seconds"] = input.RequestedLifetimeSeconds
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return demoAPIResponse{}, 0, err
	}
	request, err := http.NewRequestWithContext(ctx, "POST", endpoint+"/v1/sponsorships", bytes.NewReader(encoded))
	if err != nil {
		return demoAPIResponse{}, 0, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", key)
	client := &http.Client{Timeout: 8 * time.Second}
	reply, err := client.Do(request)
	if err != nil {
		return demoAPIResponse{}, 0, err
	}
	defer reply.Body.Close()
	var response demoAPIResponse
	if err := json.NewDecoder(reply.Body).Decode(&response); err != nil {
		return demoAPIResponse{}, reply.StatusCode, err
	}
	return response, reply.StatusCode, nil
}

func demoText(ctx context.Context, endpoint, token, path string) (string, error) {
	request, err := http.NewRequestWithContext(ctx, "GET", endpoint+path, nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	reply, err := (&http.Client{Timeout: 8 * time.Second}).Do(request)
	if err != nil {
		return "", err
	}
	defer reply.Body.Close()
	if reply.StatusCode != 200 {
		return "", fmt.Errorf("GET %s returned %d", path, reply.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(reply.Body, 1<<20))
	return string(data), err
}

func demoGET(ctx context.Context, endpoint, token, path string) (map[string]any, error) {
	text, err := demoText(ctx, endpoint, token, path)
	if err != nil {
		return nil, err
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(text), &result); err != nil {
		return nil, err
	}
	return result, nil
}

func executionPath(bundlerURL string) string {
	if bundlerURL != "" {
		return "external bundler"
	}
	return "direct"
}

func (c chain) sendViaBundler(ctx context.Context, url string, entryPoint common.Address, op userop.Packed, expectedHash [32]byte, responseLost bool) (*types.Receipt, error) {
	if len(op.PaymasterAndData) != 243 || len(op.Signature) != 65 {
		return nil, errors.New("incomplete v0.9 UserOperation")
	}
	bundler, err := rpc.DialContext(ctx, url)
	if err != nil {
		return nil, err
	}
	defer bundler.Close()
	verificationGas := new(big.Int).SetBytes(op.AccountGasLimits[:16])
	callGas := new(big.Int).SetBytes(op.AccountGasLimits[16:])
	priorityFee := new(big.Int).SetBytes(op.GasFees[:16])
	maxFee := new(big.Int).SetBytes(op.GasFees[16:])
	data := map[string]any{
		"sender": op.Sender.Hex(), "nonce": hexutil.EncodeBig(op.Nonce), "callData": hexutil.Encode(op.CallData),
		"callGasLimit": hexutil.EncodeBig(callGas), "verificationGasLimit": hexutil.EncodeBig(verificationGas),
		"preVerificationGas": hexutil.EncodeBig(op.PreVerificationGas), "maxFeePerGas": hexutil.EncodeBig(maxFee),
		"maxPriorityFeePerGas": hexutil.EncodeBig(priorityFee), "paymaster": common.BytesToAddress(op.PaymasterAndData[:20]).Hex(),
		"paymasterVerificationGasLimit": hexutil.EncodeBig(new(big.Int).SetBytes(op.PaymasterAndData[20:36])),
		"paymasterPostOpGasLimit":       hexutil.EncodeBig(new(big.Int).SetBytes(op.PaymasterAndData[36:52])),
		"paymasterData":                 hexutil.Encode(op.PaymasterAndData[52:168]),
		"paymasterSignature":            hexutil.Encode(op.PaymasterAndData[168:233]), "signature": hexutil.Encode(op.Signature),
	}
	var returned common.Hash
	submitErr := bundler.CallContext(ctx, &returned, "eth_sendUserOperation", data, entryPoint.Hex())
	if submitErr != nil && !responseLost {
		return nil, submitErr
	}
	if submitErr == nil && responseLost {
		return nil, errors.New("response-loss scenario did not lose the submission response")
	}
	if submitErr == nil && returned != common.BytesToHash(expectedHash[:]) {
		return nil, fmt.Errorf("bundler returned a different UserOperation hash: %s", returned.Hex())
	}
	if responseLost {
		returned = common.BytesToHash(expectedHash[:])
	}
	for {
		var result *struct {
			Receipt struct {
				TransactionHash common.Hash `json:"transactionHash"`
			} `json:"receipt"`
		}
		if err := bundler.CallContext(ctx, &result, "eth_getUserOperationReceipt", returned.Hex()); err != nil {
			return nil, err
		}
		if result != nil && result.Receipt.TransactionHash != (common.Hash{}) {
			return c.eth.TransactionReceipt(ctx, result.Receipt.TransactionHash)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func testKey(last byte) (*ecdsa.PrivateKey, error) {
	var scalar [32]byte
	scalar[31] = last
	return crypto.ToECDSA(scalar[:])
}

func mustChainID() policy.ChainID {
	v, _ := policy.ParseUint256("31337")
	return policy.ChainID{Uint256: v}
}

func toPolicyAddress(a common.Address) policy.Address {
	var out policy.Address
	copy(out[:], a[:])
	return out
}

func loadContract(path string) (contract, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return contract{}, err
	}
	var artifact contractArtifact
	if err := json.Unmarshal(raw, &artifact); err != nil {
		return contract{}, err
	}
	parsed, err := abi.JSON(bytes.NewReader(artifact.ABI))
	if err != nil {
		return contract{}, err
	}
	code, err := hex.DecodeString(strings.TrimPrefix(artifact.Bytecode.Object, "0x"))
	if err != nil || len(code) == 0 {
		return contract{}, errors.New("empty or invalid contract creation bytecode")
	}
	return contract{abi: parsed, code: code}, nil
}

func (c chain) deploy(ctx context.Context, from common.Address, source contract, args ...any) (contract, *types.Receipt, error) {
	constructor, err := source.abi.Pack("", args...)
	if err != nil {
		return contract{}, nil, err
	}
	data := append(append([]byte(nil), source.code...), constructor...)
	receipt, err := c.send(ctx, from, nil, data, nil)
	if err != nil {
		return contract{}, nil, err
	}
	source.address = receipt.ContractAddress
	return source, receipt, nil
}

func (c chain) send(ctx context.Context, from common.Address, to *common.Address, data []byte, value *big.Int) (*types.Receipt, error) {
	args := map[string]any{"from": from.Hex(), "data": hexutil.Encode(data), "gas": hexutil.EncodeUint64(14_000_000)}
	if to != nil {
		args["to"] = to.Hex()
	}
	if value != nil {
		args["value"] = hexutil.EncodeBig(value)
	}
	var hash common.Hash
	if err := c.rpc.CallContext(ctx, &hash, "eth_sendTransaction", args); err != nil {
		return nil, err
	}
	for {
		receipt, err := c.eth.TransactionReceipt(ctx, hash)
		if err == nil {
			if receipt.Status != types.ReceiptStatusSuccessful {
				return nil, fmt.Errorf("transaction %s reverted", hash.Hex())
			}
			return receipt, nil
		}
		if !errors.Is(err, ethereum.NotFound) {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func (c chain) view(ctx context.Context, contract contract, method string, args ...any) ([]any, error) {
	input, err := contract.abi.Pack(method, args...)
	if err != nil {
		return nil, err
	}
	output, err := c.eth.CallContract(ctx, ethereum.CallMsg{To: &contract.address, Data: input}, nil)
	if err != nil {
		return nil, err
	}
	return contract.abi.Unpack(method, output)
}

func (c chain) uintView(ctx context.Context, contract contract, method string) (*big.Int, error) {
	values, err := c.view(ctx, contract, method)
	if err != nil || len(values) != 1 {
		return nil, fmt.Errorf("read %s: %w", method, err)
	}
	value, ok := values[0].(*big.Int)
	if !ok {
		return nil, fmt.Errorf("%s did not return uint256", method)
	}
	return value, nil
}

func hasSponsorshipEvent(receipt *types.Receipt, paymaster common.Address, id [32]byte, userOpHash [32]byte) bool {
	signature := crypto.Keccak256Hash([]byte("SponsorshipValidated(bytes32,bytes32,uint256)"))
	for _, log := range receipt.Logs {
		if log.Address == paymaster && len(log.Topics) == 3 && log.Topics[0] == signature &&
			log.Topics[1] == common.BytesToHash(id[:]) && log.Topics[2] == common.BytesToHash(userOpHash[:]) {
			return true
		}
	}
	return false
}

func userOperationCost(receipt *types.Receipt, entryPoint, sender, paymaster common.Address, userOpHash [32]byte) (*big.Int, bool, bool) {
	signature := crypto.Keccak256Hash([]byte("UserOperationEvent(bytes32,address,address,uint256,bool,uint256,uint256)"))
	for _, event := range receipt.Logs {
		if event.Address != entryPoint || len(event.Topics) != 4 || len(event.Data) != 128 ||
			event.Topics[0] != signature || event.Topics[1] != common.BytesToHash(userOpHash[:]) ||
			common.BytesToAddress(event.Topics[2].Bytes()) != sender ||
			common.BytesToAddress(event.Topics[3].Bytes()) != paymaster {
			continue
		}
		if new(big.Int).SetBytes(event.Data[:32]).Sign() != 0 || new(big.Int).SetBytes(event.Data[32:64]).Cmp(big.NewInt(1)) > 0 {
			return nil, false, false
		}
		return new(big.Int).SetBytes(event.Data[64:96]), event.Data[63] == 1, true
	}
	return nil, false, false
}
