"use strict";

const { ApiPromise, WsProvider, Keyring } = require("@polkadot/api");
const { cryptoWaitReady } = require("@polkadot/util-crypto");
require("dotenv").config();

const { startProxySweep } = require("./proxySweep");

/* -------------------------------------------------------------------------- */
/* Configuration                                                              */
/* -------------------------------------------------------------------------- */
function required(name) {
  const value = process.env[name];
  if (!value) throw new Error(`Missing required environment variable: ${name}`);
  return value;
}

function positiveNumber(name, value) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error(`${name} must be a positive number`);
  }
  return parsed;
}

const CONFIG = {
  wss: required("ASTAR_WSS"),
  execMnemonic: process.env.EXEC_MNEMONIC,
  execPrivateKey: process.env.EXEC_PRIVATE_KEY,
  sponsorMnemonic: process.env.SPONSOR_MNEMONIC,
  sponsorPrivateKey: process.env.SPONSOR_PRIVATE_KEY,
  vault: required("VAULT_ADDRESS"),
  expectedSpecVersion: Number(process.env.EXPECTED_SPEC_VERSION || "2500"),
  rpcMaxRetries: positiveNumber(
    "RPC_MAX_RETRIES",
    process.env.RPC_MAX_RETRIES || "6",
  ),
  feeSafetyBps: BigInt(process.env.FEE_SAFETY_BPS || "2000"),
  minRemainingAstr: process.env.MIN_REMAINING_ASTR || "0.00001",
  // The fixed sweep amount is exactly 0.007 ASTR.
  sweepAmountAstr: process.env.SWEEP_AMOUNT_ASTR || "0.01",
  // The amount left for the transaction fee is not available as a tip.
  // Increase this value if the actual network fee is higher.
  sweepFeeReserveAstr: process.env.SWEEP_FEE_RESERVE_ASTR || "0.0005",
  reconnectInitialDelayMs: positiveNumber(
    "RECONNECT_INITIAL_DELAY_MS",
    process.env.RECONNECT_INITIAL_DELAY_MS || "1000",
  ),
  reconnectMaxDelayMs: positiveNumber(
    "RECONNECT_MAX_DELAY_MS",
    process.env.RECONNECT_MAX_DELAY_MS || "30000",
  ),
  rpcRetryInitialDelayMs: positiveNumber(
    "RPC_RETRY_INITIAL_DELAY_MS",
    process.env.RPC_RETRY_INITIAL_DELAY_MS || "500",
  ),
  rpcRetryMaxDelayMs: positiveNumber(
    "RPC_RETRY_MAX_DELAY_MS",
    process.env.RPC_RETRY_MAX_DELAY_MS || "10000",
  ),
  sponsorExtraAstr: process.env.SPONSOR_EXTRA_ASTR || "0.01",
  maxSponsorFundingAstr: process.env.MAX_SPONSOR_FUNDING_ASTR || "1",
};

/* -------------------------------------------------------------------------- */
/* Runtime state                                                              */
/* -------------------------------------------------------------------------- */
let api = null;
let provider = null;
let execPair = null;
let sponsorPair = null;
let unsubscribeAccount = null;
let unsubscribeHeads = null;
let reconnecting = false;
let shuttingDown = false;
let sweepInProgress = false;
let sweepQueued = false;
let operationInProgress = false;
let cooldownProcessing = false;
let unlockInitiated = false;
let withdrawalCompleted = false;
let reconnectGeneration = 0;
let protectedOperationGas = 0n;
let protectedOperationLabel = null;
let dappTx = null;
let dappQuery = null;

/* -------------------------------------------------------------------------- */
/* Logging                                                                    */
/* -------------------------------------------------------------------------- */
function log(level, message, data = undefined) {
  const record = {
    timestamp: new Date().toLocaleString(),
    level,
    message,
  };
  if (data !== undefined) record.data = data;
  console.log(JSON.stringify(record));
}

const info = (message, data) => log("INFO", message, data);
const warn = (message, data) => log("WARN", message, data);
const error = (message, data) => log("ERROR", message, data);

/* -------------------------------------------------------------------------- */
/* Utilities                                                                  */
/* -------------------------------------------------------------------------- */
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function toBigInt(value) {
  if (typeof value === "bigint") return value;
  if (value && typeof value.toBigInt === "function") return value.toBigInt();
  return BigInt(value.toString());
}

const UNIT = 10n ** 18n;
function astr(value) {
  const n = toBigInt(value);
  const whole = n / UNIT;
  const fraction = (n % UNIT).toString().padStart(18, "0").replace(/0+$/, "");
  return fraction ? `${whole}.${fraction}` : whole.toString();
}

function parseAstr(value) {
  const stringValue = String(value);
  const [whole, fraction = ""] = stringValue.split(".");
  if (!/^\d+$/.test(whole)) {
    throw new Error(`Invalid ASTR amount: ${value}`);
  }
  if (fraction && !/^\d+$/.test(fraction)) {
    throw new Error(`Invalid ASTR amount: ${value}`);
  }
  if (fraction.length > 18) {
    throw new Error(`ASTR amount has more than 18 decimals: ${value}`);
  }
  const normalizedFraction = (fraction + "0".repeat(18)).slice(0, 18);
  return BigInt(whole) * UNIT + BigInt(normalizedFraction);
}

function codecToJson(codec) {
  try {
    return codec?.toJSON ? codec.toJSON() : codec;
  } catch {
    return null;
  }
}

function formatError(err) {
  return err?.stack || err?.message || String(err);
}

function maxBigInt(a, b) {
  return a > b ? a : b;
}

function isFeeError(err) {
  const message = String(err?.message || err || "");
  return (
    message.includes("1010") ||
    message.includes("Inability to pay some fees") ||
    message.includes("account balance too low") ||
    message.includes("Payment")
  );
}

/* -------------------------------------------------------------------------- */
/* Retry                                                                      */
/* -------------------------------------------------------------------------- */
async function retry(label, fn) {
  let delay = CONFIG.rpcRetryInitialDelayMs;
  for (let attempt = 1; attempt <= CONFIG.rpcMaxRetries; attempt++) {
    try {
      return await fn();
    } catch (err) {
      warn(`${label} failed`, {
        attempt,
        maxAttempts: CONFIG.rpcMaxRetries,
        error: formatError(err),
      });
      if (attempt === CONFIG.rpcMaxRetries) throw err;
      await sleep(delay);
      delay = Math.min(delay * 2, CONFIG.rpcRetryMaxDelayMs);
    }
  }
  throw new Error(`${label} failed`);
}

/* -------------------------------------------------------------------------- */
/* Accounts                                                                   */
/* -------------------------------------------------------------------------- */
async function initializeAccounts() {
  await cryptoWaitReady();
  const keyring = new Keyring({
    type: "sr25519",
    ss58Format: 5,
  });
  const hasExecMnemonic = Boolean(CONFIG.execMnemonic);
  const hasExecPrivateKey = Boolean(CONFIG.execPrivateKey);
  if (hasExecMnemonic === hasExecPrivateKey) {
    throw new Error("Provide exactly one of EXEC_MNEMONIC or EXEC_PRIVATE_KEY");
  }
  const hasSponsorMnemonic = Boolean(CONFIG.sponsorMnemonic);
  const hasSponsorPrivateKey = Boolean(CONFIG.sponsorPrivateKey);
  if (hasSponsorMnemonic === hasSponsorPrivateKey) {
    throw new Error(
      "Provide exactly one of SPONSOR_MNEMONIC or SPONSOR_PRIVATE_KEY",
    );
  }
  if (CONFIG.execMnemonic) {
    execPair = keyring.addFromUri(CONFIG.execMnemonic);
  } else {
    const seed = Buffer.from(CONFIG.execPrivateKey.replace(/^0x/, ""), "hex");
    if (seed.length !== 32) {
      throw new Error("EXEC_PRIVATE_KEY must decode to a 32-byte sr25519 seed");
    }
    execPair = keyring.addFromSeed(seed);
  }
  if (CONFIG.sponsorMnemonic) {
    sponsorPair = keyring.addFromUri(CONFIG.sponsorMnemonic);
  } else {
    const seed = Buffer.from(
      CONFIG.sponsorPrivateKey.replace(/^0x/, ""),
      "hex",
    );
    if (seed.length !== 32) {
      throw new Error(
        "SPONSOR_PRIVATE_KEY must decode to a 32-byte sr25519 seed",
      );
    }
    sponsorPair = keyring.addFromSeed(seed);
  }
  if (execPair.address === sponsorPair.address) {
    throw new Error("Exec and sponsor accounts must be different");
  }
  if (execPair.address === CONFIG.vault) {
    throw new Error("Exec account cannot equal vault");
  }
  info("Accounts initialized", {
    exec: execPair.address,
    sponsor: sponsorPair.address,
    vault: CONFIG.vault,
  });
}

/* -------------------------------------------------------------------------- */
/* Runtime verification                                                       */
/* -------------------------------------------------------------------------- */
function verifyRuntime() {
  if (!api) throw new Error("API is not initialized");
  const specVersion = api.runtimeVersion.specVersion.toNumber();
  const specName = api.runtimeVersion.specName.toString().toLowerCase();
  if (specName !== "astar") {
    throw new Error(`Wrong runtime: expected Astar, got ${specName}`);
  }
  if (specVersion !== CONFIG.expectedSpecVersion) {
    throw new Error(
      `Runtime mismatch. Expected ${CONFIG.expectedSpecVersion}, got ${specVersion}`,
    );
  }
  if (!api.tx.dappStaking || !api.query.dappStaking) {
    throw new Error("dApp staking pallet is unavailable");
  }
  const requiredCalls = [
    "unstake",
    "unlock",
    "withdrawUnbonded",
    "claimStakerRewards",
  ];
  for (const call of requiredCalls) {
    if (typeof api.tx.dappStaking[call] !== "function") {
      throw new Error(
        `dappStaking.${call}() is unavailable in runtime ${specVersion}`,
      );
    }
  }
  const requiredStorage = ["ledger", "stakerInfo", "activeProtocolState"];
  for (const storage of requiredStorage) {
    if (typeof api.query.dappStaking[storage] !== "function") {
      throw new Error(
        `dappStaking.${storage}() is unavailable in runtime ${specVersion}`,
      );
    }
  }
  dappTx = api.tx.dappStaking;
  dappQuery = api.query.dappStaking;
  const callArguments = {};
  for (const call of requiredCalls) {
    callArguments[call] = (dappTx[call].meta.args || []).map((arg) => ({
      name: arg.name.toString(),
      type: arg.type.toString(),
    }));
  }
  info("Astar runtime verified", {
    specName: api.runtimeVersion.specName.toString(),
    specVersion,
    pallet: "dappStaking",
    calls: callArguments,
    storage: {
      ledger: true,
      stakerInfo: true,
      activeProtocolState: true,
    },
  });
  const unstakeArgs = callArguments.unstake;
  const unlockArgs = callArguments.unlock;
  if (unstakeArgs.length < 1 || unstakeArgs.length > 2) {
    throw new Error(
      `Unexpected dappStaking.unstake signature: ${unstakeArgs.map((arg) => arg.name).join(", ")}`,
    );
  }
  if (unlockArgs.length !== 1) {
    throw new Error(
      `Unexpected dappStaking.unlock signature: ${unlockArgs.map((arg) => arg.name).join(", ")}`,
    );
  }
}

/* -------------------------------------------------------------------------- */
/* AccountId normalization                                                    */
/* -------------------------------------------------------------------------- */
function getExecAccountId() {
  if (!api || !execPair) {
    throw new Error("API and exec account must be initialized");
  }
  return api.createType("AccountId32", execPair.address);
}

/* -------------------------------------------------------------------------- */
/* Connection                                                                 */
/* -------------------------------------------------------------------------- */
async function disconnectCurrent() {
  if (unsubscribeAccount) {
    try {
      unsubscribeAccount();
    } catch {}
    unsubscribeAccount = null;
  }
  if (unsubscribeHeads) {
    try {
      unsubscribeHeads();
    } catch {}
    unsubscribeHeads = null;
  }
  if (api) {
    try {
      await api.disconnect();
    } catch {}
  }
  api = null;
  provider = null;
}

async function connect() {
  const generation = ++reconnectGeneration;
  await disconnectCurrent();
  provider = new WsProvider(CONFIG.wss, 10_000);
  provider.on("error", (err) => {
    warn("Astar WebSocket error", {
      error: formatError(err),
    });
  });
  provider.on("disconnected", () => {
    warn("Astar WebSocket disconnected");
    if (!shuttingDown && generation === reconnectGeneration) {
      reconnect().catch((err) => {
        error("Reconnect failure", {
          error: formatError(err),
        });
      });
    }
  });
  api = await ApiPromise.create({
    provider,
    noInitWarn: true,
  });
  const [chain, properties] = await Promise.all([
    api.rpc.system.chain(),
    api.rpc.system.properties(),
  ]);
  info("Connected to Astar", {
    chain: chain.toString(),
    specName: api.runtimeVersion.specName.toString(),
    specVersion: api.runtimeVersion.specVersion.toNumber(),
    properties: properties.toJSON(),
  });
  verifyRuntime();
}

/* -------------------------------------------------------------------------- */
/* Account state                                                              */
/* -------------------------------------------------------------------------- */

function extractFrozenAmount(data) {
  const candidates = [];
  for (const field of [
    "frozen",
    "miscFrozen",
    "feeFrozen",
    "misc_frozen",
    "fee_frozen",
  ]) {
    if (data[field] === undefined || data[field] === null) continue;
    candidates.push(toBigInt(data[field]));
  }
  if (candidates.length === 0) return 0n;
  return candidates.reduce(
    (highest, value) => (value > highest ? value : highest),
    0n,
  );
}

async function getAccountState(address) {
  return retry("system.account state", async () => {
    const account = await api.query.system.account(address);
    const data = account.data;
    const free = toBigInt(data.free);
    const reserved = data.reserved !== undefined ? toBigInt(data.reserved) : 0n;
    const frozen = extractFrozenAmount(data);
    const transferable = free > frozen ? free - frozen : 0n;
    return {
      address,
      free,
      reserved,
      frozen,
      transferable,
      flags: data.flags !== undefined ? data.flags.toString() : null,
      raw: codecToJson(account),
    };
  });
}

async function getFreeBalance(address) {
  return (await getAccountState(address)).free;
}

/* -------------------------------------------------------------------------- */
/* Transaction finalization                                                   */
/* -------------------------------------------------------------------------- */
/*
 * signOptions is deliberately supported here.
 * Example:
 *   submitFinalized(tx, execPair, "Sweep", { nonce, tip })
 * Without this parameter being forwarded to signAndSend, the nonce and tip
 * passed by the caller would have no effect.
 */
async function submitFinalized(tx, signer, label, signOptions = {}) {
  return new Promise((resolve, reject) => {
    let unsubscribe = null;
    let finished = false;
    const cleanup = () => {
      if (unsubscribe) {
        unsubscribe();
        unsubscribe = null;
      }
    };
    const fail = (err) => {
      if (finished) return;
      finished = true;
      cleanup();
      reject(err);
    };
    const onResult = (result) => {
      if (finished) return;
      if (result.status.isInBlock) {
        info(`${label}: included`, {
          block: result.status.asInBlock.toHex(),
        });
      }
      if (result.dispatchError) {
        let message = result.dispatchError.toString();
        let section = null;
        let method = null;
        if (result.dispatchError.isModule) {
          const decoded = api.registry.findMetaError(
            result.dispatchError.asModule,
          );
          section = decoded.section;
          method = decoded.name;
          message = `${decoded.section}.${decoded.name}: ${decoded.docs.join(" ")}`;
        }
        const err = new Error(`${label} failed: ${message}`);
        err.dispatchError = result.dispatchError;
        err.dispatchSection = section;
        err.dispatchMethod = method;
        err.includedBlock = result.status.isInBlock
          ? result.status.asInBlock.toHex()
          : null;
        fail(err);
        return;
      }
      if (
        result.status.isDropped ||
        result.status.isInvalid ||
        result.status.isUsurped ||
        result.status.isRetracted ||
        result.status.isFinalityTimeout
      ) {
        const statusName = [
          "Dropped",
          "Invalid",
          "Usurped",
          "Retracted",
          "FinalityTimeout",
        ].find((name) => result.status[`is${name}`]);
        fail(
          new Error(
            `${label} transaction status: ${statusName || result.status.type}`,
          ),
        );
        return;
      }
      if (result.status.isFinalized) {
        finished = true;
        info(`${label}: finalized`, {
          block: result.status.asFinalized.toHex(),
        });
        cleanup();
        resolve(result);
      }
    };
    (async () => {
      try {
        unsubscribe = await tx.signAndSend(signer, signOptions, onResult);
        // The callback can theoretically complete before signAndSend resolves.
        if (finished) cleanup();
      } catch (err) {
        fail(err);
      }
    })();
  });
}

/* -------------------------------------------------------------------------- */
/* Fee estimation                                                             */
/* -------------------------------------------------------------------------- */
/*
 * Used for staking and sponsor transactions, not for the sweep.
 * The sweep deliberately avoids transactionPaymentApi.queryInfo because the
 * observed endpoint traps with RPC error 4003 on this runtime/provider.
 */
async function estimateFee(tx, signer) {
  return retry("paymentInfo", async () => {
    const result = await tx.paymentInfo(signer);
    return toBigInt(result.partialFee);
  });
}

function addFeeSafety(fee) {
  return (fee * (10_000n + CONFIG.feeSafetyBps)) / 10_000n;
}

/* -------------------------------------------------------------------------- */
/* Fee affordability                                                          */
/* -------------------------------------------------------------------------- */
async function getFeeRequirement(tx, signer) {
  const account = await getAccountState(signer.address);
  const estimatedFee = await estimateFee(tx, signer);
  const feeWithSafety = addFeeSafety(estimatedFee);
  const reserve = parseAstr(CONFIG.minRemainingAstr);
  const protectedGas =
    signer.address === execPair?.address ? protectedOperationGas : 0n;
  const available =
    account.transferable > reserve + protectedGas
      ? account.transferable - reserve - protectedGas
      : 0n;
  return {
    account,
    estimatedFee,
    feeWithSafety,
    reserve,
    protectedGas,
    available,
    canAfford: available >= feeWithSafety,
  };
}

/* -------------------------------------------------------------------------- */
/* Sponsor funding                                                            */
/* -------------------------------------------------------------------------- */
async function sponsorFundExec(requiredAmount, reason) {
  if (requiredAmount <= 0n) return 0n;
  const extra = parseAstr(CONFIG.sponsorExtraAstr);
  const funding = requiredAmount + extra;
  const maximum = parseAstr(CONFIG.maxSponsorFundingAstr);
  if (funding > maximum) {
    throw new Error(
      `Sponsor funding request ${astr(funding)} exceeds MAX_SPONSOR_FUNDING_ASTR=${CONFIG.maxSponsorFundingAstr}`,
    );
  }
  const sponsorState = await getAccountState(sponsorPair.address);
  const sponsorReserve = parseAstr(CONFIG.minRemainingAstr);
  const sponsorAvailable =
    sponsorState.transferable > sponsorReserve
      ? sponsorState.transferable - sponsorReserve
      : 0n;
  const transferTx = api.tx.balances.transferKeepAlive(
    execPair.address,
    funding.toString(),
  );
  const transferFee = await estimateFee(transferTx, sponsorPair);
  const sponsorRequired = funding + addFeeSafety(transferFee);
  if (sponsorAvailable < sponsorRequired) {
    throw new Error(
      `Sponsor cannot fund exec. Required ${astr(sponsorRequired)} ASTR, available ${astr(sponsorAvailable)} ASTR`,
    );
  }
  info("Funding exec transaction gas", {
    reason,
    required: astr(requiredAmount),
    extraSafety: astr(extra),
    funding: astr(funding),
    sponsorTransferFee: astr(transferFee),
    sponsorRequired: astr(sponsorRequired),
    sponsorAvailable: astr(sponsorAvailable),
  });
  protectedOperationGas = funding;
  protectedOperationLabel = reason;
  await submitFinalized(
    transferTx,
    sponsorPair,
    `Sponsor → exec ${astr(funding)} ASTR`,
  );
  return funding;
}

/* -------------------------------------------------------------------------- */
/* Execute an exec transaction with automatic sponsor funding                 */
/* -------------------------------------------------------------------------- */
async function submitExecOperation(txFactory, label) {
  if (operationInProgress) {
    throw new Error(
      `Another exec operation is already running: ${protectedOperationLabel || "unknown"}`,
    );
  }
  operationInProgress = true;
  try {
    let tx = txFactory();
    let requirement = await getFeeRequirement(tx, execPair);
    info("Exec fee check", {
      label,
      transferable: astr(requirement.account.transferable),
      frozen: astr(requirement.account.frozen),
      reserve: astr(requirement.reserve),
      protectedGas: astr(requirement.protectedGas),
      estimatedFee: astr(requirement.estimatedFee),
      feeWithSafety: astr(requirement.feeWithSafety),
      available: astr(requirement.available),
      canAfford: requirement.canAfford,
    });
    if (!requirement.canAfford) {
      const shortfall =
        requirement.feeWithSafety > requirement.available
          ? requirement.feeWithSafety - requirement.available
          : 0n;
      await sponsorFundExec(shortfall, label);
      tx = txFactory();
      requirement = await getFeeRequirement(tx, execPair);
      if (!requirement.canAfford) {
        throw new Error(
          `Exec still cannot afford ${label} after sponsor funding. Available: ${astr(requirement.available)}, required: ${astr(requirement.feeWithSafety)}`,
        );
      }
    }
    const nonce = await api.rpc.system.accountNextIndex(execPair.address);
    await submitFinalized(tx, execPair, label, { nonce });
    protectedOperationGas = 0n;
    protectedOperationLabel = null;
    return true;
  } catch (err) {
    if (protectedOperationGas > 0n) {
      warn("Exec operation failed; funded gas remains protected", {
        label,
        protectedGas: astr(protectedOperationGas),
        error: formatError(err),
      });
    }
    throw err;
  } finally {
    operationInProgress = false;
  }
}

/* -------------------------------------------------------------------------- */
/* Transfer                                                                   */
/* -------------------------------------------------------------------------- */
async function transfer(signer, destination, amount, label) {
  if (amount <= 0n) {
    throw new Error(`Refusing zero/negative transfer: ${amount}`);
  }
  const tx = api.tx.balances.transferKeepAlive(destination, amount.toString());
  const nonce = await api.rpc.system.accountNextIndex(signer.address);
  return submitFinalized(tx, signer, label, { nonce });
}

/* -------------------------------------------------------------------------- */
/* Sweep                                                                      */
/* -------------------------------------------------------------------------- */
const SWEEP_AMOUNT = parseAstr(CONFIG.sweepAmountAstr);
const SWEEP_FEE_RESERVE = parseAstr(CONFIG.sweepFeeReserveAstr);
const MIN_REMAINING = parseAstr(CONFIG.minRemainingAstr);
/*
 * Fixed transfer:
 *   0.007 ASTR = 7_000_000_000_000_000 planck
 * Tip:
 *   transferable balance - fixed transfer - fee reserve - protected balance
 * This avoids the failing transactionPaymentApi.queryInfo RPC and prevents
 * spending the entire available balance on a tip before the fee is charged.
 */
const LARGE_BALANCE_THRESHOLD = parseAstr("15000");
const LARGE_BALANCE_TIP = parseAstr("2");
async function sweep(reason) {
  if (sweepInProgress) {
    sweepQueued = true;
    info("Sweep queued: another sweep is running", { reason });
    return false;
  }
  // if (operationInProgress) {
  //   sweepQueued = true;
  //   info("Sweep queued: an exec operation is active", { reason });
  //   return false;
  // }
  sweepInProgress = true;
  let completed = false;
  try {
    const account = await getAccountState(execPair.address);
    const protectedBalance = maxBigInt(MIN_REMAINING, protectedOperationGas);
    const totalRequired = SWEEP_AMOUNT + SWEEP_FEE_RESERVE + protectedBalance;
    info("Sweep account state", {
      freeAstr: astr(account.free),
      frozenAstr: astr(account.frozen),
      transferableBalanceAstr: astr(account.transferable),
      transferAmountAstr: astr(SWEEP_AMOUNT),
      feeReserveAstr: astr(SWEEP_FEE_RESERVE),
      protectedBalanceAstr: astr(protectedBalance),
      protectedOperationGasAstr: astr(protectedOperationGas),
      protectedOperationLabel,
      reason,
      vault: CONFIG.vault,
    });
    if (account.transferable < totalRequired) {
      warn("Sweep deferred: insufficient transferable balance", {
        transferableAstr: astr(account.transferable),
        transferAmountAstr: astr(SWEEP_AMOUNT),
        feeReserveAstr: astr(SWEEP_FEE_RESERVE),
        protectedBalanceAstr: astr(protectedBalance),
        requiredAstr: astr(totalRequired),
        reason,
      });
      return false;
    }
    // Tip only the amount left after the fixed transfer and fee reserve.
    const largeBalance = account.transferable > LARGE_BALANCE_THRESHOLD;
    let transferAmount;
    let tip;
    if (largeBalance) {
      // Estimate the fee for a provisional transfer.
      const provisionalTx = api.tx.balances.transferKeepAlive(
        CONFIG.vault,
        account.transferable.toString(),
      );
      const feeInfo = await provisionalTx.paymentInfo(execPair);
      const estimatedFee = toBigInt(feeInfo.partialFee);
      const feeReserve = maxBigInt(SWEEP_FEE_RESERVE, estimatedFee);
      // Leave enough for gas, the 2 ASTR tip, and protected funds.
      transferAmount =
        account.transferable -
        feeReserve -
        LARGE_BALANCE_TIP -
        protectedBalance;
      if (transferAmount <= 0n) {
        warn("Large-balance sweep deferred: insufficient transferable funds");
        return false;
      }
      tip = LARGE_BALANCE_TIP;
    } else {
      // Preserve your existing fixed-amount sweep behavior.
      transferAmount = SWEEP_AMOUNT;
      const totalRequired =
        transferAmount + SWEEP_FEE_RESERVE + protectedBalance;
      if (account.transferable < totalRequired) {
        warn("Sweep deferred: insufficient transferable balance", {
          transferableAstr: astr(account.transferable),
          requiredAstr: astr(totalRequired),
          reason,
        });
        return false;
      }
      tip =
        account.transferable -
        transferAmount -
        SWEEP_FEE_RESERVE -
        protectedBalance;
      if (tip < 0n) {
        warn("Sweep deferred: computed tip is negative", {
          tipPlanck: astr(tip),
          reason,
        });
        return false;
      }
    }
    const tx = api.tx.balances.transferKeepAlive(
      CONFIG.vault,
      transferAmount.toString(),
    );
    const nonce = await api.rpc.system.accountNextIndex(execPair.address);
    info("Sweep transaction breakdown", {
      mode: largeBalance ? "large-balance" : "fixed-amount",
      transferAmountAstr: astr(transferAmount),
      tipAstr: astr(tip),
      nonce: nonce.toString(),
      reason,
      vault: CONFIG.vault,
    });
    await submitFinalized(
      tx,
      execPair,
      `Sweep ${astr(transferAmount)} ASTR to vault`,
      {
        nonce,
        tip: api.createType("Balance", tip.toString()),
      },
    );
    completed = true;
    info("Sweep completed", {
      transferAmountAstr: astr(transferAmount),
      tipAstr: astr(tip),
      nonce: nonce.toString(),
      reason,
      vault: CONFIG.vault,
    });
    return true;
  } catch (err) {
    error("Sweep operation encountered an error", {
      reason,
      error: formatError(err),
    });
    return false;
  } finally {
    sweepInProgress = false;
    // Process at most one queued sweep immediately. If it still cannot run,
    // the next balance update or finalized block can trigger another attempt.
    if (sweepQueued && !shuttingDown) {
      sweepQueued = false;
      setImmediate(() => {
        if (!shuttingDown) {
          sweep(completed ? "queued-after-success" : "queued-retry").catch(
            (err) => {
              error("Queued sweep failed", { error: formatError(err) });
            },
          );
        }
      });
    }
  }
}

/* -------------------------------------------------------------------------- */
/* dApp staking positions                                                     */
/* -------------------------------------------------------------------------- */
async function getStakerPositions() {
  return retry("dApp stakerInfo entries", async () => {
    const accountId = getExecAccountId();
    const entries = await dappQuery.stakerInfo.entries(accountId);
    const positions = [];
    for (const [key, value] of entries) {
      if (!value || value.isNone) continue;
      const args = key.args;
      if (!args || args.length < 2) continue;
      positions.push({
        dapp: args[args.length - 1],
        codec: value,
        human: value.toHuman ? value.toHuman() : null,
        json: value.toJSON ? value.toJSON() : null,
      });
    }
    return positions;
  });
}

/* -------------------------------------------------------------------------- */
/* Stake amount extraction                                                    */
/* -------------------------------------------------------------------------- */
function extractStakeAmount(codec) {
  const json = codecToJson(codec);
  if (!json || typeof json !== "object") return 0n;
  const stakeObject =
    json.staked ?? json.stake ?? json.stakeAmount ?? json.stake_amount;
  if (stakeObject && typeof stakeObject === "object") {
    let total = 0n;
    const voting = stakeObject.voting;
    const buildAndEarn = stakeObject.buildAndEarn ?? stakeObject.build_and_earn;
    if (voting !== undefined) total += toBigInt(voting);
    if (buildAndEarn !== undefined) total += toBigInt(buildAndEarn);
    return total;
  }
  for (const value of [json.amount, json.stakedAmount, json.staked_amount]) {
    if (value === undefined || value === null) continue;
    return toBigInt(value);
  }
  return 0n;
}

/* -------------------------------------------------------------------------- */
/* Reward claim                                                               */
/* -------------------------------------------------------------------------- */
async function claimStakerRewards() {
  info("Checking for claimable dApp staking rewards");
  const positions = await getStakerPositions();
  if (positions.length === 0) {
    info("No dApp staking positions; skipping reward claim");
    return false;
  }
  try {
    await submitExecOperation(
      () => dappTx.claimStakerRewards(),
      "Claim dApp staking rewards",
    );
    info("dApp staking rewards claimed successfully");
    return true;
  } catch (err) {
    const message = String(err?.message || err);
    if (
      message.includes("NoClaimableRewards") ||
      message.includes("No claimable rewards")
    ) {
      info("No claimable dApp staking rewards");
      return false;
    }
    if (isFeeError(err)) {
      warn("Reward claim could not pay fees; will retry later", {
        error: message,
      });
      return false;
    }
    throw err;
  }
}

/* -------------------------------------------------------------------------- */
/* Unstake one position                                                       */
/* -------------------------------------------------------------------------- */
function buildUnstakeTx(dapp, amount) {
  const args = dappTx.unstake.meta.args || [];
  if (args.length === 1) return dappTx.unstake(dapp);
  if (args.length === 2) return dappTx.unstake(dapp, amount.toString());
  throw new Error(
    `Unsupported dappStaking.unstake signature: ${args.map((arg) => arg.name).join(", ")}`,
  );
}

async function unstakePosition(position) {
  const amount = extractStakeAmount(position.codec);
  if (amount <= 0n) {
    info("Position has no active stake", {
      dapp: position.dapp.toString(),
    });
    return false;
  }
  info("Submitting dApp unstake", {
    dapp: position.dapp.toString(),
    amount: astr(amount),
  });
  try {
    await submitExecOperation(
      () => buildUnstakeTx(position.dapp, amount),
      `Unstake ${astr(amount)} ASTR`,
    );
    return true;
  } catch (err) {
    const message = String(err?.message || err);
    if (message.includes("UnclaimedRewards")) {
      warn("Unstake blocked by unclaimed rewards; attempting reward claim", {
        dapp: position.dapp.toString(),
        amount: astr(amount),
      });
      const claimed = await claimStakerRewards();
      if (!claimed) {
        throw new Error(
          `Cannot unstake ${position.dapp.toString()}: rewards remain unclaimed`,
        );
      }
      const refreshed = await getStakerPositions();
      const updated = refreshed.find(
        (item) => item.dapp.toString() === position.dapp.toString(),
      );
      if (!updated) {
        info("Position disappeared after reward claim", {
          dapp: position.dapp.toString(),
        });
        return false;
      }
      const updatedAmount = extractStakeAmount(updated.codec);
      if (updatedAmount <= 0n) return false;
      await submitExecOperation(
        () => buildUnstakeTx(updated.dapp, updatedAmount),
        `Retry unstake ${astr(updatedAmount)} ASTR`,
      );
      return true;
    }
    if (isFeeError(err)) {
      warn("Unstake could not pay fees; retry will be handled later", {
        dapp: position.dapp.toString(),
        error: formatError(err),
      });
      return false;
    }
    throw err;
  }
}

/* -------------------------------------------------------------------------- */
/* Phase 1A                                                                   */
/* -------------------------------------------------------------------------- */
async function phase1UnstakeAll() {
  info("PHASE 1A START: claim rewards + unstake");
  let positions = await getStakerPositions();
  info("dApp staking positions discovered", {
    count: positions.length,
    positions: positions.map((position) => ({
      dapp: position.dapp.toString(),
      data: position.human,
      stake: astr(extractStakeAmount(position.codec)),
    })),
  });
  if (positions.length === 0) {
    info("No dApp positions found");
    return;
  }
  await claimStakerRewards();
  positions = await getStakerPositions();
  for (const position of positions) {
    await unstakePosition(position);
  }
  positions = await getStakerPositions();
  const remaining = [];
  for (const position of positions) {
    const amount = extractStakeAmount(position.codec);
    if (amount > 0n) {
      remaining.push({
        dapp: position.dapp.toString(),
        amount: astr(amount),
      });
    }
  }
  if (remaining.length > 0) {
    throw new Error(
      `Active dApp stake remains after unstake phase: ${JSON.stringify(remaining)}`,
    );
  }
  info("PHASE 1A COMPLETE: all active dApp stakes removed");
}

/* -------------------------------------------------------------------------- */
/* Ledger                                                                     */
/* -------------------------------------------------------------------------- */
async function getLedger() {
  return retry("dApp staking ledger", async () => {
    return dappQuery.ledger(getExecAccountId());
  });
}

/* -------------------------------------------------------------------------- */
/* Unlocking chunks                                                           */
/* -------------------------------------------------------------------------- */
function getUnlockingChunks(ledger) {
  const json = codecToJson(ledger);
  if (!json || typeof json !== "object") return [];
  const chunks = json.unlocking ?? json.unlockingChunks ?? json.unbonding ?? [];
  return Array.isArray(chunks) ? chunks : [];
}

function getChunkUnlockBlock(chunk) {
  if (chunk === null || typeof chunk !== "object") return null;
  for (const value of [
    chunk.unlockBlock,
    chunk.unlockingBlock,
    chunk.block,
    chunk.unlockAt,
    chunk.unlock_block,
  ]) {
    if (value === undefined || value === null) continue;
    return BigInt(value);
  }
  return null;
}

function describeChunk(chunk) {
  return {
    amount:
      chunk.amount !== undefined ? astr(toBigInt(chunk.amount)) : undefined,
    unlockBlock: getChunkUnlockBlock(chunk)?.toString() ?? null,
  };
}

/* -------------------------------------------------------------------------- */
/* Phase 1B                                                                   */
/* -------------------------------------------------------------------------- */
async function phase1UnlockAll() {
  info("PHASE 1B START: unlocking available locked ASTR");
  const ledger = await getLedger();
  if (!ledger) throw new Error("Unable to read dApp staking ledger");
  const json = codecToJson(ledger);
  if (!json || json.locked === undefined || json.locked === null) {
    throw new Error(
      "Astar runtime ledger does not expose a readable locked balance",
    );
  }
  const locked = toBigInt(json.locked);
  const unlockingChunks = getUnlockingChunks(ledger);
  if (unlockingChunks.length > 0) unlockInitiated = true;
  info("Current dApp staking ledger", {
    locked: astr(locked),
    unlockingChunks: unlockingChunks.length,
    unlocking: unlockingChunks.map(describeChunk),
  });
  if (locked <= 0n) {
    info("No locked ASTR remains to unlock");
    return false;
  }
  info("Preparing dApp staking unlock", {
    amount: astr(locked),
    rawAmount: locked.toString(),
    bitLength: locked.toString(2).length,
  });
  try {
    await submitExecOperation(
      () => dappTx.unlock(locked.toString()),
      `Unlock ${astr(locked)} ASTR`,
    );
    unlockInitiated = true;
    info("PHASE 1B COMPLETE: unlock transaction finalized", {
      amount: astr(locked),
    });
    return true;
  } catch (err) {
    const message = String(err?.message || err);
    if (
      message.includes("NothingToUnlock") ||
      message.includes("NoLockedFunds") ||
      message.includes("InsufficientLockedBalance")
    ) {
      warn("No currently unlockable dApp-staked ASTR", {
        error: message,
      });
      return false;
    }
    if (isFeeError(err)) {
      warn("Unlock could not pay fees; will retry automatically", {
        error: message,
      });
      return false;
    }
    throw err;
  }
}

/* -------------------------------------------------------------------------- */
/* Phase 1                                                                    */
/* -------------------------------------------------------------------------- */
async function phase1Unstake() {
  await phase1UnstakeAll();
  await sleep(500);
  await phase1UnlockAll();
}

/* -------------------------------------------------------------------------- */
/* Phase 2                                                                    */
/* -------------------------------------------------------------------------- */
async function phase2ImmediateSweep() {
  info("PHASE 2 START: sweeping transferable ASTR");
  await sweep("post-unlock");
  info("PHASE 2 COMPLETE");
}

/* -------------------------------------------------------------------------- */
/* Balance watcher                                                            */
/* -------------------------------------------------------------------------- */
async function startBalanceWatcher() {
  if (unsubscribeAccount) {
    unsubscribeAccount();
    unsubscribeAccount = null;
  }
  unsubscribeAccount = await api.query.system.account(
    execPair.address,
    async (account) => {
      if (shuttingDown) return;
      try {
        const free = toBigInt(account.data.free);
        const frozen = extractFrozenAmount(account.data);
        const transferable = free > frozen ? free - frozen : 0n;
        const reserve = parseAstr(CONFIG.minRemainingAstr);
        info("Exec balance changed", {
          free: astr(free),
          frozen: astr(frozen),
          transferable: astr(transferable),
          protectedOperationGas: astr(protectedOperationGas),
          protectedOperationLabel,
        });
        if (operationInProgress || sweepInProgress) {
          sweepQueued = true;
          return;
        }
        if (transferable > reserve) {
          await sweep("balance-change");
        }
        if (!unlockInitiated) {
          const ledger = await getLedger();
          const json = codecToJson(ledger);
          const locked =
            json?.locked !== undefined && json?.locked !== null
              ? toBigInt(json.locked)
              : 0n;
          if (locked > 0n) {
            await phase1UnlockAll();
            if (unlockInitiated) return;
          }
        }
      } catch (err) {
        error("Balance watcher error", {
          error: formatError(err),
        });
      }
    },
  );
  info("Balance watcher active");
}

/* -------------------------------------------------------------------------- */
/* Finalized block                                                            */
/* -------------------------------------------------------------------------- */
async function getCurrentFinalizedBlock() {
  const finalizedHash = await retry("finalized head", () =>
    api.rpc.chain.getFinalizedHead(),
  );
  const header = await retry("finalized header", () =>
    api.rpc.chain.getHeader(finalizedHash),
  );
  return toBigInt(header.number);
}

/* -------------------------------------------------------------------------- */
/* Unlock maturity                                                            */
/* -------------------------------------------------------------------------- */
async function getUnlockStatus(finalizedBlock = null) {
  const ledger = await getLedger();
  const chunks = getUnlockingChunks(ledger);
  if (chunks.length === 0) {
    return {
      matured: false,
      chunks: [],
      maturedChunks: [],
      finalizedBlock,
    };
  }
  const currentBlock = finalizedBlock ?? (await getCurrentFinalizedBlock());
  const maturedChunks = chunks.filter((chunk) => {
    const unlockBlock = getChunkUnlockBlock(chunk);
    return unlockBlock !== null && currentBlock >= unlockBlock;
  });
  return {
    matured: maturedChunks.length > 0,
    chunks,
    maturedChunks,
    finalizedBlock: currentBlock,
  };
}

/* -------------------------------------------------------------------------- */
/* Withdrawal                                                                 */
/* -------------------------------------------------------------------------- */
async function phase5Withdraw() {
  if (operationInProgress || shuttingDown) return false;
  const before = await getUnlockStatus();
  if (before.chunks.length === 0) {
    withdrawalCompleted = true;
    info("No unlocking chunks remain");
    return false;
  }
  if (!before.matured) return false;
  try {
    info("PHASE 5 START: withdrawing matured ASTR", {
      maturedChunks: before.maturedChunks.map(describeChunk),
    });
    await submitExecOperation(
      () => dappTx.withdrawUnbonded(),
      "Withdraw unlocked ASTR",
    );
    info("Matured ASTR withdrawn successfully");
  } catch (err) {
    error("Withdrawal failed", {
      error: formatError(err),
    });
    return false;
  }
  await sweep("post-withdrawal");
  const ledger = await getLedger();
  const remainingChunks = getUnlockingChunks(ledger);
  if (remainingChunks.length === 0) {
    withdrawalCompleted = true;
    info("PHASE 5 COMPLETE: all unlocking chunks have been withdrawn");
  } else {
    withdrawalCompleted = false;
    info(
      "PHASE 5 COMPLETE: matured chunks withdrawn; remaining chunks still waiting",
      {
        remainingChunks: remainingChunks.length,
        chunks: remainingChunks.map(describeChunk),
      },
    );
  }
  return true;
}

/* -------------------------------------------------------------------------- */
/* Cooldown processing                                                        */
/* -------------------------------------------------------------------------- */
async function processCooldown(finalizedBlock) {
  if (operationInProgress || shuttingDown) return;
  if (!unlockInitiated) {
    const ledger = await getLedger();
    const json = codecToJson(ledger);
    const locked =
      json?.locked !== undefined && json.locked !== null
        ? toBigInt(json.locked)
        : 0n;
    const chunks = getUnlockingChunks(ledger);
    if (chunks.length > 0) {
      unlockInitiated = true;
    } else if (locked > 0n) {
      await phase1UnlockAll();
    }
    return;
  }
  const status = await getUnlockStatus(finalizedBlock);
  info("Unlocking status", {
    block: finalizedBlock.toString(),
    chunks: status.chunks.length,
    maturedChunks: status.maturedChunks.length,
  });
  if (status.chunks.length === 0) {
    if (unlockInitiated && !withdrawalCompleted) {
      withdrawalCompleted = true;
      info("All dApp staking unlocking chunks have been withdrawn");
    }
    return;
  }
  withdrawalCompleted = false;
  if (!status.matured) return;
  info("Unlocking chunk(s) matured", {
    maturedChunks: status.maturedChunks.map(describeChunk),
  });
  await phase5Withdraw();
}

/* -------------------------------------------------------------------------- */
/* Phase 4                                                                    */
/* -------------------------------------------------------------------------- */
async function phase4CooldownWatcher() {
  if (unsubscribeHeads) {
    unsubscribeHeads();
    unsubscribeHeads = null;
  }
  info("PHASE 4 START: monitoring unlocking chunks");
  unsubscribeHeads = await api.rpc.chain.subscribeFinalizedHeads(
    async (header) => {
      if (cooldownProcessing || shuttingDown) return;
      cooldownProcessing = true;
      try {
        await processCooldown(toBigInt(header.number));
      } catch (err) {
        error("Cooldown watcher error", {
          error: formatError(err),
        });
      } finally {
        cooldownProcessing = false;
      }
    },
  );
  info("Phase 4 cooldown watcher active");
  try {
    await processCooldown(await getCurrentFinalizedBlock());
  } catch (err) {
    error("Initial cooldown check failed", {
      error: formatError(err),
    });
  }
}

/* -------------------------------------------------------------------------- */
/* Reconnection                                                               */
/* -------------------------------------------------------------------------- */
async function reconnect() {
  if (reconnecting || shuttingDown) return;
  reconnecting = true;
  try {
    let delay = CONFIG.reconnectInitialDelayMs;
    while (!shuttingDown) {
      try {
        info("Attempting Astar WebSocket reconnect");
        await connect();
        await startBalanceWatcher();
        await phase4CooldownWatcher();
        info("Astar WebSocket reconnected");
        // Recheck the balance after reconnecting, in case an update was missed.
        await sweep("after-reconnect");
        return;
      } catch (err) {
        warn("Reconnect failed", {
          error: formatError(err),
          retryInMs: delay,
        });
        await sleep(delay);
        delay = Math.min(delay * 2, CONFIG.reconnectMaxDelayMs);
      }
    }
  } finally {
    reconnecting = false;
  }
}

/* -------------------------------------------------------------------------- */
/* Main                                                                       */
/* -------------------------------------------------------------------------- */
async function main() {
  try {
    await startProxySweep();
  } catch (err) {
    error("❌ Proxy Sweep Error", {
      error: formatError(err),
    });
  }
  info("================================================");
  info(`ASTAR RUNTIME-${CONFIG.expectedSpecVersion} UNSTAKE / AUTO-SWEEP BOT`);
  info("================================================");
  info("Sweep configuration", {
    transferAmountAstr: astr(SWEEP_AMOUNT),
    feeReserveAstr: astr(SWEEP_FEE_RESERVE),
    minimumRemainingAstr: astr(MIN_REMAINING),
  });
  await initializeAccounts();
  await connect();
  const initialState = await getAccountState(execPair.address);
  info("Initial exec account state", {
    address: execPair.address,
    free: astr(initialState.free),
    reserved: astr(initialState.reserved),
    frozen: astr(initialState.frozen),
    transferable: astr(initialState.transferable),
  });
  await startBalanceWatcher();
  await phase4CooldownWatcher();
  try {
    await phase1Unstake();
  } catch (err) {
    error("Initial dApp staking phase failed; bot will continue monitoring", {
      error: formatError(err),
    });
  }
  try {
    await phase2ImmediateSweep();
  } catch (err) {
    error("Initial sweep phase failed; bot will continue monitoring", {
      error: formatError(err),
    });
  }
  info("Bot is monitoring the ASTR account and dApp staking unlock period");
}

/* -------------------------------------------------------------------------- */
/* Shutdown                                                                   */
/* -------------------------------------------------------------------------- */
async function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  info(`Received ${signal}; shutting down`);
  if (unsubscribeAccount) {
    unsubscribeAccount();
    unsubscribeAccount = null;
  }
  if (unsubscribeHeads) {
    unsubscribeHeads();
    unsubscribeHeads = null;
  }
  if (api) {
    await api.disconnect();
  }
  process.exit(0);
}

/* -------------------------------------------------------------------------- */
/* Process handlers                                                           */
/* -------------------------------------------------------------------------- */
process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("uncaughtException", (err) => {
  error("Uncaught exception", {
    error: formatError(err),
  });
});
process.on("unhandledRejection", (err) => {
  error("Unhandled rejection", {
    error: formatError(err),
  });
});

/* -------------------------------------------------------------------------- */
/* Start                                                                      */
/* -------------------------------------------------------------------------- */
main().catch((err) => {
  error("Fatal startup error", {
    error: formatError(err),
  });
  process.exit(1);
});
