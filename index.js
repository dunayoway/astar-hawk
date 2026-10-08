"use strict";

const { ApiPromise, WsProvider, Keyring } = require("@polkadot/api");
const { cryptoWaitReady } = require("@polkadot/util-crypto");
require("dotenv").config();

/* -------------------------------------------------------------------------- */
/* Configuration                                                              */
/* -------------------------------------------------------------------------- */

function required(name) {
  const value = process.env[name];

  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }

  return value;
}

const CONFIG = {
  wss: required("ASTAR_WSS"),

  execMnemonic: process.env.EXEC_MNEMONIC,
  execPrivateKey: process.env.EXEC_PRIVATE_KEY,

  sponsorMnemonic: process.env.SPONSOR_MNEMONIC,
  sponsorPrivateKey: process.env.SPONSOR_PRIVATE_KEY,

  vault: required("VAULT_ADDRESS"),

  expectedSpecVersion: Number(process.env.EXPECTED_SPEC_VERSION || "2400"),

  rpcMaxRetries: Number(process.env.RPC_MAX_RETRIES || "6"),

  feeSafetyBps: BigInt(process.env.FEE_SAFETY_BPS || "2000"),

  minRemainingAstr: process.env.MIN_REMAINING_ASTR || "0.00001",

  reconnectInitialDelayMs: Number(
    process.env.RECONNECT_INITIAL_DELAY_MS || "1000",
  ),

  reconnectMaxDelayMs: Number(process.env.RECONNECT_MAX_DELAY_MS || "30000"),

  rpcRetryInitialDelayMs: Number(
    process.env.RPC_RETRY_INITIAL_DELAY_MS || "500",
  ),

  rpcRetryMaxDelayMs: Number(process.env.RPC_RETRY_MAX_DELAY_MS || "10000"),

  /*
   * Extra sponsor funding safety.
   *
   * This is added on top of the transaction fee safety.
   *
   * Example:
   *
   * estimated fee = 0.04
   * fee safety    = 20%
   * sponsor extra = 0.01
   *
   * total funded ~= 0.058 ASTR
   */
  sponsorExtraAstr: process.env.SPONSOR_EXTRA_ASTR || "0.01",

  /*
   * Prevent accidental huge sponsor transfers.
   */
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
let operationInProgress = false;
let cooldownProcessing = false;

let unlockInitiated = false;
let withdrawalCompleted = false;

let reconnectGeneration = 0;

/*
 * Generic protected gas.
 *
 * This is used for:
 *
 *   sponsor -> exec funding
 *   claim
 *   unstake
 *   unlock
 *   withdraw
 *
 * The balance watcher will NEVER sweep this amount.
 */
let protectedOperationGas = 0n;

let protectedOperationLabel = null;

let dappTx = null;
let dappQuery = null;

/* -------------------------------------------------------------------------- */
/* Logging                                                                    */
/* -------------------------------------------------------------------------- */

function log(level, message, data = undefined) {
  const record = {
    timestamp: new Date().toISOString(),
    level,
    message,
  };

  if (data !== undefined) {
    record.data = data;
  }

  console.log(JSON.stringify(record));
}

const info = (message, data) => log("INFO", message, data);

const warn = (message, data) => log("WARN", message, data);

const error = (message, data) => log("ERROR", message, data);

/* -------------------------------------------------------------------------- */
/* Utilities                                                                  */
/* -------------------------------------------------------------------------- */

function sleep(ms) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

function toBigInt(value) {
  if (typeof value === "bigint") {
    return value;
  }

  if (value && typeof value.toBigInt === "function") {
    return value.toBigInt();
  }

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

function minBigInt(a, b) {
  return a < b ? a : b;
}

function isFeeError(err) {
  const message = String(err?.message || err || "");

  return (
    message.includes("1010") ||
    message.includes("Inability to pay some fees") ||
    message.includes("account balance too low")
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

      if (attempt === CONFIG.rpcMaxRetries) {
        throw err;
      }

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
    execPair = keyring.addFromSeed(
      Buffer.from(CONFIG.execPrivateKey.replace(/^0x/, ""), "hex"),
    );
  }

  if (CONFIG.sponsorMnemonic) {
    sponsorPair = keyring.addFromUri(CONFIG.sponsorMnemonic);
  } else {
    sponsorPair = keyring.addFromSeed(
      Buffer.from(CONFIG.sponsorPrivateKey.replace(/^0x/, ""), "hex"),
    );
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
  if (!api) {
    throw new Error("API is not initialized");
  }

  const specVersion = api.runtimeVersion.specVersion.toNumber();

  if (specVersion !== CONFIG.expectedSpecVersion) {
    throw new Error(
      `Runtime mismatch. Expected ${CONFIG.expectedSpecVersion}, got ${specVersion}`,
    );
  }

  if (!api.tx.dappStaking) {
    throw new Error("dApp staking transaction pallet is unavailable");
  }

  if (!api.query.dappStaking) {
    throw new Error("dApp staking query pallet is unavailable");
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

  info("Astar runtime verified", {
    specVersion,

    pallet: "dappStaking",

    calls: {
      claimStakerRewards: true,
      unstake: true,
      unlock: true,
      withdrawUnbonded: true,
    },

    storage: {
      ledger: true,
      stakerInfo: true,
      activeProtocolState: true,
    },
  });
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

  const specVersion = api.runtimeVersion.specVersion.toNumber();

  info("Connected to Astar", {
    chain: chain.toString(),
    specName: api.runtimeVersion.specName.toString(),
    specVersion,
    properties: properties.toJSON(),
  });

  verifyRuntime();
}

/* -------------------------------------------------------------------------- */
/* Account state                                                              */
/* -------------------------------------------------------------------------- */

function extractFrozenAmount(data) {
  const candidates = [];

  const fields = [
    "frozen",
    "miscFrozen",
    "feeFrozen",
    "misc_frozen",
    "fee_frozen",
  ];

  for (const field of fields) {
    if (data[field] !== undefined && data[field] !== null) {
      try {
        candidates.push(toBigInt(data[field]));
      } catch {}
    }
  }

  if (candidates.length === 0) {
    return 0n;
  }

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
  const state = await getAccountState(address);

  return state.free;
}

/* -------------------------------------------------------------------------- */
/* Transaction finalization                                                   */
/* -------------------------------------------------------------------------- */

async function submitFinalized(tx, signer, label) {
  return new Promise(async (resolve, reject) => {
    let unsubscribe = null;
    let finished = false;

    const fail = (err) => {
      if (finished) {
        return;
      }

      finished = true;

      if (unsubscribe) {
        try {
          unsubscribe();
        } catch {}
      }

      reject(err);
    };

    try {
      unsubscribe = await tx.signAndSend(signer, (result) => {
        if (finished) {
          return;
        }

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

            message = `${decoded.section}.${decoded.name}: ${decoded.docs.join(
              " ",
            )}`;
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

        if (result.status.isFinalized) {
          finished = true;

          info(`${label}: finalized`, {
            block: result.status.asFinalized.toHex(),
          });

          if (unsubscribe) {
            try {
              unsubscribe();
            } catch {}
          }

          resolve(result);
        }
      });
    } catch (err) {
      fail(err);
    }
  });
}

/* -------------------------------------------------------------------------- */
/* Fee estimation                                                             */
/* -------------------------------------------------------------------------- */

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
  if (requiredAmount <= 0n) {
    return 0n;
  }

  const extra = parseAstr(CONFIG.sponsorExtraAstr);

  let funding = requiredAmount + extra;

  const maximum = parseAstr(CONFIG.maxSponsorFundingAstr);

  if (funding > maximum) {
    throw new Error(
      `Sponsor funding request ${astr(
        funding,
      )} exceeds MAX_SPONSOR_FUNDING_ASTR=${CONFIG.maxSponsorFundingAstr}`,
    );
  }

  const sponsorState = await getAccountState(sponsorPair.address);

  const sponsorReserve = parseAstr(CONFIG.minRemainingAstr);

  const sponsorAvailable =
    sponsorState.transferable > sponsorReserve
      ? sponsorState.transferable - sponsorReserve
      : 0n;

  /*
   * Estimate the sponsor transfer itself.
   *
   * The sponsor also has to pay the transfer fee.
   */
  let transferTx = api.tx.balances.transferKeepAlive(execPair.address, funding);

  const transferFee = await estimateFee(transferTx, sponsorPair);

  const sponsorRequired = funding + addFeeSafety(transferFee);

  if (sponsorAvailable < sponsorRequired) {
    throw new Error(
      `Sponsor cannot fund exec. Required ${astr(
        sponsorRequired,
      )} ASTR, available ${astr(sponsorAvailable)} ASTR`,
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

  /*
   * Protect BEFORE broadcasting.
   *
   * This prevents the balance watcher from
   * sweeping the newly funded ASTR.
   */
  protectedOperationGas = funding;

  protectedOperationLabel = reason;

  try {
    await submitFinalized(
      transferTx,
      sponsorPair,
      `Sponsor → exec ${astr(funding)} ASTR`,
    );

    return funding;
  } catch (err) {
    /*
     * Do not remove protection on failure.
     *
     * The funding may have been included even
     * if the callback encountered an RPC issue.
     */
    throw err;
  }
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
    /*
     * Build transaction before funding.
     */
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

    /*
     * If exec cannot pay, sponsor funds
     * the shortfall.
     */
    if (!requirement.canAfford) {
      const shortfall =
        requirement.feeWithSafety > requirement.available
          ? requirement.feeWithSafety - requirement.available
          : 0n;

      await sponsorFundExec(shortfall, label);

      /*
       * Rebuild the transaction after
       * sponsor funding.
       */
      tx = txFactory();

      requirement = await getFeeRequirement(tx, execPair);

      if (!requirement.canAfford) {
        throw new Error(
          `Exec still cannot afford ${label} after sponsor funding. Available ${astr(
            requirement.available,
          )}, required ${astr(requirement.feeWithSafety)}`,
        );
      }
    }

    /*
     * Transaction can now safely be submitted.
     */
    await submitFinalized(tx, execPair, label);

    /*
     * Operation succeeded.
     *
     * Any sponsor-funded gas that remains
     * is now ordinary exec balance and can
     * be swept.
     */
    protectedOperationGas = 0n;
    protectedOperationLabel = null;

    return true;
  } catch (err) {
    /*
     * Keep sponsor-funded gas protected so
     * a later retry can use it.
     */
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

  const tx = api.tx.balances.transferKeepAlive(destination, amount);

  return submitFinalized(tx, signer, label);
}

/* -------------------------------------------------------------------------- */
/* Sweep helpers                                                              */
/* -------------------------------------------------------------------------- */

function isFrozenError(err) {
  return (
    err?.dispatchMethod === "Frozen" ||
    String(err?.message || "").includes("Frozen") ||
    String(err?.message || "").includes('{"token":"Frozen"}')
  );
}

function calculateSweepAmount({
  free,
  frozen,
  reserve,
  fee,
  protectedGas = 0n,
}) {
  /*
   * Frozen balance is untouchable.
   *
   * We also protect:
   *
   *   - configured reserve
   *   - operation gas
   *   - transaction fee
   */
  const protectedBalance = maxBigInt(maxBigInt(reserve, frozen), protectedGas);

  const feeWithSafety = addFeeSafety(fee);

  const amount =
    free > protectedBalance + feeWithSafety
      ? free - protectedBalance - feeWithSafety
      : 0n;

  return {
    amount,
    protectedBalance,
    feeWithSafety,
  };
}

/* -------------------------------------------------------------------------- */
/* Sweep                                                                      */
/* -------------------------------------------------------------------------- */

async function sweep(reason) {
  if (sweepInProgress) {
    info("Sweep skipped: another sweep is running");

    return false;
  }

  if (operationInProgress) {
    info("Sweep skipped: exec operation is active");

    return false;
  }

  sweepInProgress = true;

  try {
    const reserve = parseAstr(CONFIG.minRemainingAstr);

    let account = await getAccountState(execPair.address);

    info("Sweep account state", {
      free: astr(account.free),
      reserved: astr(account.reserved),
      frozen: astr(account.frozen),
      transferable: astr(account.transferable),
      reserve: astr(reserve),
      protectedOperationGas: astr(protectedOperationGas),
      protectedOperationLabel,
      reason,
    });

    const protectedBalance = maxBigInt(
      maxBigInt(reserve, account.frozen),
      protectedOperationGas,
    );

    if (account.free <= protectedBalance) {
      info("Nothing safely sweepable", {
        free: astr(account.free),
        frozen: astr(account.frozen),
        reserve: astr(reserve),
        protectedOperationGas: astr(protectedOperationGas),
        protectedBalance: astr(protectedBalance),
      });

      return false;
    }

    /*
     * First fee estimate.
     */
    const candidate = account.free - protectedBalance;

    let feeTx = api.tx.balances.transferKeepAlive(CONFIG.vault, candidate);

    const estimatedFee = await estimateFee(feeTx, execPair);

    let calculation = calculateSweepAmount({
      free: account.free,
      frozen: account.frozen,
      reserve,
      fee: estimatedFee,
      protectedGas: protectedOperationGas,
    });

    if (calculation.amount <= 0n) {
      info("Nothing remains after fee/protection", {
        free: astr(account.free),
        frozen: astr(account.frozen),
        estimatedFee: astr(estimatedFee),
        protectedBalance: astr(calculation.protectedBalance),
      });

      return false;
    }

    /*
     * Re-estimate using actual amount.
     */
    feeTx = api.tx.balances.transferKeepAlive(CONFIG.vault, calculation.amount);

    const finalEstimatedFee = await estimateFee(feeTx, execPair);

    calculation = calculateSweepAmount({
      free: account.free,
      frozen: account.frozen,
      reserve,
      fee: finalEstimatedFee,
      protectedGas: protectedOperationGas,
    });

    if (calculation.amount <= 0n) {
      info("Final fee calculation leaves nothing sweepable", {
        free: astr(account.free),
        frozen: astr(account.frozen),
        estimatedFee: astr(finalEstimatedFee),
        protectedBalance: astr(calculation.protectedBalance),
      });

      return false;
    }

    const amount = calculation.amount;

    info("Submitting sweep", {
      amount: astr(amount),

      estimatedFee: astr(finalEstimatedFee),

      feeWithSafety: astr(calculation.feeWithSafety),

      frozen: astr(account.frozen),

      reserve: astr(reserve),

      protectedOperationGas: astr(protectedOperationGas),

      protectedOperationLabel,

      protectedBalance: astr(calculation.protectedBalance),

      reason,

      vault: CONFIG.vault,
    });

    const tx = api.tx.balances.transferKeepAlive(CONFIG.vault, amount);

    try {
      await submitFinalized(tx, execPair, `Sweep ${astr(amount)} ASTR`);

      info("Sweep completed", {
        amount: astr(amount),
        reason,
      });

      return true;
    } catch (err) {
      if (!isFrozenError(err)) {
        error("Sweep failed", {
          reason,
          error: formatError(err),
        });

        return false;
      }

      /*
       * Frozen is recoverable.
       */
      warn("Sweep rejected by Frozen protection; refreshing account", {
        error: formatError(err),
      });

      account = await getAccountState(execPair.address);

      info("Refreshed account after Frozen", {
        free: astr(account.free),
        reserved: astr(account.reserved),
        frozen: astr(account.frozen),
        transferable: astr(account.transferable),
      });

      const retryProtected = maxBigInt(
        maxBigInt(reserve, account.frozen),
        protectedOperationGas,
      );

      if (account.free <= retryProtected) {
        warn("No balance remains sweepable after Frozen protection", {
          free: astr(account.free),
          frozen: astr(account.frozen),
          protected: astr(retryProtected),
        });

        return false;
      }

      const retryCandidate = account.free - retryProtected;

      const retryFeeTx = api.tx.balances.transferKeepAlive(
        CONFIG.vault,
        retryCandidate,
      );

      const retryFee = await estimateFee(retryFeeTx, execPair);

      const retryCalculation = calculateSweepAmount({
        free: account.free,
        frozen: account.frozen,
        reserve,
        fee: retryFee,
        protectedGas: protectedOperationGas,
      });

      if (retryCalculation.amount <= 0n) {
        warn("Frozen recovery leaves no sweepable amount");

        return false;
      }

      info("Retrying sweep with refreshed protection", {
        amount: astr(retryCalculation.amount),
        frozen: astr(account.frozen),
        protected: astr(retryCalculation.protectedBalance),
      });

      const retryTx = api.tx.balances.transferKeepAlive(
        CONFIG.vault,
        retryCalculation.amount,
      );

      await submitFinalized(
        retryTx,
        execPair,
        `Retry sweep ${astr(retryCalculation.amount)} ASTR`,
      );

      info("Sweep recovery completed", {
        amount: astr(retryCalculation.amount),
        reason,
      });

      return true;
    }
  } catch (err) {
    error("Sweep operation encountered an error", {
      reason,
      error: formatError(err),
    });

    return false;
  } finally {
    sweepInProgress = false;
  }
}

/* -------------------------------------------------------------------------- */
/* dApp staking positions                                                     */
/* -------------------------------------------------------------------------- */

async function getStakerPositions() {
  return retry("dApp stakerInfo entries", async () => {
    const entries = await dappQuery.stakerInfo.entries(execPair.address);

    const positions = [];

    for (const [key, value] of entries) {
      if (!value || value.isNone) {
        continue;
      }

      const args = key.args;

      if (!args || args.length < 2) {
        continue;
      }

      const dapp = args[args.length - 1];

      positions.push({
        dapp,
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

  if (!json || typeof json !== "object") {
    return 0n;
  }

  const stakeObject =
    json.staked ?? json.stake ?? json.stakeAmount ?? json.stake_amount;

  if (stakeObject && typeof stakeObject === "object") {
    let total = 0n;

    const voting = stakeObject.voting;

    const buildAndEarn = stakeObject.buildAndEarn ?? stakeObject.build_and_earn;

    if (voting !== undefined) {
      total += toBigInt(voting);
    }

    if (buildAndEarn !== undefined) {
      total += toBigInt(buildAndEarn);
    }

    return total;
  }

  const directCandidates = [json.amount, json.stakedAmount, json.staked_amount];

  for (const value of directCandidates) {
    if (value === undefined || value === null) {
      continue;
    }

    try {
      return toBigInt(value);
    } catch {}
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
      () => dappTx.unstake(position.dapp, amount),
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

      if (updatedAmount <= 0n) {
        return false;
      }

      await submitExecOperation(
        () => dappTx.unstake(updated.dapp, updatedAmount),
        `Retry unstake ${astr(updatedAmount)} ASTR`,
      );

      return true;
    }

    /*
     * Fee errors are recoverable.
     */
    if (isFeeError(err)) {
      warn("Unstake could not pay fees; sponsor funding/retry will handle it", {
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

  /*
   * Query positions FIRST.
   *
   * This avoids the useless claim transaction
   * when there are no positions.
   */
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

  /*
   * Claim before unstaking.
   *
   * If there are insufficient funds,
   * submitExecOperation() automatically
   * asks the sponsor for gas.
   */
  await claimStakerRewards();

  /*
   * Refresh positions after claiming.
   */
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
      `Active dApp stake remains after unstake phase: ${JSON.stringify(
        remaining,
      )}`,
    );
  }

  info("PHASE 1A COMPLETE: all active dApp stakes removed");
}

/* -------------------------------------------------------------------------- */
/* Ledger                                                                     */
/* -------------------------------------------------------------------------- */

async function getLedger() {
  return retry("dApp staking ledger", () => dappQuery.ledger(execPair.address));
}

/* -------------------------------------------------------------------------- */
/* Unlocking chunks                                                           */
/* -------------------------------------------------------------------------- */

function getUnlockingChunks(ledger) {
  const json = codecToJson(ledger);

  if (!json || typeof json !== "object") {
    return [];
  }

  const chunks = json.unlocking ?? json.unlockingChunks ?? json.unbonding ?? [];

  return Array.isArray(chunks) ? chunks : [];
}

function getChunkUnlockBlock(chunk) {
  if (chunk === null || typeof chunk !== "object") {
    return null;
  }

  const candidates = [
    chunk.unlockBlock,
    chunk.unlockingBlock,
    chunk.block,
    chunk.unlockAt,
    chunk.unlock_block,
  ];

  for (const value of candidates) {
    if (value === undefined || value === null) {
      continue;
    }

    try {
      return BigInt(value);
    } catch {}
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

  if (!ledger) {
    throw new Error("Unable to read dApp staking ledger");
  }

  const json = codecToJson(ledger);

  if (!json || json.locked === undefined || json.locked === null) {
    throw new Error(
      "Runtime 2400 ledger does not expose a readable locked balance",
    );
  }

  const locked = toBigInt(json.locked);

  const unlockingChunks = getUnlockingChunks(ledger);

  if (unlockingChunks.length > 0) {
    unlockInitiated = true;
  }

  info("Current dApp staking ledger", {
    locked: astr(locked),

    unlockingChunks: unlockingChunks.length,

    unlocking: unlockingChunks.map(describeChunk),
  });

  if (locked <= 0n) {
    info("No locked ASTR remains to unlock");

    return false;
  }

  /*
   * Runtime 2400 unlock expects
   * Compact<u128>.
   *
   * Therefore we pass the actual
   * ledger locked value.
   */
  const amountToUnlock = locked;

  info("Preparing dApp staking unlock", {
    amount: astr(amountToUnlock),

    rawAmount: amountToUnlock.toString(),

    bitLength: amountToUnlock.toString(2).length,
  });

  try {
    await submitExecOperation(
      () => dappTx.unlock(amountToUnlock.toString()),
      `Unlock ${astr(amountToUnlock)} ASTR`,
    );

    unlockInitiated = true;

    info("PHASE 1B COMPLETE: unlock transaction finalized", {
      amount: astr(amountToUnlock),
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
    try {
      unsubscribeAccount();
    } catch {}

    unsubscribeAccount = null;
  }

  unsubscribeAccount = await api.query.system.account(
    execPair.address,
    async (account) => {
      if (operationInProgress || sweepInProgress) {
        return;
      }

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

        /*
         * Retry a pending unlock if:
         *
         *   - no unlock has started
         *   - there is locked ASTR
         *   - the account now has some
         *     usable balance
         */
        if (!unlockInitiated) {
          const ledger = await getLedger();

          const json = codecToJson(ledger);

          const locked =
            json?.locked !== undefined && json?.locked !== null
              ? toBigInt(json.locked)
              : 0n;

          if (locked > 0n) {
            await phase1UnlockAll();

            if (unlockInitiated) {
              return;
            }
          }
        }

        if (transferable > reserve) {
          await sweep("balance-change");
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
  if (operationInProgress || shuttingDown) {
    return false;
  }

  const before = await getUnlockStatus();

  if (before.chunks.length === 0) {
    withdrawalCompleted = true;

    info("No unlocking chunks remain");

    return false;
  }

  if (!before.matured) {
    return false;
  }

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
  if (operationInProgress || shuttingDown) {
    return;
  }

  /*
   * If unlock has not happened yet,
   * keep checking the ledger.
   */
  if (!unlockInitiated) {
    const ledger = await getLedger();

    const json = codecToJson(ledger);

    const locked =
      json?.locked !== undefined && json?.locked !== null
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

  if (!status.matured) {
    return;
  }

  info("Unlocking chunk(s) matured", {
    maturedChunks: status.maturedChunks.map(describeChunk),
  });

  await phase5Withdraw();
}

/* -------------------------------------------------------------------------- */
/* Phase 4                                                                     */
/* -------------------------------------------------------------------------- */

async function phase4CooldownWatcher() {
  if (unsubscribeHeads) {
    try {
      unsubscribeHeads();
    } catch {}

    unsubscribeHeads = null;
  }

  info("PHASE 4 START: monitoring unlocking chunks");

  unsubscribeHeads = await api.rpc.chain.subscribeFinalizedHeads(
    async (header) => {
      if (cooldownProcessing || shuttingDown) {
        return;
      }

      cooldownProcessing = true;

      try {
        const finalizedBlock = toBigInt(header.number);

        await processCooldown(finalizedBlock);
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

  /*
   * Process immediately instead
   * of waiting for the next block.
   */
  try {
    const currentBlock = await getCurrentFinalizedBlock();

    await processCooldown(currentBlock);
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
  if (reconnecting || shuttingDown) {
    return;
  }

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
  info("================================================");

  info("ASTAR NATIVE RUNTIME-2400 UNSTAKE / AUTO-SWEEP BOT");

  info("================================================");

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

  /*
   * Start watchers BEFORE phase processing.
   *
   * This means that even if an initial operation
   * fails, the bot is already alive and can react
   * to later balance/block changes.
   */
  await startBalanceWatcher();

  await phase4CooldownWatcher();

  /*
   * Initial dApp processing.
   */
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

  info(
    "Bot is now monitoring the ASTR account and dApp staking unlocking period",
  );
}

/* -------------------------------------------------------------------------- */
/* Shutdown                                                                   */
/* -------------------------------------------------------------------------- */

async function shutdown(signal) {
  if (shuttingDown) {
    return;
  }

  shuttingDown = true;

  info(`Received ${signal}; shutting down`);

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
