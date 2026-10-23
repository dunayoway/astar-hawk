"use strict";

require("dotenv").config();

const { ApiPromise, WsProvider, Keyring } = require("@polkadot/api");
const { cryptoWaitReady, decodeAddress } = require("@polkadot/util-crypto");

const ASTR = 10n ** 18n;

const CONFIG = {
  rpc: process.env.ASTAR_WSS || "wss://rpc.astar.network",

  signerMnemonic: process.env.EXEC_MNEMONIC,
  sponsorMnemonic: process.env.SPONSOR_MNEMONIC,
  newProxyAddress: process.env.NEW_PROXY_ADDRESS,

  proxyType: process.env.PROXY_TYPE || "Balances",
  proxyDelay: Number(process.env.PROXY_DELAY || 0),

  expectedSpecVersion: 2500,

  // 0.01 ASTR reserve above estimated costs.
  safetyMargin: 10n ** 16n,

  pollIntervalMs: Number(process.env.POLL_INTERVAL_MS || 30_000),
  retryDelayMs: Number(process.env.RETRY_DELAY_MS || 5_000),

  confirmed: process.env.CONFIRM_PROXY_RESET === "YES",
};

function log(...args) {
  console.log(new Date().toISOString(), ...args);
}

function astr(value) {
  const n = BigInt(value);
  const whole = n / ASTR;
  const fraction = (n % ASTR).toString().padStart(18, "0");
  return `${whole}.${fraction.slice(0, 8)} ASTR`;
}

function toBigInt(value) {
  return BigInt(value.toString());
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function normalizeAddress(address) {
  return new Keyring({ type: "sr25519", ss58Format: 5 }).encodeAddress(
    decodeAddress(address),
  );
}

function getTransferable(account) {
  const free = toBigInt(account.data.free);
  const frozen = toBigInt(account.data.frozen);
  return free > frozen ? free - frozen : 0n;
}

function decodeDispatchError(api, error) {
  if (!error) return "Unknown dispatch error";

  if (error.isModule) {
    const decoded = api.registry.findMetaError(error.asModule);
    return `${decoded.section}.${decoded.name}: ${decoded.docs.join(" ")}`;
  }

  return error.toString();
}

async function getProxies(api, address) {
  const [entries] = await api.query.proxy.proxies(address);
  return entries;
}

async function getFee(api, tx, signer) {
  const info = await tx.paymentInfo(signer);
  return toBigInt(info.partialFee);
}

function submitAndWait(api, tx, signer, label) {
  return new Promise((resolve, reject) => {
    let unsubscribe;
    let settled = false;

    const finish = (error, result) => {
      if (settled) return;
      settled = true;

      if (unsubscribe) {
        Promise.resolve(unsubscribe()).catch(() => {});
      }

      if (error) reject(error);
      else resolve(result);
    };

    tx.signAndSend(signer, { tip: 0 }, (result) => {
      const { status, dispatchError, txHash } = result;

      if (dispatchError) {
        finish(
          new Error(`${label}: ${decodeDispatchError(api, dispatchError)}`),
        );
        return;
      }

      if (status.isInBlock) {
        log(`${label} included in ${status.asInBlock.toString()}`);
        log(`${label} hash: ${txHash.toString()}`);
      }

      if (status.isFinalized) {
        log(`${label} finalized in ${status.asFinalized.toString()}`);
        finish(null, {
          txHash: txHash.toString(),
          blockHash: status.asFinalized.toString(),
        });
        return;
      }

      if (
        status.isDropped ||
        status.isInvalid ||
        status.isUsurped ||
        status.isRetracted ||
        status.isFinalityTimeout
      ) {
        finish(new Error(`${label}: transaction status ${status.type}`));
      }
    })
      .then((unsub) => {
        unsubscribe = unsub;
        if (settled) Promise.resolve(unsubscribe()).catch(() => {});
      })
      .catch(finish);
  });
}

function isTargetProxy(entry, targetAddress) {
  try {
    return (
      normalizeAddress(entry.delegate.toString()) === targetAddress &&
      entry.proxyType.toString() === CONFIG.proxyType &&
      Number(entry.delay.toString()) === CONFIG.proxyDelay
    );
  } catch {
    return false;
  }
}

async function fundMainWallet(api, signer, sponsor, amount) {
  if (amount <= 0n) return;

  const transfer = api.tx.balances.transferKeepAlive(
    signer.address,
    amount.toString(),
  );

  const sponsorAccount = await api.query.system.account(sponsor.address);
  const sponsorTransferable = getTransferable(sponsorAccount);
  const sponsorFee = await getFee(api, transfer, sponsor);

  if (sponsorTransferable < amount + sponsorFee) {
    throw new Error(
      `Sponsor has ${astr(sponsorTransferable)} transferable, ` +
        `but ${astr(amount + sponsorFee)} is needed for funding and fees.`,
    );
  }

  log("Funding main wallet from sponsor:", astr(amount));
  log("Estimated sponsor fee:", astr(sponsorFee));

  await submitAndWait(api, transfer, sponsor, "Sponsor funding");
}

async function ensureMainWalletFunds(
  api,
  signer,
  sponsor,
  requiredTransferable,
) {
  const account = await api.query.system.account(signer.address);
  const transferable = getTransferable(account);

  if (transferable >= requiredTransferable) {
    log("Main-wallet transferable balance is sufficient:", astr(transferable));
    return;
  }

  // Calculate the top-up needed to reach the required transferable amount.
  const shortfall = requiredTransferable - transferable;

  log("Main-wallet balance is insufficient.");
  log("Current transferable:", astr(transferable));
  log("Required transferable:", astr(requiredTransferable));

  await fundMainWallet(api, signer, sponsor, shortfall);

  const refreshed = await api.query.system.account(signer.address);
  const refreshedTransferable = getTransferable(refreshed);

  if (refreshedTransferable < requiredTransferable) {
    throw new Error(
      `Funding confirmed, but transferable balance is only ` +
        `${astr(refreshedTransferable)}. Another account action may have ` +
        `changed the balance.`,
    );
  }
}

async function reconcileProxy(api, signer, sponsor, targetAddress) {
  const current = await getProxies(api, signer.address);
  const alreadyCorrect =
    current.length === 1 && isTargetProxy(current[0], targetAddress);

  if (alreadyCorrect) {
    log("Proxy configuration is correct. No transaction needed.");
    return;
  }

  log("Proxy configuration differs from target.");
  log("Current proxy entries:", JSON.stringify(current.toJSON()));

  const removeTx = api.tx.proxy.removeProxies();
  const addTx = api.tx.proxy.addProxy(
    targetAddress,
    CONFIG.proxyType,
    CONFIG.proxyDelay,
  );

  const removeFee =
    current.length > 0 ? await getFee(api, removeTx, signer) : 0n;
  const addFee = await getFee(api, addTx, signer);

  const depositBase = api.consts.proxy?.proxyDepositBase;
  const depositFactor = api.consts.proxy?.proxyDepositFactor;

  if (!depositBase || !depositFactor) {
    throw new Error("Could not read proxy deposit constants from the runtime.");
  }

  // One replacement proxy: base deposit + one factor.
  const proxyDeposit = toBigInt(depositBase) + toBigInt(depositFactor);

  const required = removeFee + addFee + proxyDeposit + CONFIG.safetyMargin;

  log("Estimated removal fee:", astr(removeFee));
  log("Estimated add-proxy fee:", astr(addFee));
  log("Proxy deposit estimate:", astr(proxyDeposit));
  log("Safety reserve:", astr(CONFIG.safetyMargin));
  log("Required transferable balance:", astr(required));

  // If a proxy currently exists, budget for both operations before resetting.
  await ensureMainWalletFunds(api, signer, sponsor, required);

  // Recheck state because the proxy list may have changed during funding.
  const latest = await getProxies(api, signer.address);

  if (latest.length === 1 && isTargetProxy(latest[0], targetAddress)) {
    log("Target configuration appeared during funding. No reset needed.");
    return;
  }

  if (latest.length > 0) {
    log("Removing existing proxies...");
    await submitAndWait(
      api,
      api.tx.proxy.removeProxies(),
      signer,
      "Remove all proxies",
    );

    const remaining = await getProxies(api, signer.address);

    if (remaining.length !== 0) {
      throw new Error(
        "Proxy removal finalized, but proxy entries remain. Will retry.",
      );
    }

    log("Verified: no proxies remain.");
  }

  // Recalculate the remaining costs after removal.
  const freshAddTx = api.tx.proxy.addProxy(
    targetAddress,
    CONFIG.proxyType,
    CONFIG.proxyDelay,
  );

  const freshAddFee = await getFee(api, freshAddTx, signer);
  const addRequired = freshAddFee + proxyDeposit + CONFIG.safetyMargin;

  await ensureMainWalletFunds(api, signer, sponsor, addRequired);

  log("Adding replacement proxy...");
  await submitAndWait(api, freshAddTx, signer, "Add replacement proxy");

  const finalProxies = await getProxies(api, signer.address);

  if (
    finalProxies.length !== 1 ||
    !isTargetProxy(finalProxies[0], targetAddress)
  ) {
    throw new Error(
      "Replacement proxy verification failed. Will retry reconciliation.",
    );
  }

  log("SUCCESS: target proxy verified on-chain.");
}

async function startProxyMonitor() {
  if (!CONFIG.signerMnemonic) {
    throw new Error("Missing EXEC_MNEMONIC in .env");
  }
  if (!CONFIG.sponsorMnemonic) {
    throw new Error("Missing SPONSOR_MNEMONIC in .env");
  }
  if (!CONFIG.newProxyAddress) {
    throw new Error("Missing NEW_PROXY_ADDRESS in .env");
  }
  if (!CONFIG.confirmed) {
    throw new Error(
      "Set CONFIRM_PROXY_RESET=YES after verifying the wallet and target.",
    );
  }
  if (!["Balances", "Any"].includes(CONFIG.proxyType)) {
    throw new Error('PROXY_TYPE must be "Balances" or "Any".');
  }
  if (!Number.isSafeInteger(CONFIG.proxyDelay) || CONFIG.proxyDelay < 0) {
    throw new Error("PROXY_DELAY must be a non-negative integer.");
  }
  if (
    !Number.isSafeInteger(CONFIG.pollIntervalMs) ||
    CONFIG.pollIntervalMs < 1000
  ) {
    throw new Error("POLL_INTERVAL_MS must be at least 1000.");
  }

  await cryptoWaitReady();

  const keyring = new Keyring({ type: "sr25519", ss58Format: 5 });
  const signer = keyring.addFromMnemonic(CONFIG.signerMnemonic);
  const sponsor = keyring.addFromMnemonic(CONFIG.sponsorMnemonic);
  const targetAddress = normalizeAddress(CONFIG.newProxyAddress);

  if (signer.address === sponsor.address) {
    throw new Error("Sponsor and main wallet must be different accounts.");
  }
  if (signer.address === targetAddress) {
    throw new Error("Target proxy must differ from the main wallet.");
  }

  const provider = new WsProvider(CONFIG.rpc);
  const api = await ApiPromise.create({ provider });

  let stopping = false;

  const stop = () => {
    stopping = true;
    log("Shutdown requested. Stopping after the current operation.");
  };

  process.on("SIGINT", stop);
  process.on("SIGTERM", stop);

  try {
    await api.isReady;

    const specVersion = api.runtimeVersion.specVersion.toNumber();

    log("Connected to Astar.");
    log("Runtime:", specVersion);
    log("Main wallet:", signer.address);
    log("Sponsor wallet:", sponsor.address);
    log("Target proxy:", targetAddress);
    log("Proxy type:", CONFIG.proxyType);
    log("Proxy delay:", CONFIG.proxyDelay);
    log("Polling interval:", CONFIG.pollIntervalMs, "ms");

    if (specVersion !== CONFIG.expectedSpecVersion) {
      throw new Error(
        `Expected runtime ${CONFIG.expectedSpecVersion}, got ${specVersion}.`,
      );
    }

    if (
      !api.tx.proxy?.removeProxies ||
      !api.tx.proxy?.addProxy ||
      !api.query.proxy?.proxies ||
      !api.tx.balances?.transferKeepAlive
    ) {
      throw new Error("Required Astar runtime calls are unavailable.");
    }

    // Validate the runtime's ProxyType enum.
    api.registry.createType("ProxyType", CONFIG.proxyType);

    while (!stopping) {
      try {
        await reconcileProxy(api, signer, sponsor, targetAddress);
      } catch (error) {
        log("Reconciliation error:", error.message || error);
      }

      if (!stopping) {
        await sleep(CONFIG.pollIntervalMs);
      }
    }
  } finally {
    await api.disconnect();
    log("Disconnected.");
  }
}

module.exports = { startProxyMonitor };
