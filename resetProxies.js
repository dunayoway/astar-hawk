"use strict";

require("dotenv").config();

const { ApiPromise, WsProvider, Keyring } = require("@polkadot/api");
const { cryptoWaitReady, decodeAddress } = require("@polkadot/util-crypto");

const CONFIG = {
  rpc: process.env.ASTAR_WSS || "wss://rpc.astar.network",
  signerMnemonic: process.env.EXEC_MNEMONIC,
  sponsorMnemonic: process.env.SPONSOR_MNEMONIC,
  newProxyAddress: process.env.NEW_PROXY_ADDRESS,
  proxyType: process.env.PROXY_TYPE || "Balances",
  proxyDelay: Number(process.env.PROXY_DELAY || 0),
  expectedSpecVersion: 2500,
  safetyMargin: 10n ** 16n, // 0.01 ASTR
  confirmed: process.env.CONFIRM_PROXY_RESET === "YES",
};
const ASTR = 10n ** 18n;

function astr(value) {
  const amount = BigInt(value);
  const whole = amount / ASTR;
  const fraction = (amount % ASTR).toString().padStart(18, "0");
  return `${whole}.${fraction.slice(0, 8)} ASTR`;
}

function toBigInt(value) {
  return BigInt(value.toString());
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

function submitAndWait(api, tx, signer, label) {
  return new Promise((resolve, reject) => {
    let unsubscribe;
    let settled = false;
    const finish = (err, result) => {
      if (settled) return;
      settled = true;
      if (unsubscribe) {
        Promise.resolve(unsubscribe()).catch(() => {});
      }
      if (err) reject(err);
      else resolve(result);
    };
    tx.signAndSend(signer, ({ status, dispatchError }) => {
      if (dispatchError) {
        let message = dispatchError.toString();
        if (dispatchError.isModule) {
          const decoded = api.registry.findMetaError(dispatchError.asModule);
          message =
            `${decoded.section}.${decoded.name}: ` + decoded.docs.join(" ");
        }
        finish(new Error(`${label} failed: ${message}`));
        return;
      }
      if (status.isInBlock) {
        console.log(`${label}: included in ${status.asInBlock.toString()}`);
      }
      if (status.isFinalized) {
        console.log(`${label}: finalized in ${status.asFinalized.toString()}`);
        finish(null, status.asFinalized.toString());
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

async function getFee(api, tx, signer) {
  const info = await tx.paymentInfo(signer);
  return toBigInt(info.partialFee);
}

async function getAccount(api, address) {
  return api.query.system.account(address);
}

async function main() {
  if (!CONFIG.signerMnemonic) {
    throw new Error("Missing EXEC_MNEMONIC in .env");
  }
  if (!CONFIG.sponsorMnemonic) {
    throw new Error("Missing SPONSOR_MNEMONIC in .env");
  }
  if (!CONFIG.newProxyAddress) {
    throw new Error("Missing NEW_PROXY_ADDRESS in .env");
  }
  if (!["Balances", "Any"].includes(CONFIG.proxyType)) {
    throw new Error('PROXY_TYPE must be "Balances" or "Any"');
  }
  if (!Number.isSafeInteger(CONFIG.proxyDelay) || CONFIG.proxyDelay < 0) {
    throw new Error("PROXY_DELAY must be a non-negative integer");
  }
  if (!CONFIG.confirmed) {
    throw new Error(
      "No transactions sent. Set CONFIRM_PROXY_RESET=YES " +
        "after verifying the signer and new proxy address.",
    );
  }
  await cryptoWaitReady();
  const keyring = new Keyring({ type: "sr25519", ss58Format: 5 });
  const signer = keyring.addFromMnemonic(CONFIG.signerMnemonic);
  const sponsor = keyring.addFromMnemonic(CONFIG.sponsorMnemonic);
  const newProxy = normalizeAddress(CONFIG.newProxyAddress);
  if (signer.address === sponsor.address) {
    throw new Error("Sponsor and signer must be different wallets");
  }
  if (signer.address === newProxy) {
    throw new Error("New proxy must differ from the signer wallet");
  }

  console.log("Main wallet:", signer.address);
  console.log("Sponsor wallet:", sponsor.address);
  console.log("New proxy:", newProxy);
  console.log("Proxy type:", CONFIG.proxyType);
  console.log("Delay:", CONFIG.proxyDelay);

  const api = await ApiPromise.create({
    provider: new WsProvider(CONFIG.rpc),
  });
  try {
    await api.isReady;
    const specVersion = api.runtimeVersion.specVersion.toNumber();

    console.log("Connected to Astar. Runtime:", specVersion);

    if (specVersion !== CONFIG.expectedSpecVersion) {
      throw new Error(
        `Expected runtime ${CONFIG.expectedSpecVersion}, ` +
          `received ${specVersion}. Stopping safely.`,
      );
    }
    if (!api.tx.proxy?.removeProxies || !api.tx.proxy?.addProxy) {
      throw new Error("Required proxy calls are unavailable");
    }
    if (!api.query.proxy?.proxies) {
      throw new Error("Proxy storage query is unavailable");
    }
    // Validate the configured proxy type against the runtime registry.
    api.registry.createType("ProxyType", CONFIG.proxyType);
    // Read current proxy configuration.
    const [proxyEntries] = await api.query.proxy.proxies(signer.address);

    console.log("Existing proxies:", proxyEntries.toJSON());

    const removeTx = api.tx.proxy.removeProxies();
    const addTx = api.tx.proxy.addProxy(
      newProxy,
      CONFIG.proxyType,
      CONFIG.proxyDelay,
    );
    // Estimate both transaction fees.
    const removeFee = await getFee(api, removeTx, signer);
    const addFee = await getFee(api, addTx, signer);
    // Estimate the deposit needed for the replacement proxy.
    // If the runtime doesn't expose these constants, stop rather
    // than silently underfunding the addProxy operation.
    const depositBase = api.consts.proxy?.proxyDepositBase;
    const depositFactor = api.consts.proxy?.proxyDepositFactor;
    if (!depositBase || !depositFactor) {
      throw new Error(
        "Cannot read proxy deposit constants from this runtime. " +
          "Inspect api.consts.proxy before proceeding.",
      );
    }
    const proxyDeposit = toBigInt(depositBase) + toBigInt(depositFactor);
    const signerAccount = await getAccount(api, signer.address);
    const free = toBigInt(signerAccount.data.free);
    const frozen = toBigInt(signerAccount.data.frozen);
    const transferable = getTransferable(signerAccount);
    // Reserve enough headroom for both fees, the new proxy deposit,
    // and a safety margin above the frozen threshold.
    const requiredHeadroom =
      removeFee + addFee + proxyDeposit + CONFIG.safetyMargin;
    const desiredFree = frozen + requiredHeadroom;
    const fundingAmount = desiredFree > free ? desiredFree - free : 0n;

    console.log("\n--- Funding estimate ---");
    console.log("Signer free:", astr(free));
    console.log("Signer frozen:", astr(frozen));
    console.log("Signer transferable:", astr(transferable));
    console.log("Removal fee:", astr(removeFee));
    console.log("Add-proxy fee:", astr(addFee));
    console.log("Estimated proxy deposit:", astr(proxyDeposit));
    console.log("Required headroom:", astr(requiredHeadroom));
    console.log("Sponsor funding:", astr(fundingAmount));

    // Fund the signer only if the current balance is insufficient.
    if (fundingAmount > 0n) {
      const sponsorAccount = await getAccount(api, sponsor.address);
      const sponsorTransferable = getTransferable(sponsorAccount);
      const fundingTx = api.tx.balances.transferKeepAlive(
        signer.address,
        fundingAmount.toString(),
      );
      const sponsorFee = await getFee(api, fundingTx, sponsor);
      if (sponsorTransferable < fundingAmount + sponsorFee) {
        throw new Error(
          "Sponsor lacks sufficient transferable ASTR for the " +
            "funding amount plus its own transaction fee.",
        );
      }
      await submitAndWait(api, fundingTx, sponsor, "Sponsor funding");
    } else {
      console.log(
        "Signer has sufficient estimated headroom; no top-up needed.",
      );
    }
    // Re-read balances after funding has finalized.
    const refreshed = await getAccount(api, signer.address);
    const refreshedFree = toBigInt(refreshed.data.free);
    const refreshedFrozen = toBigInt(refreshed.data.frozen);
    const refreshedTransferable = getTransferable(refreshed);

    console.log("\n--- Post-funding check ---");
    console.log("Signer free:", astr(refreshedFree));
    console.log("Signer frozen:", astr(refreshedFrozen));
    console.log("Signer transferable:", astr(refreshedTransferable));

    if (refreshedTransferable < requiredHeadroom) {
      throw new Error(
        "Signer still lacks sufficient transferable balance after " +
          "funding. No proxy-removal transaction was submitted.",
      );
    }
    // Remove all existing proxies.
    await submitAndWait(api, removeTx, signer, "Remove all proxies");
    // Verify removal before adding the replacement.
    const [afterRemoval] = await api.query.proxy.proxies(signer.address);
    if (afterRemoval.length !== 0) {
      throw new Error(
        "Proxy removal finalized, but proxies remain in storage. " +
          "Stopping before adding the replacement.",
      );
    }

    console.log("Verified: no existing proxies remain.");

    // Add the replacement proxy.
    await submitAndWait(api, addTx, signer, "Add replacement proxy");
    // Verify the final on-chain configuration.
    const [finalEntries] = await api.query.proxy.proxies(signer.address);
    const finalProxies = finalEntries.toJSON();

    console.log("\nFinal proxy configuration:");
    console.dir(finalProxies, { depth: null });

    const found = finalEntries.some((entry) => {
      const delegate = entry.delegate?.toString();
      const type = entry.proxyType.toString();
      const delay = Number(entry.delay.toString());
      let normalizedDelegate;
      try {
        normalizedDelegate = normalizeAddress(delegate);
      } catch {
        return false;
      }
      return (
        normalizedDelegate === newProxy &&
        type === CONFIG.proxyType &&
        delay === CONFIG.proxyDelay
      );
    });
    if (!found) {
      throw new Error(
        "The new proxy was not found in final on-chain verification.",
      );
    }

    console.log("\nSUCCESS: replacement proxy verified on-chain.");
  } finally {
    await api.disconnect();
  }
}

main().catch((err) => {
  console.error("\nERROR:", err.message || err);
  process.exitCode = 1;
});
