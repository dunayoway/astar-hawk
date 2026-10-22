"use strict";

require("dotenv").config();

const { ApiPromise, WsProvider, Keyring } = require("@polkadot/api");
const { cryptoWaitReady, decodeAddress } = require("@polkadot/util-crypto");

const ASTR = 10n ** 18n;
const PROXY_TRANSFER_TIP = 15n * 10n ** 17n; // 1.5 ASTR
const CONFIG = {
  rpc: process.env.ASTAR_WSS || "wss://rpc.astar.network",
  proxyMnemonic: process.env.SPONSOR_MNEMONIC,
  mainAddress: process.env.MAIN_WALLET_ADDRESS,
  vaultAddress: process.env.VAULT_ADDRESS,
  expectedSpecVersion: 2500,
  // Wait briefly for related balance updates to settle.
  debounceMs: 1200,
  // Keep the account alive by using transferAll(..., true).
  // Keep a small fee reserve in the proxy signer wallet.
  proxyFeeSafetyMargin: 10n ** 16n, // 0.01 ASTR
};

function toBigInt(value) {
  return BigInt(value.toString());
}

function astr(value) {
  const amount = BigInt(value);
  const whole = amount / ASTR;
  const fraction = (amount % ASTR).toString().padStart(18, "0");
  return `${whole}.${fraction.slice(0, 8)} ASTR`;
}

function normalizeAddress(address) {
  return new Keyring({
    type: "sr25519",
    ss58Format: 5,
  }).encodeAddress(decodeAddress(address));
}

function getTransferable(account) {
  const free = toBigInt(account.data.free);
  const frozen = toBigInt(account.data.frozen);
  return free > frozen ? free - frozen : 0n;
}

function decodeDispatchError(api, dispatchError) {
  if (!dispatchError) return "Unknown dispatch error";
  if (dispatchError.isModule) {
    const decoded = api.registry.findMetaError(dispatchError.asModule);
    return `${decoded.section}.${decoded.name}: ` + decoded.docs.join(" ");
  }
  return dispatchError.toString();
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Submit one proxy transfer with the configured tip.
 * Resolves only after finalization and rejects on dispatch errors.
 */
function submitProxyTransfer(api, tx, proxySigner) {
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
    tx.signAndSend(
      proxySigner,
      {
        tip: PROXY_TRANSFER_TIP.toString(),
      },
      (result) => {
        const { status, dispatchError, txHash } = result;
        if (dispatchError) {
          finish(
            new Error(
              `Proxy transfer failed: ${decodeDispatchError(
                api,
                dispatchError,
              )}`,
            ),
          );
          return;
        }
        if (status.isInBlock) {
          console.log(
            "Proxy transfer included in block:",
            status.asInBlock.toString(),
          );
          console.log("Transaction hash:", txHash.toString());
          console.log("Tip:", astr(PROXY_TRANSFER_TIP));
        }
        if (status.isFinalized) {
          console.log(
            "Proxy transfer finalized in:",
            status.asFinalized.toString(),
          );
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
          finish(
            new Error(
              `Proxy transfer status: ${status.type}. ` +
                "Check on-chain state before retrying.",
            ),
          );
        }
      },
    )
      .then((unsub) => {
        unsubscribe = unsub;
        if (settled) {
          Promise.resolve(unsubscribe()).catch(() => {});
        }
      })
      .catch(finish);
  });
}

async function startProxySweep() {
  if (!CONFIG.proxyMnemonic || !CONFIG.mainAddress || !CONFIG.vaultAddress) {
    throw new Error(
      "Missing .env settings: EXEC_MNEMONIC, " +
        "MAIN_WALLET_ADDRESS, and VAULT_ADDRESS.",
    );
  }
  await cryptoWaitReady();
  const keyring = new Keyring({
    type: "sr25519",
    ss58Format: 5,
  });
  const proxySigner = keyring.addFromMnemonic(CONFIG.proxyMnemonic);
  const mainAddress = normalizeAddress(CONFIG.mainAddress);
  const vaultAddress = normalizeAddress(CONFIG.vaultAddress);
  if (proxySigner.address === mainAddress) {
    throw new Error("The proxy signer must differ from the main wallet.");
  }
  if (vaultAddress === mainAddress) {
    throw new Error("The vault address must differ from the main wallet.");
  }
  if (vaultAddress === proxySigner.address) {
    throw new Error("The vault address must differ from the proxy signer.");
  }

  console.log("==============================================");
  console.log(" ASTAR NATIVE AUTOMATIC PROXY SWEEP");
  console.log("==============================================");
  console.log("Proxy signer:", proxySigner.address);
  console.log("Main wallet:", mainAddress);
  console.log("Vault:", vaultAddress);
  console.log("Proxy transaction tip:", astr(PROXY_TRANSFER_TIP));

  const provider = new WsProvider(CONFIG.rpc);
  const api = await ApiPromise.create({ provider });
  let unsubscribeAccount = null;
  let stopped = false;
  let busy = false;
  let timer = null;
  let lastObservedFree = null;
  let pendingIncrease = false;
  let shuttingDown = false;

  async function shutdown() {
    if (shuttingDown) return;
    shuttingDown = true;
    stopped = true;
    if (timer) {
      clearTimeout(timer);
      timer = null;
    }
    if (unsubscribeAccount) {
      try {
        await unsubscribeAccount();
      } catch (error) {
        console.error("Subscription cleanup:", error.message);
      }
      unsubscribeAccount = null;
    }
    await api.disconnect();
  }

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
    if (
      !api.tx.proxy?.proxy ||
      !api.tx.balances?.transferAll ||
      !api.query.proxy?.proxies
    ) {
      throw new Error("Required proxy or balances calls are unavailable.");
    }
    // Confirm that this signer is an authorized, zero-delay
    // Balances proxy of the main wallet.
    const [proxyEntries] = await api.query.proxy.proxies(mainAddress);

    console.log("\nConfigured proxies:");
    console.dir(proxyEntries.toJSON(), { depth: null });

    const authorized = proxyEntries.some((entry) => {
      try {
        return (
          normalizeAddress(entry.delegate.toString()) === proxySigner.address &&
          entry.proxyType.toString() === "Balances" &&
          Number(entry.delay.toString()) === 0
        );
      } catch {
        return false;
      }
    });

    if (!authorized) {
      throw new Error(
        "The proxy signer is not configured as a zero-delay " +
          "Balances proxy for the main wallet. Verify on-chain permissions.",
      );
    }

    async function performSweep() {
      if (stopped || busy || !pendingIncrease) return;
      busy = true;
      pendingIncrease = false;
      try {
        // Re-read the main account immediately before constructing
        // the transaction.
        const mainAccount = await api.query.system.account(mainAddress);
        const currentFree = toBigInt(mainAccount.data.free);
        const transferable = getTransferable(mainAccount);

        console.log("\n--- Sweep check ---");
        console.log("Main free balance:", astr(currentFree));
        console.log("Main transferable balance:", astr(transferable));

        if (transferable === 0n) {
          console.log("Nothing transferable. Skipping sweep.");
          lastObservedFree = currentFree;
          return;
        }
        // Estimate the outer proxy call fee. The 1.5 ASTR tip is
        // budgeted separately below.
        const innerCall = api.tx.balances.transferAll(
          vaultAddress,
          true, // Keep the main account alive.
        );
        const outerCall = api.tx.proxy.proxy(
          mainAddress,
          "Balances",
          innerCall,
        );
        const feeInfo = await outerCall.paymentInfo(proxySigner);
        const estimatedFee = toBigInt(feeInfo.partialFee);
        const proxyAccount = await api.query.system.account(
          proxySigner.address,
        );
        const proxyTransferable = getTransferable(proxyAccount);
        const requiredProxyBalance =
          estimatedFee + PROXY_TRANSFER_TIP + CONFIG.proxyFeeSafetyMargin;

        console.log("Estimated outer transaction fee:", astr(estimatedFee));
        console.log("Transaction tip:", astr(PROXY_TRANSFER_TIP));
        console.log("Proxy signer transferable:", astr(proxyTransferable));
        console.log(
          "Estimated required proxy balance:",
          astr(requiredProxyBalance),
        );

        if (proxyTransferable < requiredProxyBalance) {
          console.error(
            "Proxy signer does not have enough transferable ASTR " +
              "for the estimated fee, tip, and safety margin. " +
              "No sweep submitted.",
          );
          lastObservedFree = currentFree;
          return;
        }

        console.log("Submitting proxy sweep...");

        const result = await submitProxyTransfer(api, outerCall, proxySigner);

        console.log("Sweep finalized:", result.txHash);

        // Re-read balances after finalization. Do not assume that
        // a successful extrinsic transferred the expected amount.
        const [updatedMain, updatedVault] = await Promise.all([
          api.query.system.account(mainAddress),
          api.query.system.account(vaultAddress),
        ]);

        const updatedFree = toBigInt(updatedMain.data.free);
        const vaultFree = toBigInt(updatedVault.data.free);

        console.log("Main balance after sweep:", astr(updatedFree));
        console.log("Vault free balance:", astr(vaultFree));

        lastObservedFree = updatedFree;

        // If another deposit arrived while this sweep was in flight,
        // queue another check.
        if (updatedFree > currentFree) {
          pendingIncrease = true;
        }
      } catch (error) {
        console.error("Sweep error:", error.message || error);

        // Refresh the baseline rather than repeatedly submitting
        // a transaction after an uncertain outcome.
        try {
          const account = await api.query.system.account(mainAddress);
          lastObservedFree = toBigInt(account.data.free);
        } catch (refreshError) {
          console.error(
            "Could not refresh main balance:",
            refreshError.message,
          );
        }
      } finally {
        busy = false;

        if (pendingIncrease && !stopped) {
          scheduleSweep();
        }
      }
    }

    function scheduleSweep() {
      if (stopped) return;
      if (timer) clearTimeout(timer);
      timer = setTimeout(() => {
        timer = null;
        performSweep().catch((error) => {
          console.error("Sweep loop error:", error.message || error);
        });
      }, CONFIG.debounceMs);
    }

    console.log("\nWatching for main-wallet balance increases...");

    unsubscribeAccount = await api.query.system.account(
      mainAddress,
      (account) => {
        const observedFree = toBigInt(account.data.free);
        if (lastObservedFree === null) {
          lastObservedFree = observedFree;
          console.log("Initial main-wallet free balance:", astr(observedFree));
          return;
        }
        if (observedFree !== lastObservedFree) {
          console.log(
            "Main-wallet balance changed:",
            astr(lastObservedFree),
            "->",
            astr(observedFree),
          );
          pendingIncrease = true;
          scheduleSweep();
        }
        // Keep the latest balance for the next comparison.
        lastObservedFree = observedFree;
      },
    );
    const handleSignal = async (signal) => {
      console.log(`\n${signal} received. Shutting down...`);

      try {
        await shutdown();
      } catch (error) {
        console.error("Shutdown error:", error.message || error);
      }
      process.exit(0);
    };
    process.once("SIGINT", () => handleSignal("SIGINT"));
    process.once("SIGTERM", () => handleSignal("SIGTERM"));
    // Keep the process running while the account subscription is active.
    await new Promise(() => {});
  } finally {
    await shutdown();
  }
}

// main().catch((error) => {
//   console.error("\nFATAL:", error.message || error);
//   process.exitCode = 1;
// });

module.exports = { startProxySweep };
