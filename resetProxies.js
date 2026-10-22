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

  // 0.01 ASTR additional reserve.
  safetyMargin: 10n ** 16n,

  // The requested tip for each removal attempt.
  removalTip: ASTR,

  maxRemovalAttempts: 3,
  retryDelayMs: 1500,

  confirmed: process.env.CONFIRM_PROXY_RESET === "YES",
};

// ------------------------------------------------------------
// Formatting and account helpers
// ------------------------------------------------------------

function astr(value) {
  const amount = BigInt(value);
  const whole = amount / ASTR;
  const fraction = (amount % ASTR).toString().padStart(18, "0");

  return `${whole}.${fraction.slice(0, 8)} ASTR`;
}

function toBigInt(value) {
  return BigInt(value.toString());
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
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

async function getAccount(api, address) {
  return api.query.system.account(address);
}

async function getFee(api, tx, signer) {
  const info = await tx.paymentInfo(signer);
  return toBigInt(info.partialFee);
}

async function getProxies(api, address) {
  const [entries] = await api.query.proxy.proxies(address);
  return entries;
}

// ------------------------------------------------------------
// Transaction submission helper
// ------------------------------------------------------------

function submitAndWait(api, tx, signer, label, options = {}) {
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

    tx.signAndSend(signer, options, (result) => {
      const { status, dispatchError, txHash } = result;

      if (dispatchError) {
        finish(
          new Error(
            `${label} failed: ${decodeDispatchError(api, dispatchError)}`,
          ),
        );
        return;
      }

      if (status.isInBlock) {
        console.log(`${label}: included in ${status.asInBlock.toString()}`);
        console.log(`${label} hash: ${txHash.toString()}`);
      }

      if (status.isFinalized) {
        console.log(`${label}: finalized in ${status.asFinalized.toString()}`);

        finish(null, {
          blockHash: status.asFinalized.toString(),
          txHash: txHash.toString(),
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

        if (settled) {
          Promise.resolve(unsubscribe()).catch(() => {});
        }
      })
      .catch(finish);
  });
}

// ------------------------------------------------------------
// Sign a removal transaction before sponsor funding.
// The signer nonce is not changed by a transfer to this account.
// ------------------------------------------------------------

async function prepareRemoval(api, signer) {
  const tx = api.tx.proxy.removeProxies();

  const nonce = await api.rpc.system.accountNextIndex(signer.address);

  await tx.signAsync(signer, {
    nonce: nonce.toString(),
    tip: CONFIG.removalTip.toString(),
  });

  console.log("Prepared removal extrinsic.");
  console.log("Prepared nonce:", nonce.toString());
  console.log("Removal tip:", astr(CONFIG.removalTip));

  return tx;
}

// ------------------------------------------------------------
// Submit a previously signed extrinsic.
// Resolves only when finalized.
// ------------------------------------------------------------

function submitPreparedRemoval(api, signedTx, attempt) {
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

    signedTx
      .send((result) => {
        const { status, dispatchError, txHash } = result;

        if (dispatchError) {
          finish(
            new Error(
              `Removal attempt ${attempt} failed: ` +
                decodeDispatchError(api, dispatchError),
            ),
          );
          return;
        }

        if (status.isInBlock) {
          console.log(
            `Removal attempt ${attempt} included in ` +
              `${status.asInBlock.toString()}`,
          );
          console.log("Removal hash:", txHash.toString());
        }

        if (status.isFinalized) {
          console.log(
            `Removal attempt ${attempt} finalized in ` +
              `${status.asFinalized.toString()}`,
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
            new Error(`Removal attempt ${attempt} status: ${status.type}`),
          );
        }
      })
      .then((unsub) => {
        unsubscribe = unsub;

        if (settled) {
          Promise.resolve(unsubscribe()).catch(() => {});
        }
      })
      .catch(finish);
  });
}

// ------------------------------------------------------------
// Controlled removal retries.
//
// Each retry checks on-chain state and uses a fresh nonce.
// Never broadcast multiple competing copies blindly.
// ------------------------------------------------------------

async function removeProxiesWithRetries(api, signer, preparedRemoval = null) {
  for (let attempt = 1; attempt <= CONFIG.maxRemovalAttempts; attempt++) {
    const currentProxies = await getProxies(api, signer.address);

    if (currentProxies.length === 0) {
      console.log("Verified: no proxies remain.");
      return true;
    }

    console.log(`\nRemoval attempt ${attempt}/${CONFIG.maxRemovalAttempts}`);

    const tx = api.tx.proxy.removeProxies();

    const account = await getAccount(api, signer.address);
    const free = toBigInt(account.data.free);
    const frozen = toBigInt(account.data.frozen);
    const transferable = getTransferable(account);

    const fee = await getFee(api, tx, signer);
    const required = fee + CONFIG.removalTip + CONFIG.safetyMargin;

    console.log("Signer free:", astr(free));
    console.log("Signer frozen:", astr(frozen));
    console.log("Signer transferable:", astr(transferable));
    console.log("Estimated removal fee:", astr(fee));
    console.log("Removal tip:", astr(CONFIG.removalTip));
    console.log("Required fee reserve:", astr(required));

    if (transferable < required) {
      throw new Error(
        "Insufficient transferable ASTR for removal fee, tip, " +
          "and safety reserve. The active proxy may have swept " +
          "the incoming funding.",
      );
    }

    let signedTx;

    if (attempt === 1 && preparedRemoval) {
      signedTx = preparedRemoval;
    } else {
      const nonce = await api.rpc.system.accountNextIndex(signer.address);

      await tx.signAsync(signer, {
        nonce: nonce.toString(),
        tip: CONFIG.removalTip.toString(),
      });
    }

    // The first attempt can use a prepared extrinsic.
    // Subsequent attempts are signed with a fresh nonce.
    if (attempt === 1 && preparedRemoval) {
      try {
        await submitPreparedRemoval(api, signedTx, attempt);
      } catch (error) {
        console.error(error.message);
        if (attempt === CONFIG.maxRemovalAttempts) {
          throw error;
        }

        // Check chain state before retrying.
        const [remaining] = await api.query.proxy.proxies(signer.address);

        if (remaining.length === 0) return true;

        await sleep(CONFIG.retryDelayMs);
        continue;
      }
    } else {
      // Recreate the signed transaction using the nonce obtained
      // above. This avoids reusing an old signature on a retry.
      const nonce = await api.rpc.system.accountNextIndex(signer.address);

      await tx.signAsync(signer, {
        nonce: nonce.toString(),
        tip: CONFIG.removalTip.toString(),
      });

      try {
        await submitPreparedRemoval(api, tx, attempt);
      } catch (error) {
        console.error(error.message);

        const [remaining] = await api.query.proxy.proxies(signer.address);

        if (remaining.length === 0) return true;

        if (attempt === CONFIG.maxRemovalAttempts) {
          throw error;
        }

        await sleep(CONFIG.retryDelayMs);
        continue;
      }
    }

    const [remaining] = await api.query.proxy.proxies(signer.address);

    if (remaining.length === 0) {
      console.log("SUCCESS: all proxies removed.");
      return true;
    }

    console.warn("The transaction finalized, but proxy entries remain.");

    if (attempt < CONFIG.maxRemovalAttempts) {
      await sleep(CONFIG.retryDelayMs);
    }
  }

  return false;
}

// ------------------------------------------------------------
// Submit funding, then trigger removal at InBlock rather than
// waiting for funding finality first.
//
// This reduces delay but does not guarantee transaction ordering.
// ------------------------------------------------------------

async function fundAndRemoveImmediately(
  api,
  signer,
  sponsor,
  fundingAmount,
  preparedRemoval,
) {
  const fundingTx = api.tx.balances.transferKeepAlive(
    signer.address,
    fundingAmount.toString(),
  );

  const sponsorAccount = await getAccount(api, sponsor.address);
  const sponsorTransferable = getTransferable(sponsorAccount);
  const sponsorFee = await getFee(api, fundingTx, sponsor);

  if (sponsorTransferable < fundingAmount + sponsorFee) {
    throw new Error(
      "Sponsor lacks transferable ASTR for funding plus its fee.",
    );
  }

  console.log("\nSubmitting sponsor funding.");
  console.log("Funding amount:", astr(fundingAmount));
  console.log("Sponsor fee estimate:", astr(sponsorFee));

  return new Promise((resolve, reject) => {
    let fundingUnsubscribe;
    let settled = false;
    let removalStarted = false;

    const finish = (error, result) => {
      if (settled) return;
      settled = true;

      if (fundingUnsubscribe) {
        Promise.resolve(fundingUnsubscribe()).catch(() => {});
      }

      if (error) reject(error);
      else resolve(result);
    };

    fundingTx
      .signAndSend(sponsor, (result) => {
        const { status, dispatchError, txHash } = result;

        if (dispatchError) {
          finish(
            new Error(
              "Sponsor funding failed: " +
                decodeDispatchError(api, dispatchError),
            ),
          );
          return;
        }

        if (status.isInBlock && !removalStarted) {
          removalStarted = true;

          console.log(
            "Funding included in block:",
            status.asInBlock.toString(),
          );
          console.log("Funding transaction:", txHash.toString());
          console.log("Immediately submitting the prepared removal extrinsic.");

          // Do not await funding finality before attempting removal.
          removeProxiesWithRetries(api, signer, preparedRemoval)
            .then((removed) => {
              if (!removed) {
                finish(
                  new Error("Could not verify proxy removal after retries."),
                );
                return;
              }

              finish(null, true);
            })
            .catch(finish);
        }

        if (
          !removalStarted &&
          (status.isDropped ||
            status.isInvalid ||
            status.isUsurped ||
            status.isRetracted ||
            status.isFinalityTimeout)
        ) {
          finish(
            new Error(`Sponsor funding transaction status: ${status.type}`),
          );
        }
      })
      .then((unsub) => {
        fundingUnsubscribe = unsub;

        if (settled) {
          Promise.resolve(fundingUnsubscribe()).catch(() => {});
        }
      })
      .catch(finish);
  });
}

// ------------------------------------------------------------
// Main
// ------------------------------------------------------------

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
    throw new Error('PROXY_TYPE must be "Balances" or "Any".');
  }

  if (!Number.isSafeInteger(CONFIG.proxyDelay) || CONFIG.proxyDelay < 0) {
    throw new Error("PROXY_DELAY must be a non-negative integer.");
  }

  if (!CONFIG.confirmed) {
    throw new Error(
      "No transactions sent. Set CONFIRM_PROXY_RESET=YES " +
        "after verifying the signer and replacement proxy.",
    );
  }

  await cryptoWaitReady();

  const keyring = new Keyring({
    type: "sr25519",
    ss58Format: 5,
  });

  const signer = keyring.addFromMnemonic(CONFIG.signerMnemonic);

  const sponsor = keyring.addFromMnemonic(CONFIG.sponsorMnemonic);

  const newProxy = normalizeAddress(CONFIG.newProxyAddress);

  if (signer.address === sponsor.address) {
    throw new Error("Sponsor and signer must be different wallets.");
  }

  if (signer.address === newProxy) {
    throw new Error("Replacement proxy must differ from the signer wallet.");
  }

  console.log("==============================================");
  console.log(" ASTAR NATIVE PROXY RECOVERY");
  console.log("==============================================");
  console.log("Main wallet:", signer.address);
  console.log("Sponsor wallet:", sponsor.address);
  console.log("Replacement proxy:", newProxy);
  console.log("Proxy type:", CONFIG.proxyType);
  console.log("Proxy delay:", CONFIG.proxyDelay);
  console.log("Removal tip:", astr(CONFIG.removalTip));
  console.log("Maximum removal attempts:", CONFIG.maxRemovalAttempts);

  const provider = new WsProvider(CONFIG.rpc);
  const api = await ApiPromise.create({ provider });

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
      !api.tx.proxy?.removeProxies ||
      !api.tx.proxy?.addProxy ||
      !api.query.proxy?.proxies
    ) {
      throw new Error(
        "Required proxy calls or storage queries are unavailable.",
      );
    }

    if (!api.tx.balances?.transferKeepAlive) {
      throw new Error("balances.transferKeepAlive is unavailable.");
    }

    // Validate the proxy type against the runtime registry.
    api.registry.createType("ProxyType", CONFIG.proxyType);

    const existingProxies = await getProxies(api, signer.address);

    console.log("\nExisting proxies:");
    console.dir(existingProxies.toJSON(), { depth: null });

    if (existingProxies.length === 0) {
      console.log("No existing proxies found.");
    }

    const removeTx = api.tx.proxy.removeProxies();
    const addTx = api.tx.proxy.addProxy(
      newProxy,
      CONFIG.proxyType,
      CONFIG.proxyDelay,
    );

    const removeFee = await getFee(api, removeTx, signer);
    const addFee = await getFee(api, addTx, signer);

    const depositBase = api.consts.proxy?.proxyDepositBase;
    const depositFactor = api.consts.proxy?.proxyDepositFactor;

    if (!depositBase || !depositFactor) {
      throw new Error("Cannot read proxy deposit constants from this runtime.");
    }

    const proxyDeposit = toBigInt(depositBase) + toBigInt(depositFactor);

    const signerAccount = await getAccount(api, signer.address);
    const free = toBigInt(signerAccount.data.free);
    const frozen = toBigInt(signerAccount.data.frozen);
    const transferable = getTransferable(signerAccount);

    // Include the tip in the funding budget.
    const requiredHeadroom =
      removeFee +
      CONFIG.removalTip +
      addFee +
      proxyDeposit +
      CONFIG.safetyMargin;

    const desiredFree = frozen + requiredHeadroom;
    const fundingAmount = desiredFree > free ? desiredFree - free : 0n;

    console.log("\n--- Funding estimate ---");
    console.log("Signer free:", astr(free));
    console.log("Signer frozen:", astr(frozen));
    console.log("Signer transferable:", astr(transferable));
    console.log("Removal fee estimate:", astr(removeFee));
    console.log("Removal tip:", astr(CONFIG.removalTip));
    console.log("Add-proxy fee estimate:", astr(addFee));
    console.log("Replacement proxy deposit estimate:", astr(proxyDeposit));
    console.log("Required headroom:", astr(requiredHeadroom));
    console.log("Sponsor funding:", astr(fundingAmount));

    if (existingProxies.length === 0) {
      console.log("Skipping removal: no proxies need to be removed.");
    } else if (fundingAmount > 0n) {
      // Prepare before the top-up to reduce delay after inclusion.
      const preparedRemoval = await prepareRemoval(api, signer);

      await fundAndRemoveImmediately(
        api,
        signer,
        sponsor,
        fundingAmount,
        preparedRemoval,
      );
    } else {
      console.log("No sponsor funding required.");

      const removed = await removeProxiesWithRetries(api, signer);

      if (!removed) {
        throw new Error("Proxy removal could not be verified.");
      }
    }

    // Verify removal before adding the replacement.
    const afterRemoval = await getProxies(api, signer.address);

    if (afterRemoval.length !== 0) {
      throw new Error(
        "Existing proxies remain. Stopping before adding a replacement.",
      );
    }

    console.log("\nVerified: no existing proxies remain.");

    // Recheck available balance and fee budget before adding.
    const beforeAdd = await getAccount(api, signer.address);
    const addTransferable = getTransferable(beforeAdd);
    const addRequired = addFee + proxyDeposit + CONFIG.safetyMargin;

    console.log(
      "Balance available before adding proxy:",
      astr(addTransferable),
    );
    console.log("Estimated add-proxy budget:", astr(addRequired));

    if (addTransferable < addRequired) {
      throw new Error(
        "Old proxies were removed, but insufficient transferable ASTR " +
          "remains to add the replacement. Fund the wallet only after " +
          "considering the security implications.",
      );
    }

    await submitAndWait(api, addTx, signer, "Add replacement proxy");

    const finalProxies = await getProxies(api, signer.address);

    console.log("\nFinal proxy configuration:");
    console.dir(finalProxies.toJSON(), { depth: null });

    const found = finalProxies.some((entry) => {
      try {
        return (
          normalizeAddress(entry.delegate.toString()) === newProxy &&
          entry.proxyType.toString() === CONFIG.proxyType &&
          Number(entry.delay.toString()) === CONFIG.proxyDelay
        );
      } catch {
        return false;
      }
    });

    if (!found) {
      throw new Error(
        "Replacement proxy was not found in final on-chain verification.",
      );
    }

    console.log("\nSUCCESS: replacement proxy verified on-chain.");
  } finally {
    await api.disconnect();
  }
}

main().catch((error) => {
  console.error("\nERROR:", error.message || error);
  process.exitCode = 1;
});
