"use strict";

require("dotenv").config();

const { ApiPromise, WsProvider, Keyring } = require("@polkadot/api");
const { cryptoWaitReady, decodeAddress } = require("@polkadot/util-crypto");

const RPC = process.env.ASTAR_WSS || "wss://rpc.astar.network";
const MNEMONIC = process.env.EXEC_MNEMONIC;
const NEW_PROXY_ADDRESS = process.env.NEW_PROXY_ADDRESS;
const PROXY_TYPE = process.env.PROXY_TYPE || "Balances";
const PROXY_DELAY = Number(process.env.PROXY_DELAY || 0);
const EXPECTED_SPEC_VERSION = 2500;

function validateAddress(address) {
  try {
    decodeAddress(address);
    return true;
  } catch {
    return false;
  }
}

function submitAndWait(tx, signer, label) {
  return new Promise(async (resolve, reject) => {
    let unsubscribe;
    let settled = false;
    const finish = (err, result) => {
      if (settled) return;
      settled = true
      if (unsubscribe) {
        Promise.resolve(unsubscribe()).catch(() => {});
      }
      if (err) reject(err);
      else resolve(result);
    };
    try {
      unsubscribe = await tx.signAndSend(
        signer,
        ({ status, events, dispatchError }) => {
          if (status.isInBlock) {
            console.log(
              `${label}: included in block ${status.asInBlock.toString()}`,
            );
            if (dispatchError) {
              let message = dispatchError.toString();
              if (dispatchError.isModule) {
                const decoded = tx.registry.findMetaError(
                  dispatchError.asModule,
                );
                message = `${decoded.section}.${decoded.name}: ${decoded.docs.join(" ")}`;
              }
              finish(new Error(`${label} failed: ${message}`));
              return;
            }
            const failedEvent = events.find(({ event }) =>
              tx.registry.events.system.ExtrinsicFailed.is(event),
            );
            if (failedEvent) {
              finish(new Error(`${label} emitted ExtrinsicFailed`));
              return;
            }
          }
          if (status.isFinalized) {
            console.log(
              `${label}: finalized in block ${status.asFinalized.toString()}`,
            );
            finish(null, status.asFinalized.toString());
            return;
          }
          if (
            status.isDropped ||
            status.isInvalid ||
            status.isUsurped ||
            status.isRetracted
          ) {
            finish(new Error(`${label} stopped with status ${status.type}`));
          }
        },
      );
    } catch (err) {
      finish(err);
    }
  });
}

async function main() {
  if (!MNEMONIC) {
    throw new Error("Missing EXEC_MNEMONIC in .env");
  }
  if (!NEW_PROXY_ADDRESS || !validateAddress(NEW_PROXY_ADDRESS)) {
    throw new Error("NEW_PROXY_ADDRESS is missing or invalid");
  }
  if (!["Balances", "Any"].includes(PROXY_TYPE)) {
    throw new Error('PROXY_TYPE must be "Balances" or "Any"');
  }
  if (!Number.isSafeInteger(PROXY_DELAY) || PROXY_DELAY < 0) {
    throw new Error("PROXY_DELAY must be a non-negative integer");
  }
  await cryptoWaitReady();
  const keyring = new Keyring({ type: "sr25519", ss58Format: 5 });
  const signer = keyring.addFromMnemonic(MNEMONIC);
  // Ensure the new proxy address is encoded as a valid Astar address.
  const newProxy = keyring.encodeAddress(decodeAddress(NEW_PROXY_ADDRESS));
  if (signer.address === newProxy) {
    throw new Error("The new proxy address must differ from the main wallet");
  }

  console.log("Main wallet:", signer.address);
  console.log("New proxy:", newProxy);
  console.log("Proxy type:", PROXY_TYPE);
  console.log("Delay:", PROXY_DELAY);

  const api = await ApiPromise.create({
    provider: new WsProvider(RPC),
  });
  try {
    await api.isReady;
    const specVersion = api.runtimeVersion.specVersion.toNumber();

    console.log("Connected to Astar. Runtime:", specVersion);

    if (specVersion !== EXPECTED_SPEC_VERSION) {
      throw new Error(
        `Expected runtime ${EXPECTED_SPEC_VERSION}, got ${specVersion}. ` +
          "Check the runtime before proceeding.",
      );
    }
    if (!api.tx.proxy?.removeProxies || !api.tx.proxy?.addProxy) {
      throw new Error("Required proxy calls are unavailable in this runtime");
    }
    // Confirm the proxy pallet exposes the expected proxy type.
    const availableTypes = api.registry.createType("ProxyType", PROXY_TYPE);

    console.log("Validated proxy type:", availableTypes.toString());

    const confirmation = process.env.CONFIRM_PROXY_RESET;
    if (confirmation !== "YES") {
      throw new Error(
        "No transactions sent. Set CONFIRM_PROXY_RESET=YES in .env " +
          "after checking the wallet and new proxy address.",
      );
    }

    // Step 1: Remove every existing proxy.
    console.log("\nRemoving all existing proxies...");

    const removeTx = api.tx.proxy.removeProxies();
    await submitAndWait(removeTx, signer, "Remove all proxies");

    // Step 2: Add the replacement proxy only after removal is finalized.
    console.log("\nAdding the new proxy...");

    const addTx = api.tx.proxy.addProxy(newProxy, PROXY_TYPE, PROXY_DELAY);
    await submitAndWait(addTx, signer, "Add new proxy");
    // Step 3: Verify the on-chain configuration.
    const result = await api.query.proxy.proxies(signer.address);
    const proxies = result[0].toJSON();

    console.log("\nProxy configuration after update:");
    console.dir(proxies, { depth: null });

    const found = proxies.some((entry) => {
      const delegate = entry.delegate?.Id ?? entry.delegate;
      return (
        delegate &&
        keyring.encodeAddress(decodeAddress(delegate)) === newProxy &&
        entry.proxyType === PROXY_TYPE &&
        Number(entry.delay) === PROXY_DELAY
      );
    });
    if (!found) {
      throw new Error(
        "The new proxy was not found in the final on-chain verification.",
      );
    }

    console.log("\nSUCCESS: New proxy verified on-chain.");
  } finally {
    await api.disconnect();
  }
}

main().catch((err) => {
  console.error("\nERROR:", err.message || err);
  process.exitCode = 1;
});
