import express from 'express';
import bodyParser from 'body-parser';
import { Address } from '@multiversx/sdk-core';
import { ProxyNetworkProvider } from '@multiversx/sdk-network-providers';
import { UserSigner } from '@multiversx/sdk-wallet';
import { WarpBuilder, WarpActionExecutor } from '@vleap/warps';
import { WarpRegistry } from '@vleap/warp-sdk';
import BigNumber from 'bignumber.js';

// Use mainnet (revert to devnet by uncommenting the devnet line below)
const provider = new ProxyNetworkProvider("https://gateway.multiversx.com", { clientName: "warp-integration" });
// const provider = new ProxyNetworkProvider("https://devnet-gateway.multiversx.com", { clientName: "warp-integration" });

const app = express();
const PORT = process.env.PORT || 3000;
const SECURE_TOKEN = process.env.SECURE_TOKEN || 'MY_SECURE_TOKEN';

app.use(bodyParser.json());

// Warp Configurations (for mainnet, adjust for devnet by uncommenting devnet URL below)
const warpConfig = {
  providerUrl: "https://gateway.multiversx.com",
  currentUrl: process.env.CURRENT_URL || "https://warps-makex.onrender.com",
  chainApiUrl: "https://api.multiversx.com", // Mainnet API for WarpRegistry
  env: "mainnet", // Specify environment
  registryContract: "erd1...", // Replace with actual registry contract address from vLeap docs (e.g., mainnet)
  userAddress: undefined // Optional, set if needed for transactions
};
// const warpConfig = {
//   providerUrl: "https://devnet-gateway.multiversx.com",
//   currentUrl: process.env.CURRENT_URL || "https://warps-makex.onrender.com",
//   chainApiUrl: "https://devnet-api.multiversx.com", // Devnet API for WarpRegistry
//   env: "devnet", // Specify environment
//   registryContract: "erd1...", // Replace with devnet registry contract address
//   userAddress: undefined // Optional
// };

let warpRegistry; // Global instance for WarpRegistry

// Middleware: Token check
const checkToken = (req, res, next) => {
  const token = req.headers.authorization;
  if (token === `Bearer ${SECURE_TOKEN}`) next();
  else res.status(401).json({ error: 'Unauthorized' });
};

// Helper: Get PEM and derive address
function getPemContent(req) {
  const pemContent = req.body.walletPem;
  if (!pemContent || typeof pemContent !== 'string' || !pemContent.includes('-----BEGIN PRIVATE KEY-----')) {
    throw new Error('Invalid PEM content');
  }
  return pemContent;
};

// Helper: Initialize WarpRegistry (async to ensure config is loaded)
async function initializeWarpRegistry() {
  if (!warpRegistry) {
    warpRegistry = new WarpRegistry(warpConfig);
    await warpRegistry.init(); // Load registry configs
  }
  return warpRegistry;
}

// Helper: Fetch WARP info (using WarpRegistry for aliases)
async function fetchWarpInfo(warpId) {
  const warpBuilder = new WarpBuilder(warpConfig);
  const registry = await initializeWarpRegistry();

  // Determine if warpId is a hash or alias
  const isHash = warpId.length === 64 && /^[0-9a-fA-F]+$/.test(warpId);
  let warp;

  if (isHash) {
    warp = await warpBuilder.createFromTransactionHash(warpId);
  } else {
    // Resolve alias via WarpRegistry
    try {
      console.log(`Resolving alias ${warpId} via WarpRegistry...`);
      const { registryInfo } = await registry.getInfoByAlias(warpId, { ttl: 3600 }); // Cache for 1 hour
      if (!registryInfo || !registryInfo.hash) {
        throw new Error(`Alias ${warpId} not found in registry`);
      }
      const warpHash = registryInfo.hash;
      console.log(`Resolved alias ${warpId} to hash: ${warpHash}`);
      warp = await warpBuilder.createFromTransactionHash(warpHash);
    } catch (error) {
      console.error(`Error resolving alias ${warpId}: ${error.message}`);
      throw new Error(`Failed to resolve alias ${warpId}. Use a valid alias or hash.`);
    }
  }
  
  if (!warp || !warp.actions || warp.actions.length === 0) {
    throw new Error(`Invalid WARP: ${warpId}`);
  }
  
  // Return the full blueprint for debugging/logging
  console.log(`Fetched WARP Blueprint for ${warpId}:`, warp);
  return warp; // Return the full warp object (including actions, inputs, etc.)
}

// Helper: Check transaction status with improved retry logic
async function checkTransactionStatus(txHash, retries = 20, delay = 3000) { // Keep reduced retries and delay for speed
  const txStatusUrl = `https://api.multiversx.com/transactions/${txHash}`;
  for (let i = 0; i < retries; i++) {
    try {
      console.log(`Attempt ${i + 1}/${retries} to check transaction ${txHash} status at ${new Date().toISOString()}...`);
      const response = await fetch(txStatusUrl, { timeout: 5000 }); // Retain timeout
      if (!response.ok) {
        console.warn(`Non-200 response for ${txHash}: ${response.status}`);
        throw new Error(`HTTP error ${response.status}`);
      }
      const txStatus = await response.json();
      console.log(`Transaction ${txHash} status: ${txStatus.status || 'undefined'}`);

      if (txStatus.status === "success") {
        return { status: "success", txHash };
      } else if (txStatus.status === "fail" || txStatus.status === "invalid") {
        return { status: "fail", txHash, details: txStatus.error || txStatus.receipt?.data || 'No error details provided' };
      }

      // Treat any other status (including pending or missing) as needing a retry
      console.log(`Transaction ${txHash} still pending, retrying...`);
      await new Promise(resolve => setTimeout(resolve, delay));
    } catch (error) {
      console.error(`Error fetching transaction ${txHash} (attempt ${i + 1}): ${error.message}`);
      // Don't throw here—let the loop continue and throw only on final retry
    }
  }
  throw new Error(`Transaction ${txHash} status could not be determined after ${retries} retries.`);
}

// Endpoint: Get WARP input requirements (updated to return full blueprint for debugging)
app.get('/warpInfo', checkToken, async (req, res) => {
  try {
    const { warpId } = req.query;
    if (!warpId) throw new Error("Missing warpId in query parameters");

    console.log(`Fetching WARP info for warpId: ${warpId}`);
    // Fetch WARP info
    const warp = await fetchWarpInfo(warpId);
    const action = warp.actions[0];
    if (!action || action.type !== 'contract') {
      throw new Error(`WARP ${warpId} must have a 'contract' action`);
    }

    // Return input requirements and full blueprint for debugging
    const inputs = action.inputs || [];
    console.log(`WARP Info Response:`, {
      warpId,
      warpHash: warp.hash || warpId,
      inputs: inputs,
      fullBlueprint: warp
    });
    return res.json({
      warpId,
      warpHash: warp.hash || warpId,
      inputs: inputs.map(input => ({
        name: input.name,
        type: input.type.split(':')[0], // e.g., "string" from "string:default"
        required: input.required || false,
        min: input.min,
        max: input.max,
        pattern: input.pattern,
        patternDescription: input.patternDescription,
        modifier: input.modifier // Include modifier for scaling (e.g., "scale:18")
      })),
      fullBlueprint: warp // Optionally return full blueprint for debugging
    });
  } catch (error) {
    console.error("Error in /warpInfo:", error.message);
    return res.status(400).json({ error: error.message });
  }
});

// Endpoint: Execute WARP with no user inputs
app.post('/executeWarp', checkToken, async (req, res) => {
  try {
    const { warpId } = req.body;
    if (!warpId) throw new Error("Missing warpId in request body");

    // Extract PEM and signer
    const pemContent = getPemContent(req);
    const signer = UserSigner.fromPem(pemContent);
    const userAddress = signer.getAddress();

    // Fetch WARP info
    const warpInfo = await fetchWarpInfo(warpId);
    const action = warpInfo.actions[0];
    if (!action || action.type !== 'contract') {
      throw new Error(`WARP ${warpId} must have a 'contract' action`);
    }
    if (action.inputs && action.inputs.length > 0) {
      throw new Error(`WARP ${warpId} requires user inputs; use /executeWarpWithInputs instead`);
    }

    // Execute with no inputs
    const executorConfig = { ...warpConfig, userAddress: userAddress.bech32() };
    const warpActionExecutor = new WarpActionExecutor(executorConfig);
    const tx = warpActionExecutor.createTransactionForExecute(action, [], []);

    const accountOnNetwork = await provider.getAccount(userAddress);
    tx.nonce = accountOnNetwork.nonce;
    await signer.sign(tx);
    const txHash = await provider.sendTransaction(tx);
    const status = await checkTransactionStatus(txHash.toString());

    if (status.status === "fail") {
      return res.status(400).json({
        error: `Transaction failed: ${status.details || 'Unknown reason'}`
      });
    }

    return res.json({
      warpId,
      warpHash: warpInfo.hash,
      finalTxHash: txHash.toString(),
      finalStatus: status.status
    });
  } catch (error) {
    console.error("Error in /executeWarp:", error.message);
    return res.status(400).json({ error: error.message });
  }
});

// Endpoint: Execute WARP with user inputs
app.post('/executeWarpWithInputs', checkToken, async (req, res) => {
  try {
    const { warpId, inputs } = req.body;
    if (!warpId) throw new Error("Missing warpId in request body");
    if (!inputs || typeof inputs !== 'object') throw new Error("Missing or invalid 'inputs' object in request body");

    // Extract PEM and signer
    const pemContent = getPemContent(req);
    const signer = UserSigner.fromPem(pemContent);
    const userAddress = signer.getAddress();

    // Fetch WARP info
    const warpInfo = await fetchWarpInfo(warpId);
    const action = warpInfo.actions[0];
    if (!action || action.type !== 'contract') {
      throw new Error(`WARP ${warpId} must have a 'contract' action`);
    }
    if (!action.inputs || action.inputs.length === 0) {
      throw new Error(`WARP ${warpId} has no input requirements; use /executeWarp instead`);
    }

    // Validate and prepare inputs dynamically, handling modifiers (e.g., scale:18)
    const userInputsArray = [];
    for (const input of action.inputs) {
      const value = inputs[input.name];
      if (input.required && (value === undefined || value === null)) {
        throw new Error(`Missing required input: ${input.name}`);
      }
      if (value !== undefined) {
        let typedValue = value;
        const type = input.type.split(':')[0]; // e.g., "string" from "string:default"
        
        // Handle scaling for biguint with modifier (e.g., scale:18)
        if (type === "biguint" && input.modifier && input.modifier.startsWith("scale:")) {
          const decimals = parseInt(input.modifier.split(':')[1], 10);
          if (isNaN(decimals)) throw new Error(`Invalid scale modifier for ${input.name}`);
          typedValue = new BigNumber(value).times(new BigNumber(10).pow(decimals)).toFixed(0);
        }

        if (type === "uint8" && (value < input.min || value > input.max)) {
          throw new Error(`${input.name} must be between ${input.min} and ${input.max}`);
        }
        if (type === "address" && !Address.isValid(value)) {
          throw new Error(`${input.name} must be a valid Multiversx address`);
        }
        if (type === "string" && input.pattern && !new RegExp(input.pattern).test(value)) {
          throw new Error(`${input.name} must match pattern: ${input.patternDescription || input.pattern}`);
        }
        userInputsArray.push(`${type}:${typedValue}`);
      }
    }

    // Execute transaction
    const executorConfig = { ...warpConfig, userAddress: userAddress.bech32() };
    const warpActionExecutor = new WarpActionExecutor(executorConfig);
    const tx = warpActionExecutor.createTransactionForExecute(action, userInputsArray, []);

    const accountOnNetwork = await provider.getAccount(userAddress);
    tx.nonce = accountOnNetwork.nonce;
    await signer.sign(tx);
    const txHash = await provider.sendTransaction(tx);
    const status = await checkTransactionStatus(txHash.toString());

    if (status.status === "fail") {
      return res.status(400).json({
        error: `Transaction failed: ${status.details || 'Unknown reason'}`
      });
    }

    return res.json({
      warpId,
      warpHash: warpInfo.hash,
      finalTxHash: txHash.toString(),
      finalStatus: status.status
    });
  } catch (error) {
    console.error("Error in /executeWarpWithInputs:", error.message);
    return res.status(400).json({ error: error.message });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Warp integration app is running on port ${PORT}`);
});
