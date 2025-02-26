import express from 'express';
import bodyParser from 'body-parser';
import { Address } from '@multiversx/sdk-core';
import { ProxyNetworkProvider } from '@multiversx/sdk-network-providers';
import { UserSigner } from '@multiversx/sdk-wallet';
import { WarpBuilder, WarpActionExecutor } from '@vleap/warps';

const provider = new ProxyNetworkProvider("https://gateway.multiversx.com", { clientName: "warp-integration" });
const app = express();
const PORT = process.env.PORT || 3000;
const SECURE_TOKEN = process.env.SECURE_TOKEN || 'MY_SECURE_TOKEN';

app.use(bodyParser.json());

// Warp Configurations
const warpConfig = {
  providerUrl: "https://gateway.multiversx.com",
  currentUrl: process.env.CURRENT_URL || "https://warps-makex.onrender.com"
};

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
}

// Helper: Fetch WARP info (simplified, assumes @vleap/warps provides this)
async function fetchWarpInfo(warpId) {
  const warpBuilder = new WarpBuilder(warpConfig);
  
  // Determine if warpId is an alias or hash
  const isHash = warpId.length === 64 && /^[0-9a-fA-F]+$/.test(warpId);
  let warp;
  
  if (isHash) {
    warp = await warpBuilder.createFromTransactionHash(warpId);
  } else {
    // Assume alias resolution via registry (pseudo-code, adjust per SDK)
    // This might require a direct contract query if not built into WarpBuilder
    warp = await warpBuilder.createFromAlias(warpId); // Hypothetical method
    if (!warp) {
      throw new Error(`Failed to resolve alias: ${warpId}. Use a valid alias or hash.`);
    }
  }
  
  if (!warp || !warp.actions || warp.actions.length === 0) {
    throw new Error(`Invalid WARP: ${warpId}`);
  }
  
  return {
    hash: isHash ? warpId : warp.hash, // Fallback to resolved hash if alias
    actions: warp.actions
  };
}

// Helper: Prepare inputs based on action requirements
function prepareWarpInputs(action, payload) {
  if (!action.inputs || action.inputs.length === 0) return [];

  const inputs = [];
  for (const input of action.inputs) {
    const value = payload[input.name];
    if (input.required && (value === undefined || value === null)) {
      throw new Error(`Missing required input: ${input.name}`);
    }
    if (value !== undefined) {
      const type = input.type.split(':')[0]; // e.g., "string" from "string:default"
      if (type === "uint8" && (value < 0 || value > 255)) {
        throw new Error(`${input.name} must be between 0 and 255`);
      }
      if (type === "address" && !Address.isValid(value)) {
        throw new Error(`${input.name} must be a valid MultiversX address`);
      }
      inputs.push(`${type}:${value}`);
    }
  }
  return inputs;
}

// Helper: Check transaction status (unchanged)
async function checkTransactionStatus(txHash, retries = 40, delay = 5000) {
  const txStatusUrl = `https://api.multiversx.com/transactions/${txHash}`;
  for (let i = 0; i < retries; i++) {
    const response = await fetch(txStatusUrl);
    if (!response.ok) throw new Error(`HTTP error ${response.status}`);
    const txStatus = await response.json();
    if (txStatus.status === "success") return { status: "success", txHash };
    if (txStatus.status === "fail") return { status: "fail", txHash };
    await new Promise(resolve => setTimeout(resolve, delay));
  }
  throw new Error(`Transaction ${txHash} not determined after ${retries} retries.`);
}

// Endpoint: Execute WARP by ID
app.post('/executeWarp', checkToken, async (req, res) => {
  try {
    const { warpId, ...payload } = req.body;
    if (!warpId) throw new Error("Missing warpId in request body");

    // Fetch WARP info
    const warpInfo = await fetchWarpInfo(warpId);
    const action = warpInfo.actions[0]; // Default to first action, could be parameterized
    if (!action || action.type !== 'contract') {
      throw new Error(`WARP ${warpId} must have a 'contract' action`);
    }

    // Extract PEM and signer
    const pemContent = getPemContent(req);
    const signer = UserSigner.fromPem(pemContent);
    const userAddress = signer.getAddress();

    // Prepare inputs dynamically
    const userInputsArray = prepareWarpInputs(action, payload);

    // Execute transaction
    const executorConfig = { ...warpConfig, userAddress: userAddress.bech32() };
    const warpActionExecutor = new WarpActionExecutor(executorConfig);
    const tx = warpActionExecutor.createTransactionForExecute(action, userInputsArray, []);

    const accountOnNetwork = await provider.getAccount(userAddress);
    tx.nonce = accountOnNetwork.nonce;
    await signer.sign(tx);
    const txHash = await provider.sendTransaction(tx);
    const status = await checkTransactionStatus(txHash.toString());

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

// Start server
app.listen(PORT, () => {
  console.log(`Warp integration app is running on port ${PORT}`);
});