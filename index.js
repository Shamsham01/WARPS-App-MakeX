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

// Helper: Fetch WARP info (simplified, assumes @vleap/warps handles aliases)
async function fetchWarpInfo(warpId) {
  const warpBuilder = new WarpBuilder(warpConfig);
  
  // Determine if warpId is a hash or alias
  const isHash = warpId.length === 64 && /^[0-9a-fA-F]+$/.test(warpId);
  let warp;
  
  if (isHash) {
    warp = await warpBuilder.createFromTransactionHash(warpId);
  } else {
    // Placeholder for alias resolution (adjust if @vleap/warps has a specific method)
    warp = await warpBuilder.createFromAlias?.(warpId) || await warpBuilder.createFromTransactionHash(warpId); // Fallback to hash if alias unsupported
    if (!warp) {
      throw new Error(`Failed to resolve alias: ${warpId}. Use a valid alias or hash.`);
    }
  }
  
  if (!warp || !warp.actions || warp.actions.length === 0) {
    throw new Error(`Invalid WARP: ${warpId}`);
  }
  
  return {
    hash: isHash ? warpId : warp.hash || warpId, // Use resolved hash if available
    actions: warp.actions
  };
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

    // Validate and prepare inputs dynamically
    const userInputsArray = [];
    for (const input of action.inputs) {
      const value = inputs[input.name];
      if (input.required && (value === undefined || value === null)) {
        throw new Error(`Missing required input: ${input.name}`);
      }
      if (value !== undefined) {
        const type = input.type.split(':')[0]; // e.g., "string" from "string:default"
        if (type === "uint8" && (value < input.min || value > input.max)) {
          throw new Error(`${input.name} must be between ${input.min} and ${input.max}`);
        }
        if (type === "address" && !Address.isValid(value)) {
          throw new Error(`${input.name} must be a valid Multiversx address`);
        }
        if (type === "string" && input.pattern && !new RegExp(input.pattern).test(value)) {
          throw new Error(`${input.name} must match pattern: ${input.patternDescription || input.pattern}`);
        }
        userInputsArray.push(`${type}:${value}`);
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
