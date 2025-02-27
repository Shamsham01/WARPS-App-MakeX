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

// Helper: Check transaction status
async function checkTransactionStatus(txHash, retries = 20, delay = 3000) { // Reduced retries to 20, delay to 3s
  const txStatusUrl = `https://api.multiversx.com/transactions/${txHash}`;
  for (let i = 0; i < retries; i++) {
    try {
      console.log(`Attempt ${i + 1}/${retries} to check transaction ${txHash} status at ${new Date().toISOString()}...`);
      const response = await fetch(txStatusUrl, { timeout: 5000 }); // Add timeout for fetch
      if (!response.ok) {
        console.warn(`Non-200 response for ${txHash}: ${response.status} - ${response.statusText}`);
        throw new Error(`HTTP error ${response.status}: ${response.statusText}`);
      }
      const txStatus = await response.json();
      console.log(`Transaction ${txHash} status: ${txStatus.status || 'undefined'}`);

      // Check for success or failure
      if (txStatus.status === "success") {
        return { status: "success", txHash };
      } else if (txStatus.status === "fail") {
        return { status: "fail", txHash, details: txStatus.error || 'No error details provided' };
      } else if (txStatus.status === "pending" || !txStatus.status) {
        // Continue retrying if pending or status is missing
        await new Promise(resolve => setTimeout(resolve, delay));
        continue;
      } else {
        throw new Error(`Unexpected transaction status: ${txStatus.status}`);
      }
    } catch (error) {
      console.error(`Error fetching transaction ${txHash} (attempt ${i + 1}): ${error.message}`);
      if (i === retries - 1) throw new Error(`Transaction ${txHash} not determined after ${retries} retries. Details: ${error.message}`);
      await new Promise(resolve => setTimeout(resolve, delay)); // Retry on error
    }
  }
  throw new Error(`Transaction ${txHash} not determined after ${retries} retries.`);
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

    // Validate and prepare inputs
    const userInputsArray = [];
    for (const input of action.inputs) {
      const value = inputs[input.name];
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
