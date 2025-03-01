import express from 'express';
import bodyParser from 'body-parser';
import { Address } from '@multiversx/sdk-core';
import { ProxyNetworkProvider } from '@multiversx/sdk-network-providers';
import { UserSigner } from '@multiversx/sdk-wallet';
import { WarpBuilder, WarpActionExecutor, WarpLink } from '@vleap/warps'; // Use WarpLink from @vleap/warps
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
  chainApiUrl: "https://api.multiversx.com", // Mainnet API for registry
  env: "mainnet", // Specify environment
  registryContract: "erd1qqqqqqqqqqqqqpgq3mrpj3u6q7tejv6d7eqhnyd27n9v5c5tl3ts08mffe", // Mainnet WARP Registry contract (replace if incorrect, check vLeap docs)
  userAddress: undefined // Optional, set if needed for transactions
};
// const warpConfig = {
//   providerUrl: "https://devnet-gateway.multiversx.com",
//   currentUrl: process.env.CURRENT_URL || "https://warps-makex.onrender.com",
//   chainApiUrl: "https://devnet-api.multiversx.com", // Devnet API for registry
//   env: "devnet", // Specify environment
//   registryContract: "erd1...", // Devnet WARP Registry contract (replace if incorrect)
//   userAddress: undefined // Optional
// };

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

// Helper: Fetch WARP info (using WarpLink for both hashes and aliases)
async function fetchWarpInfo(warpId) {
  const warpBuilder = new WarpBuilder(warpConfig);
  const warpLink = new WarpLink(warpConfig); // Initialize WarpLink for detection

  // Try to resolve warpId using WarpLink.detect (handles both hashes and aliases)
  try {
    console.log(`Resolving ${warpId} via WarpLink...`);
    const result = await warpLink.detect(warpId); // Pass warpId directly (hash or alias)
    if (!result.match || !result.warp) {
      throw new Error(`Could not resolve ${warpId}`);
    }
    console.log(`Resolved ${warpId} to hash: ${result.warp.meta?.hash || 'unknown hash'}`);
    return result.warp; // Return the full Warp blueprint
  } catch (error) {
    console.error(`Error resolving ${warpId} via WarpLink: ${error.message}`);
    throw new Error(`Failed to resolve ${warpId}. Use a valid alias or hash.`);
  }
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

// Endpoint: Get WARP input requirements (updated to return only inputs for Make.com mapping)
app.get('/warpInfo', checkToken, async (req, res) => {
  try {
    const { warpId } = req.query;
    if (!warpId) throw new Error("Missing warpId in query parameters");

    console.log(`Fetching WARP input requirements for warpId: ${warpId}`);
    // Fetch WARP info
    const warp = await fetchWarpInfo(warpId);
    const action = warp.actions[0];
    if (!action || action.type !== 'contract') {
      throw new Error(`WARP ${warpId} must have a 'contract' action`);
    }

    // Extract and map only the inputs array, converting types for Make.com
    const inputs = action.inputs || [];
    const mappedInputs = inputs.map(input => ({
      name: input.name,
      type: mapToMakeType(input.type.split(':')[0]), // Convert API type to Make.com type
      label: input.name, // Use name as label since label isn’t explicitly provided
      required: input.required || false,
      min: input.min,
      max: input.max,
      pattern: input.pattern,
      patternDescription: input.patternDescription,
      modifier: input.modifier // Include modifier for scaling (e.g., "scale:Token Decimals")
    }));

    console.log(`WARP Input Requirements Response:`, mappedInputs);
    return res.json(mappedInputs); // Return only the mapped inputs array
  } catch (error) {
    console.error("Error in /warpInfo:", error.message);
    return res.status(400).json({ error: error.message });
  }
});

// Helper function to map API types to Make.com types
function mapToMakeType(apiType) {
  switch (apiType) {
    case "string":
      return "text"; // Make.com uses "text" instead of "string"
    case "biguint":
    case "uint8":
      return "number"; // Map large/unsigned integers to "number"
    case "date":
      return "date"; // Map date types to Make.com’s "date"
    default:
      return "text"; // Default to "text" if type isn’t recognized
  }
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
      warpHash: warpInfo.meta?.hash,
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
      warpHash: warpInfo.meta?.hash,
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
