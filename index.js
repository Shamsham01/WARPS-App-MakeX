import express from 'express';
import bodyParser from 'body-parser';
import { Address } from '@multiversx/sdk-core';
import { ProxyNetworkProvider } from '@multiversx/sdk-network-providers';
import { UserSigner } from '@multiversx/sdk-wallet';
import { WarpBuilder, WarpActionExecutor, WarpLink, WarpRegistry } from '@vleap/warps';
import BigNumber from 'bignumber.js';

// Use mainnet (or revert to devnet by uncommenting the devnet line below)
const provider = new ProxyNetworkProvider("https://gateway.multiversx.com", { clientName: "warp-integration" });
// const provider = new ProxyNetworkProvider("https://devnet-gateway.multiversx.com", { clientName: "warp-integration" });

const app = express();
const PORT = process.env.PORT || 3000;
const SECURE_TOKEN = process.env.SECURE_TOKEN || 'MY_SECURE_TOKEN';

app.use(bodyParser.json());

// Warp Configurations (adjust for mainnet or devnet as needed)
const warpConfig = {
  providerUrl: "https://gateway.multiversx.com",
  currentUrl: process.env.CURRENT_URL || "https://warps-makex.onrender.com",
  chainApiUrl: "https://api.multiversx.com", // Mainnet API for registry
  env: "mainnet",
  registryContract: "erd1qqqqqqqqqqqqqpgq3mrpj3u6q7tejv6d7eqhnyd27n9v5c5tl3ts08mffe",
  userAddress: undefined
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
};

// Helper: Fetch WARP info using WarpRegistry and WarpLink
async function fetchWarpInfo(warpId) {
  const warpRegistry = new WarpRegistry(warpConfig);
  const warpLink = new WarpLink(warpConfig);

  try {
    console.log(`Resolving ${warpId}...`);
    let warp;
    let resolutionSource = '';

    if (warpId.startsWith('hash:')) {
      resolutionSource = 'WarpRegistry.getInfoByHash';
      warp = await warpRegistry.getInfoByHash(warpId.replace('hash:', ''));
    } else {
      // Try alias first via registry
      resolutionSource = 'WarpRegistry.getInfoByAlias';
      warp = await warpRegistry.getInfoByAlias(warpId);
      if (!warp) {
        resolutionSource = 'WarpLink.detect';
        const result = await warpLink.detect(warpId);
        if (!result.match || !result.warp) {
          throw new Error(`Could not resolve ${warpId}`);
        }
        warp = result.warp; // Use the nested warp object from WarpLink.detect
      }
    }

    console.log(`Raw warp object from ${resolutionSource}:`, JSON.stringify(warp, null, 2));
    console.log(`Resolved ${warpId} to hash: ${warp?.meta?.hash || 'unknown hash'}`);

    // Ensure warp object consistency
    if (!warp) {
      throw new Error(`No warp data returned for ${warpId}`);
    }
    if (!Array.isArray(warp.actions) || warp.actions.length === 0) {
      throw new Error(`Invalid warp structure for ${warpId}: actions is missing or empty`);
    }

    return warp;
  } catch (error) {
    console.error(`Error resolving ${warpId}: ${error.message}`);
    throw error; // Propagate the original error for better debugging
  }
}

// Helper: Check transaction status with retry logic
async function checkTransactionStatus(txHash, retries = 20, delay = 3000) {
  const txStatusUrl = `https://api.multiversx.com/transactions/${txHash}`;
  for (let i = 0; i < retries; i++) {
    try {
      console.log(`Attempt ${i + 1}/${retries} to check transaction ${txHash} at ${new Date().toISOString()}...`);
      const response = await fetch(txStatusUrl, { timeout: 5000 });
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
      console.log(`Transaction ${txHash} still pending, retrying...`);
      await new Promise(resolve => setTimeout(resolve, delay));
    } catch (error) {
      console.error(`Error fetching transaction ${txHash} (attempt ${i + 1}): ${error.message}`);
    }
  }
  throw new Error(`Transaction ${txHash} status could not be determined after ${retries} retries.`);
}

// --- Endpoints ---

// 1. GET /warpRPC
// This endpoint returns dynamic input fields for Make.com based on the warp blueprint.
app.get('/warpRPC', checkToken, async (req, res) => {
  try {
    const { warpId } = req.query;
    if (!warpId) throw new Error("Missing warpId in query parameters");

    console.log(`Fetching dynamic input fields for warpId: ${warpId}`);
    const warp = await fetchWarpInfo(warpId);
    console.log(`Warp object received:`, JSON.stringify(warp, null, 2));

    // Validate actions array
    if (!Array.isArray(warp.actions) || warp.actions.length === 0) {
      throw new Error(`Warp ${warpId} has no valid actions array`);
    }

    const action = warp.actions[0];
    if (!action || action.type !== 'contract') {
      throw new Error(`Warp ${warpId} must have a 'contract' action`);
    }

    // Map inputs for Make.com
    const inputs = action.inputs || [];
    const mappedInputs = inputs.map(input => ({
      name: input.name,
      type: mapToMakeType(input.type.split(':')[0]), // Converts API type to Make.com type
      label: input.name,
      required: input.required || false,
      min: input.min,
      max: input.max,
      pattern: input.pattern,
      patternDescription: input.patternDescription,
      modifier: input.modifier // e.g., "scale:18"
    }));

    console.log(`Response from /warpRPC:`, mappedInputs);
    return res.json(mappedInputs);
  } catch (error) {
    console.error("Error in /warpRPC:", error.message);
    return res.status(400).json({ error: error.message });
  }
});

// Helper function to map API types to Make.com types
function mapToMakeType(apiType) {
  switch (apiType) {
    case "string":
      return "text";
    case "biguint":
    case "uint8":
    case "uint16":
    case "uint32":
    case "uint64":
      return "number";
    case "date":
      return "date";
    default:
      return "text";
  }
}

// 2. POST /warpInfo
// This endpoint interacts with the registry to fetch blueprint details and then executes the warp.
app.post('/warpInfo', checkToken, async (req, res) => {
  try {
    console.log("Incoming /warpInfo request body:", req.body);
    const { warpId, inputs } = req.body;
    if (!warpId) throw new Error("Missing warpId in request body");
    if (!inputs || typeof inputs !== 'object') throw new Error("Missing or invalid 'inputs' object in request body");

    // Extract PEM and signer details
    const pemContent = getPemContent(req);
    const signer = UserSigner.fromPem(pemContent);
    const userAddress = signer.getAddress();

    // Initialize WarpRegistry and fetch registry blueprint info
    const warpRegistry = new WarpRegistry(warpConfig);
    let registryInfo;
    if (warpId.startsWith('hash:')) {
      registryInfo = await warpRegistry.getInfoByHash(warpId.replace('hash:', ''));
    } else {
      // Default: treat as alias (strip alias: prefix if present)
      registryInfo = await warpRegistry.getInfoByAlias(warpId.replace('alias:', ''));
    }
    if (!registryInfo) {
      throw new Error(`No registry info found for ${warpId}`);
    }
    console.log(`Registry info for warpId ${warpId}:`, JSON.stringify(registryInfo, null, 2));

    // Use the blueprint (registryInfo) to get the contract action details
    const action = registryInfo.actions[0];
    if (!action || action.type !== 'contract') {
      throw new Error(`Warp ${warpId} from registry must have a 'contract' action`);
    }
    if (!action.inputs || action.inputs.length === 0) {
      throw new Error(`Warp ${warpId} from registry has no input requirements; execution may not be needed`);
    }

    // Validate and prepare inputs based on registry blueprint details
    const userInputsArray = [];
    for (const input of action.inputs) {
      const value = inputs[input.name];
      if (input.required && (value === undefined || value === null)) {
        throw new Error(`Missing required input: ${input.name}`);
      }
      if (value !== undefined) {
        let typedValue = value;
        const type = input.type.split(':')[0];
        
        // Handle scaling for numeric types if modifier exists (e.g., scale:18)
        if ((type === "biguint" || type.startsWith("uint")) && input.modifier && input.modifier.startsWith("scale:")) {
          const decimals = parseInt(input.modifier.split(':')[1], 10);
          if (isNaN(decimals)) throw new Error(`Invalid scale modifier for ${input.name}`);
          typedValue = new BigNumber(value).times(new BigNumber(10).pow(decimals)).toFixed(0);
        }

        // Additional validations (e.g., address format or pattern matching)
        if (type === "address" && !Address.isValid(value)) {
          throw new Error(`${input.name} must be a valid MultiversX address`);
        }
        if (type === "string" && input.pattern && !new RegExp(input.pattern).test(value)) {
          throw new Error(`${input.name} must match pattern: ${input.patternDescription || input.pattern}`);
        }

        userInputsArray.push(`${type}:${typedValue}`);
      }
    }
    console.log("Prepared userInputsArray for registry warp:", userInputsArray);

    // Execute the transaction using the registry blueprint data
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
      warpHash: registryInfo.meta?.hash,
      finalTxHash: txHash.toString(),
      finalStatus: status.status
    });
  } catch (error) {
    console.error("Error in /warpInfo:", error.message);
    return res.status(400).json({ error: error.message });
  }
});

// 3. POST /executeWarpWithInputs
// This endpoint executes a warp using inputs provided by Make.com via WarpLink.
app.post('/executeWarpWithInputs', checkToken, async (req, res) => {
  try {
    console.log("Incoming /executeWarpWithInputs request body:", req.body);
    const { warpId, inputs } = req.body;
    if (!warpId) throw new Error("Missing warpId in request body");
    if (!inputs || typeof inputs !== 'object') throw new Error("Missing or invalid 'inputs' object in request body");

    // Extract PEM and signer details
    const pemContent = getPemContent(req);
    const signer = UserSigner.fromPem(pemContent);
    const userAddress = signer.getAddress();

    // Fetch warp info via WarpLink (this may differ from registry-based warps)
    const warpInfo = await fetchWarpInfo(warpId);
    console.log("Fetched warp info via WarpLink:", JSON.stringify(warpInfo, null, 2));
    console.log("User inputs received:", inputs);

    const action = warpInfo.actions[0];
    if (!action || action.type !== 'contract') {
      throw new Error(`Warp ${warpId} must have a 'contract' action`);
    }
    if (!action.inputs || action.inputs.length === 0) {
      throw new Error(`Warp ${warpId} does not have input requirements; use /executeWarp instead`);
    }

    // Validate and prepare inputs dynamically
    const userInputsArray = [];
    for (const input of action.inputs) {
      const value = inputs[input.name];
      if (input.required && (value === undefined || value === null)) {
        throw new Error(`Missing required input: ${input.name}`);
      }
      if (value !== undefined) {
        let typedValue = value;
        const type = input.type.split(':')[0];
        
        // Handle scaling for numeric types if modifier exists (e.g., scale:18)
        if ((type === "biguint" || type.startsWith("uint")) && input.modifier && input.modifier.startsWith("scale:")) {
          const decimals = parseInt(input.modifier.split(':')[1], 10);
          if (isNaN(decimals)) throw new Error(`Invalid scale modifier for ${input.name}`);
          typedValue = new BigNumber(value).times(new BigNumber(10).pow(decimals)).toFixed(0);
        }

        // Additional validations
        if (type === "address" && !Address.isValid(value)) {
          throw new Error(`${input.name} must be a valid MultiversX address`);
        }
        if (type === "string" && input.pattern && !new RegExp(input.pattern).test(value)) {
          throw new Error(`${input.name} must match pattern: ${input.patternDescription || input.pattern}`);
        }

        userInputsArray.push(`${type}:${typedValue}`);
      }
    }
    console.log("Prepared userInputsArray for WarpLink execution:", userInputsArray);

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
