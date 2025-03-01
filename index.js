import express from 'express';
import bodyParser from 'body-parser';
import { Address } from '@multiversx/sdk-core';
import { ProxyNetworkProvider } from '@multiversx/sdk-network-providers';
import { UserSigner } from '@multiversx/sdk-wallet';
import { WarpBuilder, WarpActionExecutor, WarpLink, WarpRegistry } from '@vleap/warps';
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
  registryContract: "erd1qqqqqqqqqqqqqpgq3mrpj3u6q7tejv6d7eqhnyd27n9v5c5tl3ts08mffe", // Mainnet WARP Registry contract
  userAddress: undefined // Optional, set if needed for transactions
};
// const warpConfig = {
//   providerUrl: "https://devnet-gateway.multiversx.com",
//   currentUrl: process.env.CURRENT_URL || "https://warps-makex.onrender.com",
//   chainApiUrl: "https://devnet-api.multiversx.com", // Devnet API for registry
//   env: "devnet", // Specify environment
//   registryContract: "erd1...", // Devnet WARP Registry contract
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

// Helper: Fetch WARP info and registry details (using WarpLink and WarpRegistry for dynamic type mapping)
async function fetchWarpInfo(warpId) {
  const warpBuilder = new WarpBuilder(warpConfig);
  const warpLink = new WarpLink(warpConfig);
  const warpRegistry = new WarpRegistry(warpConfig); // Initialize WarpRegistry for dynamic type mapping

  try {
    console.log(`Resolving ${warpId} via WarpLink...`);
    const result = await warpLink.detect(warpId); // Pass warpId directly (hash or alias)
    if (!result.match || !result.warp) {
      throw new Error(`Could not resolve ${warpId}`);
    }
    console.log(`Resolved ${warpId} to hash: ${result.warp.meta?.hash || 'unknown hash'}`);

    // Fetch detailed registry info for dynamic type mapping
    const registryInfo = await warpRegistry.getInfoByAlias(warpId);
    if (!registryInfo || !registryInfo.inputs) {
      console.warn(`No registry info or inputs found for ${warpId}, using default warp data`);
    }

    return {
      ...result.warp,
      registryInputs: registryInfo?.inputs || result.warp.actions[0]?.inputs || [] // Use registry inputs if available, else use warp actions
    }; // Return enhanced warp object with registry data
  } catch (error) {
    console.error(`Error resolving ${warpId} via WarpLink/Registry: ${error.message}`);
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

// Helper: Dynamically map types from registry or default to WARP actions
function mapTypeFromRegistryOrDefault(input) {
  const type = input.type.split(':')[0]; // Base type (e.g., "string", "uint64")
  const registryType = input.registryType || type; // Use registry type if available, else default

  // Map to Make.com-compatible types dynamically
  switch (registryType.toLowerCase()) {
    case "string":
      return { makeType: "text", validation: { pattern: input.pattern, minLength: input.min, maxLength: input.max } };
    case "uint8":
    case "uint16":
    case "uint32":
    case "uint64":
    case "biguint":
      return { makeType: "number", validation: { min: input.min, max: input.max, scale: input.modifier?.startsWith("scale:") ? input.modifier.split(':')[1] : null } };
    case "bool":
      return { makeType: "boolean", validation: {} };
    case "address":
      return { makeType: "text", validation: { address: true } }; // Custom validation for Multiversx addresses
    case "token":
    case "codesdata":
    case "hex":
    case "esdt":
    case "nft":
      return { makeType: "text", validation: {} };
    case "date":
      return { makeType: "date", validation: {} };
    case "option":
    case "optional":
      const baseType = input.type.split(':')[1] || "text";
      const baseMapping = mapTypeFromRegistryOrDefault({ type: baseType });
      return { makeType: baseMapping.makeType, validation: { ...baseMapping.validation, optional: true } };
    case "list":
      const listType = input.type.split(':')[1] || "text";
      const listMapping = mapTypeFromRegistryOrDefault({ type: listType });
      return { makeType: "array", validation: { itemType: listMapping.makeType, ...listMapping.validation } };
    case "varladic":
      const varladicType = input.type.split(':')[1].split('|')[0] || "text";
      const varladicMapping = mapTypeFromRegistryOrDefault({ type: varladicType });
      return { makeType: "array", validation: { itemType: varladicMapping.makeType, ...varladicMapping.validation } };
    case "composite":
      return { makeType: "text", validation: { composite: true, types: input.type.split(':')[1].split('|') || [] } };
    default:
      console.warn(`Unknown type ${registryType} for input ${input.name}, defaulting to text`);
      return { makeType: "text", validation: {} };
  }
}

// Endpoint: Get WARP input requirements (updated to return only inputs with registry-based type mapping)
app.get('/warpInfo', checkToken, async (req, res) => {
  try {
    const { warpId } = req.query;
    if (!warpId) throw new Error("Missing warpId in query parameters");

    console.log(`Fetching WARP input requirements for warpId: ${warpId}`);
    // Fetch WARP info with registry details
    const warp = await fetchWarpInfo(warpId);
    const action = warp.actions[0];
    if (!action || action.type !== 'contract') {
      throw new Error(`WARP ${warpId} must have a 'contract' action`);
    }

    // Use registry inputs if available, else fall back to action inputs
    const inputs = warp.registryInputs || action.inputs || [];
    const mappedInputs = inputs.map(input => {
      const { makeType, validation } = mapTypeFromRegistryOrDefault(input);
      return {
        name: input.name,
        type: makeType,
        label: input.name, // Use name as label since label isn’t explicitly provided
        required: input.required || false,
        ...validation // Include dynamic validation (min, max, pattern, etc.)
      };
    });

    console.log(`WARP Input Requirements Response:`, mappedInputs);
    return res.json(mappedInputs); // Ensure this is properly closed
  } catch (error) {
    console.error("Error in /warpInfo:", error.message);
    return res.status(400).json({ error: error.message });
  }
});

// Endpoint: Execute WARP with user inputs (updated to handle all WARP types, nested structures, and Make.com input formats)
app.post('/executeWarp', checkToken, async (req, res) => {
  try {
    const { warpId, inputs } = req.body;
    if (!warpId) throw new Error("Missing warpId in request body");

    // Handle inputs flexibly: accept object, array, or undefined, but ensure required fields are present
    let normalizedInputs = {};
    if (!inputs) {
      console.warn("No inputs provided in request body, checking WARP requirements...");
      const warpInfo = await fetchWarpInfo(warpId);
      const action = warpInfo.actions[0];
      if (!action || !action.inputs || action.inputs.length === 0) {
        normalizedInputs = {}; // No inputs required, proceed with empty object
      } else {
        throw new Error("Missing required 'inputs' object in request body");
      }
    } else if (typeof inputs === 'object' && !Array.isArray(inputs)) {
      normalizedInputs = inputs;
    } else if (Array.isArray(inputs)) {
      // Convert array inputs into object format
      inputs.forEach(input => {
        if (input.name && input.value !== undefined) {
          normalizedInputs[input.name] = input.value;
        }
      });
    } else {
      throw new Error("Invalid 'inputs' format in request body; must be an object or array");
    }

    console.log(`Normalized Inputs for warpId ${warpId}:`, normalizedInputs);

    // Extract PEM and signer
    const pemContent = getPemContent(req);
    const signer = UserSigner.fromPem(pemContent);
    const userAddress = signer.getAddress();

    // Fetch WARP info with registry details
    const warpInfo = await fetchWarpInfo(warpId);
    const action = warpInfo.actions[0];
    if (!action || action.type !== 'contract') {
      throw new Error(`WARP ${warpId} must have a 'contract' action`);
    }

    // Use registry inputs for validation and preparation
    const inputsSpec = warpInfo.registryInputs || action.inputs || [];
    const userInputsArray = [];

    for (const inputSpec of inputsSpec) {
      const fieldName = inputSpec.name;
      let typedValue = normalizedInputs[fieldName];

      if (inputSpec.required && (typedValue === undefined || typedValue === null || typedValue === "")) {
        throw new Error(`Missing required input: ${fieldName}`);
      }

      if (typedValue !== undefined && typedValue !== null && typedValue !== "") {
        const { makeType, validation } = mapTypeFromRegistryOrDefault(inputSpec);
        try {
          switch (makeType) {
            case "text":
              if (typeof typedValue !== "string") throw new Error(`${fieldName} must be a string`);
              if (validation.pattern && !new RegExp(validation.pattern).test(typedValue)) {
                throw new Error(`${fieldName} must match pattern: ${validation.patternDescription || validation.pattern}`);
              }
              if (validation.minLength && typedValue.length < validation.minLength) {
                throw new Error(`${fieldName} must be at least ${validation.minLength} characters`);
              }
              if (validation.maxLength && typedValue.length > validation.maxLength) {
                throw new Error(`${fieldName} must not exceed ${validation.maxLength} characters`);
              }
              break;

            case "number":
              if (isNaN(typedValue) || typeof typedValue !== "string" && typeof typedValue !== "number") {
                throw new Error(`${fieldName} must be a number or numeric string`);
              }
              typedValue = new BigNumber(typedValue).toFixed(0).toString();

              // Apply scaling if needed
              if (validation.scale) {
                const decimals = parseInt(validation.scale, 10);
                if (isNaN(decimals)) throw new Error(`Invalid scale modifier for ${fieldName}`);
                typedValue = new BigNumber(typedValue).times(new BigNumber(10).pow(decimals)).toFixed(0);
              }

              if (validation.min && new BigNumber(typedValue).lt(validation.min)) {
                throw new Error(`${fieldName} must be at least ${validation.min}`);
              }
              if (validation.max && new BigNumber(typedValue).gt(validation.max)) {
                throw new Error(`${fieldName} must not exceed ${validation.max}`);
              }
              break;

            case "boolean":
              if (typedValue !== true && typedValue !== false && typedValue !== "true" && typedValue !== "false") {
                throw new Error(`${fieldName} must be a boolean value (true/false)`);
              }
              typedValue = typedValue === true || typedValue === "true";
              break;

            case "date":
              if (!new Date(typedValue).getTime()) throw new Error(`${fieldName} must be a valid date`);
              typedValue = new Date(typedValue).toISOString();
              break;

            case "array":
              if (typeof typedValue !== "string" && !Array.isArray(typedValue)) {
                throw new Error(`${fieldName} must be a string or array of values`);
              }
              if (typeof typedValue === "string") typedValue = typedValue.split(',').map(v => v.trim());
              typedValue = typedValue.map(v => handleNestedType(v, validation.itemType || "text"));
              break;

            default:
              if (typeof typedValue !== "string") throw new Error(`${fieldName} must be a string for type ${makeType}`);
              break;
          }

          // Format value for WarpActionExecutor
          if (Array.isArray(typedValue)) {
            userInputsArray.push(...typedValue.map(v => `${makeType}:${v}`));
          } else if (typedValue !== null) {
            userInputsArray.push(`${makeType}:${typedValue}`);
          }
        } catch (validationError) {
          throw new Error(`Validation error for ${fieldName}: ${validationError.message}`);
        }
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
    console.error("Error in /executeWarp:", error.message, 'Request Body:', req.body);
    return res.status(400).json({ error: error.message });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Warp integration app is running on port ${PORT}`);
});
