import express from 'express';
import bodyParser from 'body-parser';
import { Address } from '@multiversx/sdk-core';
import { ProxyNetworkProvider } from '@multiversx/sdk-network-providers';
import { UserSigner } from '@multiversx/sdk-wallet';
import { WarpBuilder, WarpActionExecutor, WarpLink } from '@vleap/warps';
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
  // Handle base types
  switch (apiType) {
    case "string":
      return "text"; // Make.com uses "text" instead of "string"
    case "uint8":
    case "uint16":
    case "uint32":
    case "uint64":
    case "biguint":
      return "number"; // Map all unsigned integers to "number"
    case "bool":
      return "boolean"; // Map boolean to Make.com’s "boolean"
    case "address":
    case "token":
    case "codesdata":
    case "hex":
    case "esdt":
    case "nft":
      return "text"; // Map these to "text" for user input, with custom validation if needed
    case "date":
      return "date"; // Map date to Make.com’s "date"
    default:
      // Handle nested types
      if (apiType.startsWith("option:")) {
        const baseType = apiType.split(':')[1];
        return mapToMakeType(baseType); // Map to base type, mark as optional in validation
      } else if (apiType.startsWith("optional:")) {
        const baseType = apiType.split(':')[1];
        return mapToMakeType(baseType); // Map to base type, optional
      } else if (apiType.startsWith("list:")) {
        const baseType = apiType.split(':')[1];
        return "array"; // Map lists to "array" in Make.com, with custom parsing
      } else if (apiType.startsWith("varladic:")) {
        const baseType = apiType.split(':')[1].split('|')[0]; // Get first type (e.g., "uint64")
        return "array"; // Map varladic to "array" of base type
      } else if (apiType.startsWith("composite:")) {
        return "text"; // Map composites to "text" for simplicity, with custom parsing if needed
      }
      return "text"; // Default to "text" if type isn’t recognized
  }
}

// Endpoint: Execute WARP with user inputs (renamed and updated to handle all WARP types and nested structures)
app.post('/executeWarp', checkToken, async (req, res) => {
  try {
    const { warpId, inputs } = req.body;
    if (!warpId) throw new Error("Missing warpId in request body");
    if (!inputs || typeof inputs !== 'object' || Object.keys(inputs).length === 0) {
      throw new Error("Missing or invalid 'inputs' object in request body");
    }

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
      throw new Error(`WARP ${warpId} has no input requirements`);
    }

    // Prepare user inputs dynamically, handling all WARP types and nested structures
    const userInputsArray = [];
    for (const input of action.inputs) {
      const fieldName = input.name;
      const value = inputs[fieldName]; // Get value from the flat inputs object sent by Make.com

      if (input.required && (value === undefined || value === null || value === "")) {
        throw new Error(`Missing required input: ${fieldName}`);
      }

      if (value !== undefined && value !== null && value !== "") {
        let typedValue = value;
        const type = input.type.split(':')[0]; // e.g., "string" from "string:default"

        // Handle base types and nested structures
        switch (type) {
          case "string":
            if (typeof typedValue !== "string") throw new Error(`${fieldName} must be a string`);
            if (input.pattern && !new RegExp(input.pattern).test(typedValue)) {
              throw new Error(`${fieldName} must match pattern: ${input.patternDescription || input.pattern}`);
            }
            if (input.min && typedValue.length < input.min) throw new Error(`${fieldName} must be at least ${input.min} characters`);
            if (input.max && typedValue.length > input.max) throw new Error(`${fieldName} must not exceed ${input.max} characters`);
            break;
          case "uint8":
          case "uint16":
          case "uint32":
          case "uint64":
          case "biguint":
            if (isNaN(typedValue) || typeof typedValue !== "string" && typeof typedValue !== "number") {
              throw new Error(`${fieldName} must be a number or numeric string`);
            }
            typedValue = new BigNumber(typedValue).toFixed(0).toString(); // Convert to BigNumber for precision
            if (input.modifier && input.modifier.startsWith("scale:")) {
              const scaleValue = input.modifier.split(':')[1];
              if (scaleValue === "Token Decimals") {
                const decimals = inputs["Token Decimals"];
                if (decimals === undefined || isNaN(decimals)) {
                  throw new Error(`Missing or invalid 'Token Decimals' for scaling ${fieldName}`);
                }
                const actualDecimals = parseInt(decimals, 10);
                if (actualDecimals < 0 || actualDecimals > 18) {
                  throw new Error(`'Token Decimals' must be between 0 and 18`);
                }
                typedValue = new BigNumber(typedValue).times(new BigNumber(10).pow(actualDecimals)).toFixed(0);
              } else {
                const decimals = parseInt(scaleValue, 10);
                if (isNaN(decimals)) throw new Error(`Invalid scale modifier for ${fieldName}`);
                typedValue = new BigNumber(typedValue).times(new BigNumber(10).pow(decimals)).toFixed(0);
              }
            }
            break;
          case "bool":
            if (typedValue !== true && typedValue !== false && typedValue !== "true" && typedValue !== "false") {
              throw new Error(`${fieldName} must be a boolean value (true/false)`);
            }
            typedValue = typedValue === true || typedValue === "true";
            break;
          case "address":
            if (!Address.isValid(typedValue)) {
              throw new Error(`${fieldName} must be a valid Multiversx address`);
            }
            break;
          case "token":
          case "codesdata":
          case "hex":
          case "esdt":
          case "nft":
            if (typeof typedValue !== "string") throw new Error(`${fieldName} must be a string`);
            break;
          case "date":
            if (!new Date(typedValue).getTime()) throw new Error(`${fieldName} must be a valid date`);
            typedValue = new Date(typedValue).toISOString();
            break;
          case "option":
          case "optional":
            if (typedValue === "" || typedValue === null || typedValue === undefined) {
              typedValue = null; // Handle optional/empty values
            } else {
              const baseType = input.type.split(':')[1];
              typedValue = handleNestedType(typedValue, baseType);
            }
            break;
          case "list":
            if (typeof typedValue !== "string" && !Array.isArray(typedValue)) {
              throw new Error(`${fieldName} must be a string or array of values`);
            }
            if (typeof typedValue === "string") typedValue = typedValue.split(',').map(v => v.trim());
            typedValue = typedValue.map(v => handleNestedType(v, input.type.split(':')[1]));
            break;
          case "varladic":
            if (typeof typedValue !== "string" && !Array.isArray(typedValue)) {
              throw new Error(`${fieldName} must be a string or array of values`);
            }
            if (typeof typedValue === "string") typedValue = typedValue.split(',').map(v => v.trim());
            const varladicType = input.type.split(':')[1].split('|')[0]; // Get first type (e.g., "uint64")
            typedValue = typedValue.map(v => handleNestedType(v, varladicType));
            break;
          case "composite":
            if (typeof typedValue !== "string") throw new Error(`${fieldName} must be a string in format 'type1:value1|type2:value2'`);
            typedValue = parseComposite(typedValue, input.type.split(':')[1].split('|')); // Parse based on composite types
            break;
          default:
            throw new Error(`Unsupported type ${type} for ${fieldName}`);
        }

        // Format the value for WarpActionExecutor (e.g., "type:value" or array for lists/varladic)
        if (Array.isArray(typedValue)) {
          userInputsArray.push(...typedValue.map(v => `${type}:${v}`));
        } else if (typedValue !== null) { // Skip null for optional/empty values
          userInputsArray.push(`${type}:${typedValue}`);
        }
      }
    }

    // Helper function for nested types
    function handleNestedType(value, baseType) {
      switch (baseType) {
        case "string":
          if (typeof value !== "string") throw new Error(`Value must be a string`);
          return value;
        case "uint8":
        case "uint16":
        case "uint32":
        case "uint64":
        case "biguint":
          if (isNaN(value)) throw new Error(`Value must be a number`);
          return new BigNumber(value).toFixed(0).toString();
        case "bool":
          if (value !== true && value !== false && value !== "true" && value !== "false") {
            throw new Error(`Value must be a boolean (true/false)`);
          }
          return value === true || value === "true";
        case "address":
          if (!Address.isValid(value)) throw new Error(`Value must be a valid Multiversx address`);
          return value;
        default:
          return value.toString(); // Default to string for unrecognized nested types
      }
    }

    // Helper function for composite types
    function parseComposite(value, types) {
      const parts = value.split('|');
      if (parts.length !== types.length) throw new Error(`Composite ${value} must match types ${types.join('|')}`);
      const result = [];
      parts.forEach((part, index) => {
        const type = types[index];
        result.push(`${type}:${handleNestedType(part, type)}`);
      });
      return result;
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
    console.error("Error in /executeWarp:", error.message);
    return res.status(400).json({ error: error.message });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Warp integration app is running on port ${PORT}`);
});
