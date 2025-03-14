import express from 'express';
import bodyParser from 'body-parser';
import { Address, TransactionsFactoryConfig, TransferTransactionsFactory, TokenTransfer, Token } from '@multiversx/sdk-core';
import { ProxyNetworkProvider } from '@multiversx/sdk-network-providers';
import { UserSigner } from '@multiversx/sdk-wallet';
import { WarpBuilder, WarpActionExecutor, WarpLink } from '@vleap/warps';
import BigNumber from 'bignumber.js';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import fetch from 'node-fetch';

// Use mainnet (or revert to devnet by uncommenting the devnet line below)
const provider = new ProxyNetworkProvider("https://gateway.multiversx.com", { clientName: "warp-integration" });
// const provider = new ProxyNetworkProvider("https://devnet-gateway.multiversx.com", { clientName: "warp-integration" });

const app = express();
const PORT = process.env.PORT || 10000; // Matches Render's detected port
const SECURE_TOKEN = process.env.SECURE_TOKEN || 'MY_SECURE_TOKEN';

app.use(bodyParser.json());

// Warp Configurations (adjust for mainnet or devnet as needed)
const warpConfig = {
  providerUrl: "https://gateway.multiversx.com",
  currentUrl: process.env.CURRENT_URL || "https://warps-makex.onrender.com",
  chainApiUrl: "https://api.multiversx.com",
  env: "mainnet",
  userAddress: undefined
};

// Constants for usage fee
const FIXED_USD_FEE = 0.03; // $0.03 fixed fee
const REWARD_TOKEN = "REWARD-cf6eac";
const TREASURY_WALLET = "erd158k2c3aserjmwnyxzpln24xukl2fsvlk9x46xae4dxl5xds79g6sdz37qn";
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const whitelistFilePath = path.join(__dirname, 'whitelist.json');

// In-memory store for tracking pending transactions (in production, consider using Redis or a database)
const pendingUsageFeeTransactions = new Map();

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

// Helper: Fetch token decimals from MultiversX API
const getTokenDecimals = async (tokenTicker) => {
  const apiUrl = `https://api.multiversx.com/tokens/${tokenTicker}`;
  const response = await fetch(apiUrl);
  if (!response.ok) {
    throw new Error(`Failed to fetch token info: ${response.statusText}`);
  }
  const tokenInfo = await response.json();
  return tokenInfo.decimals || 0;
};

// Helper: Convert amount to blockchain-compatible value
const convertAmountToBlockchainValue = (amount, decimals) => {
  const factor = new BigNumber(10).pow(decimals);
  return new BigNumber(amount).multipliedBy(factor).toFixed(0);
};

// Helper: Load whitelist from file
const loadWhitelist = () => {
  if (!fs.existsSync(whitelistFilePath)) {
    fs.writeFileSync(whitelistFilePath, JSON.stringify([], null, 2));
  }
  const data = fs.readFileSync(whitelistFilePath);
  return JSON.parse(data);
};

// Helper: Check if wallet is whitelisted
const isWhitelisted = (walletAddress) => {
  const whitelist = loadWhitelist();
  return whitelist.some(entry => entry.walletAddress === walletAddress);
};

// Helper: Fetch REWARD token price from MultiversX API
const getRewardPrice = async () => {
  try {
    // Fetch token info directly from MultiversX API
    const tokenResponse = await fetch(`https://api.multiversx.com/tokens?search=${REWARD_TOKEN}`);
    if (!tokenResponse.ok) {
      throw new Error(`Failed to fetch token info: ${tokenResponse.statusText}`);
    }
    
    const tokenData = await tokenResponse.json();
    if (!tokenData || !tokenData.length || !tokenData[0].price) {
      throw new Error('Token price not available');
    }
    
    // Get price directly from the API response
    const tokenPrice = new BigNumber(tokenData[0].price);
    
    if (tokenPrice.isZero() || !tokenPrice.isFinite()) {
      throw new Error('Invalid token price from API');
    }
    
    return tokenPrice.toNumber();
  } catch (error) {
    console.error('Error fetching REWARD price:', error);
    throw error;
  }
};

// Helper: Calculate dynamic usage fee based on REWARD price
const calculateDynamicUsageFee = async () => {
  const rewardPrice = await getRewardPrice();
  
  if (rewardPrice <= 0) {
    throw new Error('Invalid REWARD token price');
  }

  const rewardAmount = new BigNumber(FIXED_USD_FEE).dividedBy(rewardPrice);
  const decimals = await getTokenDecimals(REWARD_TOKEN);
  
  // Ensure the amount is not too small or too large
  if (!rewardAmount.isFinite() || rewardAmount.isZero()) {
    throw new Error('Invalid usage fee calculation');
  }

  return convertAmountToBlockchainValue(rewardAmount, decimals);
};

// Helper: Check transaction status with consistent retry logic
async function checkTransactionStatus(txHash, maxRetries = 20, retryInterval = 2000) {
  for (let i = 0; i < maxRetries; i++) {
    try {
      // Only log first, last, and every 5th attempt to reduce noise
      if (i === 0 || i === maxRetries - 1 || i % 5 === 0) {
        console.log(`Checking transaction ${txHash} status (attempt ${i + 1}/${maxRetries})...`);
      }
      
      const txStatusUrl = `https://api.multiversx.com/transactions/${txHash}`;
      const response = await fetch(txStatusUrl, { timeout: 5000 });
      
      if (!response.ok) {
        if (response.status === 404) {
          // Transaction not yet visible, retry after interval
          await new Promise(resolve => setTimeout(resolve, retryInterval));
          continue;
        }
        throw new Error(`HTTP error ${response.status}`);
      }
      
      const txStatus = await response.json();
      
      if (txStatus.status === "success") {
        console.log(`Transaction ${txHash} completed successfully.`);
        return { status: "success", txHash };
      } else if (txStatus.status === "fail" || txStatus.status === "invalid") {
        console.log(`Transaction ${txHash} failed with status: ${txStatus.status}`);
        return { 
          status: "fail", 
          txHash, 
          details: txStatus.error || txStatus.receipt?.data || 'No error details provided' 
        };
      }
      
      // Transaction still pending, retry after interval
      await new Promise(resolve => setTimeout(resolve, retryInterval));
    } catch (error) {
      console.error(`Error checking transaction ${txHash}: ${error.message}`);
      // Continue retrying even after fetch errors
      await new Promise(resolve => setTimeout(resolve, retryInterval));
    }
  }
  
  // Max retries reached without definitive status
  console.log(`Transaction ${txHash} status undetermined after ${maxRetries} retries`);
  return { status: "pending", txHash };
}

// Helper: Send usage fee transaction
const sendUsageFee = async (pemContent, walletAddress) => {
  // Check if there's already a pending transaction for this wallet
  const pendingTx = pendingUsageFeeTransactions.get(walletAddress);
  if (pendingTx) {
    try {
      // Check if the pending transaction has completed
      const status = await checkTransactionStatus(pendingTx.txHash);
      
      // If transaction succeeded, return the existing transaction hash
      if (status.status === "success") {
        pendingUsageFeeTransactions.delete(walletAddress); // Clean up the record
        return pendingTx.txHash;
      }
      
      // If transaction failed, continue with creating a new one
      if (status.status === "fail") {
        pendingUsageFeeTransactions.delete(walletAddress); // Clean up the failed transaction
      } else if (status.status === "pending") {
        // Transaction is still pending, return the existing hash
        // This prevents double charging for slow transactions
        return pendingTx.txHash;
      }
    } catch (error) {
      // If the transaction check fails for any reason, clear it and try again
      pendingUsageFeeTransactions.delete(walletAddress);
    }
  }

  const signer = UserSigner.fromPem(pemContent);
  const senderAddress = signer.getAddress();
  const receiverAddress = new Address(TREASURY_WALLET);

  const accountOnNetwork = await provider.getAccount(senderAddress);
  const nonce = accountOnNetwork.nonce;

  // Calculate dynamic fee
  const dynamicFeeAmount = await calculateDynamicUsageFee();

  const factoryConfig = new TransactionsFactoryConfig({ chainID: "1" });
  const factory = new TransferTransactionsFactory({ config: factoryConfig });

  const tx = factory.createTransactionForESDTTokenTransfer({
    sender: senderAddress,
    receiver: receiverAddress,
    tokenTransfers: [
      new TokenTransfer({
        token: new Token({ identifier: REWARD_TOKEN }),
        amount: BigInt(dynamicFeeAmount),
      }),
    ],
  });

  tx.nonce = nonce;
  tx.gasLimit = BigInt(500000);

  await signer.sign(tx);
  const txHash = await provider.sendTransaction(tx);
  
  // Store the pending transaction with timestamp
  pendingUsageFeeTransactions.set(walletAddress, {
    txHash: txHash.toString(),
    timestamp: Date.now()
  });

  // We'll do a minimal initial check with just a few retries to avoid holding up the API
  // Full status tracking happens through the pendingUsageFeeTransactions system
  const status = await checkTransactionStatus(txHash.toString(), 3, 1000);
  
  if (status.status === "success") {
    pendingUsageFeeTransactions.delete(walletAddress); // Clean up on success
  } else if (status.status === "fail") {
    pendingUsageFeeTransactions.delete(walletAddress); // Clean up on failure
    throw new Error('Usage fee transaction failed. Ensure sufficient REWARD tokens are available.');
  }
  // For pending status, leave in the map for future checks
  
  return txHash.toString();
};

// Periodic cleanup of old pending transactions (run every 30 minutes)
setInterval(() => {
  const now = Date.now();
  for (const [wallet, txData] of pendingUsageFeeTransactions.entries()) {
    // Remove transactions older than 1 hour (3600000 ms)
    if (now - txData.timestamp > 3600000) {
      pendingUsageFeeTransactions.delete(wallet);
    }
  }
}, 1800000); // 30 minutes

// Middleware: Handle usage fee
const handleUsageFee = async (req, res, next) => {
  try {
    const pemContent = getPemContent(req);
    const walletAddress = UserSigner.fromPem(pemContent).getAddress().toString();

    if (isWhitelisted(walletAddress)) {
      console.log(`Wallet ${walletAddress} is whitelisted. Skipping usage fee.`);
      return next();
    }

    const txHash = await sendUsageFee(pemContent, walletAddress);
    req.usageFeeHash = txHash;
    next();
  } catch (error) {
    console.error('Error processing usage fee:', error.message);
    res.status(400).json({ error: error.message });
  }
};

// Authorization Endpoint for Make.com
app.post('/authorization', (req, res) => {
  try {
    const token = req.headers.authorization;
    if (token === `Bearer ${SECURE_TOKEN}`) {
      return res.json({ message: "Authorization successful" });
    }
    return res.status(401).json({ error: "Unauthorized" });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

// Helper: Fetch WARP info using WarpLink (retaining direct detection for simplicity)
async function fetchWarpInfo(warpId) {
  const warpLink = new WarpLink(warpConfig);

  try {
    console.log(`Resolving ${warpId} directly with WarpLink...`);
    const result = await warpLink.detect(warpId);
    console.log(`WarpLink.detect result for ${warpId}:`, JSON.stringify(result, null, 2));
    if (!result.match || !result.warp) {
      throw new Error(`Could not resolve ${warpId}: warp not found`);
    }
    const warp = result.warp;
    console.log(`Raw warp object from WarpLink.detect:`, JSON.stringify(warp, null, 2));
    console.log(`Resolved ${warpId} to hash: ${warp.meta?.hash || 'unknown hash'}`);

    if (!warp || !Array.isArray(warp.actions) || warp.actions.length === 0) {
      throw new Error(`Invalid warp structure for ${warpId}: actions is missing or empty`);
    }

    return warp;
  } catch (error) {
    console.error(`Error resolving ${warpId}: ${error.message}`);
    throw error;
  }
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

// 2. POST /executeWarpWithInputs
// This endpoint executes a warp using inputs provided by Make.com via WarpLink, relying on WarpActionExecutor for scaling.
app.post('/executeWarpWithInputs', checkToken, handleUsageFee, async (req, res) => {
  try {
    console.log("Incoming /executeWarpWithInputs request received.");
    const { warpId, inputs } = req.body;
    if (!warpId) throw new Error("Missing warpId in request body");
    if (!inputs || typeof inputs !== 'object') throw new Error("Missing or invalid 'inputs' object in request body");

    // Extract PEM and signer details
    const pemContent = getPemContent(req);
    const signer = UserSigner.fromPem(pemContent);
    const userAddress = signer.getAddress();

    // Fetch warp info
    const warpInfo = await fetchWarpInfo(warpId);
    console.log("Fetched warp info.");

    const action = warpInfo.actions[0];
    if (!action || action.type !== 'contract') {
      throw new Error(`Warp ${warpId} must have a 'contract' action`);
    }
    if (!action.inputs || action.inputs.length === 0) {
      throw new Error(`Warp ${warpId} does not have input requirements; use /executeWarp instead`);
    }

    // Validate and prepare inputs dynamically, passing raw values to WarpActionExecutor
    const userInputsArray = [];
    for (const input of action.inputs) {
      const value = inputs[input.name];
      if (input.required && (value === undefined || value === null)) {
        throw new Error(`Missing required input: ${input.name}`);
      }
      if (value !== undefined) {
        let typedValue = value;
        const type = input.type.split(':')[0];
        
        // No manual scaling here—let WarpActionExecutor handle modifiers
        console.log(`Passing raw ${input.name} value to WarpActionExecutor`);

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
    console.log("Prepared user inputs for execution.");

    // Execute transaction, relying on WarpActionExecutor to handle scaling and modifiers
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
      finalStatus: status.status,
      usageFeeHash: req.usageFeeHash || 'N/A'
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
