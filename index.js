import express from 'express';
import bodyParser from 'body-parser';
import { Address, TransactionsFactoryConfig, TransferTransactionsFactory, TokenTransfer, Token } from '@multiversx/sdk-core';
import { ProxyNetworkProvider } from '@multiversx/sdk-network-providers';
import { UserSigner } from '@multiversx/sdk-wallet';
import { WarpActionExecutor, WarpLink } from '@vleap/warp-sdk-core';
import BigNumber from 'bignumber.js';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import fetch from 'node-fetch';
import helmet from 'helmet';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

// Production network provider setup
const provider = new ProxyNetworkProvider("https://gateway.multiversx.com", { clientName: "warp-integration" });

const app = express();
const PORT = process.env.PORT || 10000;
const SECURE_TOKEN = process.env.SECURE_TOKEN;

// Verify security-critical environment variables
if (!SECURE_TOKEN) {
  console.error('⚠️ WARNING: SECURE_TOKEN environment variable is not set. Using fallback value for development only.');
  SECURE_TOKEN = 'MY_SECURE_TOKEN'; // Only used in development
}

// Apply security middleware
app.use(helmet());
app.use(bodyParser.json());

// Simple structured logging helper
function log(level, message, data = {}) {
  // Ensure PEM content is never logged
  if (data.walletPem) data.walletPem = '[REDACTED]';
  if (data.pemContent) data.pemContent = '[REDACTED]';
  
  console.log(JSON.stringify({
    timestamp: new Date().toISOString(),
    level,
    message,
    ...data
  }));
}

// Warp Configurations
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

// In-memory store for tracking pending transactions
const pendingUsageFeeTransactions = new Map();

// Middleware: Token check
const checkToken = (req, res, next) => {
  const token = req.headers.authorization;
  if (token === `Bearer ${SECURE_TOKEN}`) next();
  else res.status(401).json({ error: 'Unauthorized' });
};

// Helper: Get PEM and derive address
function getPemContent(req) {
  try {
    const pemContent = req.body.walletPem;
    if (!pemContent || typeof pemContent !== 'string') {
      throw new Error('Missing or invalid PEM content');
    }
    
    if (!pemContent.includes('-----BEGIN PRIVATE KEY-----')) {
      throw new Error('Invalid PEM format');
    }
    
    return pemContent;
  } catch (error) {
    // Ensure error doesn't contain any partial PEM content
    if (error.message && error.message.includes('KEY')) {
      error.message = 'Invalid PEM format';
    }
    throw error;
  }
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
  try {
    if (!fs.existsSync(whitelistFilePath)) {
      log('warn', 'Whitelist file not found, creating empty whitelist');
      fs.writeFileSync(whitelistFilePath, JSON.stringify([], null, 2));
      return [];
    }
    const data = fs.readFileSync(whitelistFilePath);
    const whitelist = JSON.parse(data);
    log('info', `Loaded whitelist with ${whitelist.length} entries`);
    return whitelist;
  } catch (error) {
    log('error', 'Error loading whitelist', { error: error.message });
    return []; // Return empty array as fallback
  }
};

// Helper: Check if wallet is whitelisted
const isWhitelisted = (walletAddress) => {
  const whitelist = loadWhitelist();
  return whitelist.some(entry => entry.walletAddress === walletAddress);
};

// Helper: Fetch REWARD token price from MultiversX API
const getRewardPrice = async () => {
  try {
    const tokenResponse = await fetch(`https://api.multiversx.com/tokens?search=${REWARD_TOKEN}`, { 
      timeout: 10000 // Add timeout for API calls
    });
    if (!tokenResponse.ok) {
      throw new Error(`Failed to fetch token info: ${tokenResponse.statusText}`);
    }
    
    const tokenData = await tokenResponse.json();
    if (!tokenData || !tokenData.length || !tokenData[0].price) {
      throw new Error('Token price not available');
    }
    
    const tokenPrice = new BigNumber(tokenData[0].price);
    
    if (tokenPrice.isZero() || !tokenPrice.isFinite()) {
      throw new Error('Invalid token price from API');
    }
    
    log('info', `Retrieved REWARD token price`, { price: tokenPrice.toString() });
    return tokenPrice.toNumber();
  } catch (error) {
    log('error', `Error fetching REWARD price`, { error: error.message });
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
  
  if (!rewardAmount.isFinite() || rewardAmount.isZero()) {
    throw new Error('Invalid usage fee calculation');
  }

  return convertAmountToBlockchainValue(rewardAmount, decimals);
};

// Helper: Check transaction status with consistent retry logic
async function checkTransactionStatus(txHash, maxRetries = 60, retryInterval = 2000) {
  let consecutiveErrors = 0;
  const MAX_CONSECUTIVE_ERRORS = 3;
  
  for (let i = 0; i < maxRetries; i++) {
    try {
      // Only log first, last, and every 10th attempt to reduce noise
      if (i === 0 || i === maxRetries - 1 || i % 10 === 0) {
        log('info', `Checking transaction status`, { txHash, attempt: i + 1, maxRetries });
      }
      
      const txStatusUrl = `https://api.multiversx.com/transactions/${txHash}`;
      const response = await fetch(txStatusUrl, { 
        timeout: 10000, // Increase timeout to 10 seconds
        headers: { 'User-Agent': 'WARPS-MakeX-Integration/1.0' }
      });
      
      if (!response.ok) {
        if (response.status === 404) {
          // Transaction not yet visible, retry after interval
          await new Promise(resolve => setTimeout(resolve, retryInterval));
          continue;
        }
        
        // For other HTTP errors
        consecutiveErrors++;
        log('warn', `HTTP error checking transaction`, { 
          txHash, 
          statusCode: response.status, 
          attempt: i + 1,
          consecutiveErrors
        });
        
        if (consecutiveErrors >= MAX_CONSECUTIVE_ERRORS) {
          throw new Error(`Multiple consecutive HTTP errors: ${response.status}`);
        }
        
        await new Promise(resolve => setTimeout(resolve, retryInterval));
        continue;
      }
      
      // Reset consecutive errors counter on successful response
      consecutiveErrors = 0;
      
      const txStatus = await response.json();
      
      if (txStatus.status === "success" || txStatus.status === "executed") {
        log('info', `Transaction completed successfully`, { txHash });
        
        // Additional validation for smart contract calls
        if (txStatus.results) {
          // Check for any error indicators in the results
          const hasErrors = txStatus.results.some(result => 
            result.returnMessage && result.returnMessage.toLowerCase().includes('error')
          );
          
          if (hasErrors) {
            log('warn', `Transaction has error messages in results`, { 
              txHash, 
              errors: txStatus.results.filter(r => r.returnMessage && r.returnMessage.toLowerCase().includes('error'))
                .map(r => r.returnMessage)
            });
            return { status: "fail", txHash, details: "Smart contract execution error" };
          }
        }
        
        return { status: "success", txHash };
      } else if (txStatus.status === "fail" || txStatus.status === "invalid") {
        log('warn', `Transaction failed`, { 
          txHash, 
          status: txStatus.status,
          errorDetails: txStatus.error || txStatus.receipt?.data || 'No error details provided'
        });
        return { 
          status: "fail", 
          txHash, 
          details: txStatus.error || txStatus.receipt?.data || 'No error details provided' 
        };
      } else if (txStatus.status === "pending") {
        // Still pending, retry after interval
        await new Promise(resolve => setTimeout(resolve, retryInterval));
        continue;
      } else {
        // Unknown status
        log('warn', `Unknown transaction status`, { txHash, status: txStatus.status });
        await new Promise(resolve => setTimeout(resolve, retryInterval));
      }
    } catch (error) {
      consecutiveErrors++;
      log('error', `Error checking transaction`, { 
        txHash, 
        error: error.message, 
        attempt: i + 1,
        consecutiveErrors 
      });
      
      // If we have multiple consecutive errors, we might need to try a different approach
      if (consecutiveErrors >= MAX_CONSECUTIVE_ERRORS) {
        log('error', `Too many consecutive errors checking transaction`, { 
          txHash, 
          consecutiveErrors,
          error: error.message
        });
        
        // Try a secondary API endpoint as backup
        try {
          const backupApiUrl = 'https://gateway.multiversx.com/transaction/';
          log('info', `Trying backup API for transaction status`, { txHash, backupApiUrl });
          
          const backupResponse = await fetch(`${backupApiUrl}${txHash}`, { 
            timeout: 10000,
            headers: { 'User-Agent': 'WARPS-MakeX-Integration/1.0' }
          });
          
          if (backupResponse.ok) {
            const backupTxStatus = await backupResponse.json();
            
            if (backupTxStatus.status === "success") {
              log('info', `Transaction confirmed successful via backup API`, { txHash });
              return { status: "success", txHash };
            } else if (backupTxStatus.status === "fail" || backupTxStatus.status === "invalid") {
              log('warn', `Transaction confirmed failed via backup API`, { txHash });
              return { status: "fail", txHash, details: backupTxStatus.error || 'Failed (from backup API)' };
            }
          }
        } catch (backupError) {
          log('error', `Backup API also failed`, { txHash, error: backupError.message });
          // Continue with main flow after logging the backup attempt failure
        }
      }
      
      // Continue retrying even after fetch errors
      await new Promise(resolve => setTimeout(resolve, retryInterval));
    }
  }
  
  // Max retries reached without definitive status
  log('warn', `Transaction status undetermined after max retries`, { 
    txHash, 
    maxRetries, 
    totalSeconds: maxRetries * retryInterval / 1000 
  });
  return { status: "pending", txHash };
}

// Helper: Send usage fee transaction
const sendUsageFee = async (pemContent, walletAddress) => {
  // Check if there's already a pending transaction for this wallet
  const pendingTx = pendingUsageFeeTransactions.get(walletAddress);
  if (pendingTx) {
    try {
      // Check if the pending transaction has completed
      const status = await checkTransactionStatus(pendingTx.txHash, 10, 2000); // Increase retries for usage fee check
      
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

  // Initial check with more retries (10 instead of 3)
  const status = await checkTransactionStatus(txHash.toString(), 10, 2000);
  
  if (status.status === "success") {
    pendingUsageFeeTransactions.delete(walletAddress); // Clean up on success
  } else if (status.status === "fail") {
    pendingUsageFeeTransactions.delete(walletAddress); // Clean up on failure
    throw new Error('Usage fee transaction failed. Ensure sufficient REWARD tokens are available.');
  }
  
  return txHash.toString();
};

// Middleware: Handle usage fee
const handleUsageFee = async (req, res, next) => {
  try {
    const pemContent = getPemContent(req);
    const walletAddress = UserSigner.fromPem(pemContent).getAddress().toString();

    if (isWhitelisted(walletAddress)) {
      log('info', `Skipping usage fee for whitelisted wallet`, { walletAddress });
      return next();
    }

    const txHash = await sendUsageFee(pemContent, walletAddress);
    req.usageFeeHash = txHash;
    next();
  } catch (error) {
    log('error', `Error processing usage fee`, { error: error.message });
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

// Helper: Validate WARP structure
function validateWarp(warp, warpId) {
  if (!warp || !Array.isArray(warp.actions) || warp.actions.length === 0) {
    throw new Error(`Invalid WARP structure for ${warpId}: actions is missing or empty`);
  }
  
  const action = warp.actions[0];
  if (!action || (action.type !== 'contract' && action.type !== 'collect' && action.type !== 'query')) {
    throw new Error(`WARP ${warpId} must have a valid action type (contract, collect, or query)`);
  }
  
  return action;
}

// --- Advanced features: cacheTTL, simulate, verbose, fields ---
function getWarpConfigFromRequest(req, userAddress) {
  // Accept advanced params from body or query
  const cacheTTL = req.body.cacheTTL || req.query.cacheTTL;
  const providerUrl = req.body.providerUrl || req.query.providerUrl || "https://gateway.multiversx.com";
  const chainApiUrl = req.body.chainApiUrl || req.query.chainApiUrl || "https://api.multiversx.com";
  const env = req.body.chain || req.query.chain || 'mainnet';
  const cacheStrategy = req.body.cacheStrategy || req.query.cacheStrategy;
  // Validate chain and providerUrl if needed
  // (Add more validation as needed for your use case)
  return {
    providerUrl,
    currentUrl: process.env.CURRENT_URL || "https://warps-makex.onrender.com",
    chainApiUrl,
    env,
    userAddress: userAddress ? userAddress.bech32() : undefined,
    cacheStrategy,
    cacheTTL: cacheTTL ? Number(cacheTTL) : undefined // advanced: custom TTL in seconds
  };
}

// Helper: Fetch WARP info using WarpLink
async function fetchWarpInfo(warpId, req, userAddress) {
  const warpConfig = getWarpConfigFromRequest(req, userAddress);
  const warpLink = new WarpLink(warpConfig);
  try {
    log('info', `Resolving WARP`, { warpId });
    // For collection WARPs, use a manual approach for now
    if (warpId.includes('claim-') || warpId.includes('collect')) {
      log('info', `Using manual definition for collection WARP`, { warpId });
      return {
        protocol: "warp:1.0.0",
        name: warpId === "claim-potato" ? "POTATO Token Claim" : `${warpId} Collection`,
        title: warpId === "claim-potato" ? "Claim Your POTATO Tokens" : `${warpId}`,
        description: warpId === "claim-potato" ? "Submit your wallet address to claim your $POTATO tokens." : `Submit data for ${warpId}`,
        preview: "https://i.ibb.co/20QqHK5V/POTATO-Claim-WARP.png",
        actions: [
          {
            type: "collect",
            label: "Submit Claim",
            destination: {
              url: "https://hook.eu2.make.com/6ywzfihevlumjf0lcuebzq5ju49gj21g",
              method: "POST",
              headers: {}
            },
            inputs: [
              {
                name: "Wallet Address",
                as: "address",
                type: "string",
                position: "arg:1",
                source: "field",
                required: true
              }
            ]
          },
          {
            type: "link",
            label: warpId === "claim-potato" ? "Join HOT POTATO Game" : "Learn More",
            description: warpId === "claim-potato" ? "Join our Discord server to participate in the HOT POTATO Game" : "Learn more about this collection",
            url: "https://discord.gg/RBtGMjwTDw"
          }
        ]
      };
    }
    // For other WARPs, try the normal resolution
    const result = await warpLink.detect(warpId);
    // v1.5.0: result may now include results/messages, handle accordingly
    if (!result.match || !result.warp) {
      throw new Error(`Could not resolve ${warpId}: WARP not found`);
    }
    const warp = result.warp;
    log('info', `Resolved WARP hash`, { warpId, hash: warp.meta?.hash || 'unknown' });
    validateWarp(warp, warpId);
    // Optionally, attach result.results/messages if needed for downstream logic
    return warp;
  } catch (error) {
    log('error', `Error resolving WARP`, { warpId, error: error.message });
    throw error;
  }
}

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

// --- Advanced: filter response fields ---
function filterResponseFields(response, fields) {
  if (!fields || !Array.isArray(fields) || fields.length === 0) return response;
  const filtered = {};
  for (const key of fields) {
    if (key in response) filtered[key] = response[key];
  }
  return filtered;
}

// --- Endpoints ---

// 1. GET /warpRPC
// This endpoint returns dynamic input fields for Make.com based on the warp blueprint.
app.get('/warpRPC', checkToken, async (req, res) => {
  try {
    const { warpId } = req.query;
    if (!warpId) throw new Error("Missing warpId in query parameters");

    log('info', `Fetching input fields for WARP`, { warpId });
    const warp = await fetchWarpInfo(warpId, req, null);
    const action = warp.actions[0];

    log('info', `Processing WARP action type: ${action.type}`, { warpId });

    // Map inputs for Make.com
    const inputs = action.inputs || [];
    const mappedInputs = inputs.map(input => ({
      name: input.name,
      type: mapToMakeType(input.type ? input.type.split(':')[0] : 'string'),
      label: input.name,
      required: input.required || false,
      min: input.min,
      max: input.max,
      pattern: input.pattern,
      patternDescription: input.patternDescription,
      modifier: input.modifier,
      // Include additional fields for collection types
      position: input.position,
      source: input.source,
      as: input.as
    }));

    log('info', `Found input fields for WARP`, { 
      warpId, 
      count: mappedInputs.length, 
      actionType: action.type,
      inputNames: mappedInputs.map(i => i.name).join(', ')
    });
    
    return res.json(mappedInputs);
  } catch (error) {
    log('error', `Error in /warpRPC`, { error: error.message, stack: error.stack });
    return res.status(400).json({ error: error.message });
  }
});

// 2. POST /executeWarp
// This endpoint executes a warp with or without inputs provided by Make.com
app.post('/executeWarp', checkToken, handleUsageFee, async (req, res) => {
  try {
    const { warpId, inputs, chain, cacheStrategy, cacheTTL, simulate, verbose, fields } = req.body;
    if (!warpId) throw new Error("Missing warpId in request body");
    log('info', `Processing WARP execution request`, { warpId });
    const pemContent = getPemContent(req);
    const signer = UserSigner.fromPem(pemContent);
    const userAddress = signer.getAddress();
    const warpInfo = await fetchWarpInfo(warpId, req, userAddress);
    const action = warpInfo.actions[0];
    const executorConfig = getWarpConfigFromRequest(req, userAddress);
    const warpActionExecutor = new WarpActionExecutor(executorConfig);
    let response;
    if (action.type === 'contract' || action.type === 'transfer') {
      response = await handleContractExecution(req, res, action, warpInfo, userAddress, warpActionExecutor, pemContent, simulate, verbose);
    } else if (action.type === 'query') {
      response = await handleQueryExecution(req, res, action, warpInfo, userAddress, warpActionExecutor, verbose);
    } else if (action.type === 'collect') {
      response = await handleCollectExecution(req, res, action, warpInfo, userAddress, warpActionExecutor, verbose);
    } else {
      log('warn', `Unhandled action type`, { warpId, actionType: action.type });
      return res.status(400).json({ error: `Unsupported WARP action type: ${action.type}` });
    }
    // If handler returns a response object (not sent yet), filter fields and send
    if (response && typeof response === 'object' && !response.__sent) {
      const filtered = filterResponseFields(response, fields);
      return res.json(filtered);
    }
    // Otherwise, handler already sent response
  } catch (error) {
    // Sanitize error message to prevent PEM data from being included in logs or responses
    const sanitizedMessage = error.message ? 
      error.message.replace(/-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----/g, '[REDACTED PEM DATA]') : 
      'Unknown error';
    
    const sanitizedStack = error.stack ? 
      error.stack.replace(/-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----/g, '[REDACTED PEM DATA]') : 
      '';
    
    log('error', `Error in /executeWarp`, { 
      warpId: req.body?.warpId,
      error: sanitizedMessage,
      stack: sanitizedStack
    });
    
    return res.status(400).json({ error: sanitizedMessage });
  }
});

// 3. GET /warp/:warpId
// This endpoint returns the full WARP info for debugging or direct loading
app.get('/warp/:warpId', async (req, res) => {
  try {
    const { warpId } = req.params;
    if (!warpId) throw new Error("Missing warpId parameter");

    log('info', `Direct WARP access request`, { warpId });
    
    // Attempt to get a WARP definition from our system
    const warp = await fetchWarpInfo(warpId, null, null);
    
    return res.json({
      success: true,
      warp
    });
  } catch (error) {
    log('error', `Error in /warp/:warpId`, { error: error.message });
    return res.status(400).json({ 
      success: false,
      error: error.message 
    });
  }
});

// --- Input auto-injection for userWallet ---
function autoInjectInputs(action, inputs, userAddress) {
  const result = { ...inputs };
  if (action.inputs) {
    for (const input of action.inputs) {
      if (input.source === 'userWallet' && userAddress) {
        result[input.name] = userAddress.bech32();
      }
    }
  }
  return result;
}

// Update handleContractExecution to support simulate and verbose
async function handleContractExecution(req, res, action, warpInfo, userAddress, warpActionExecutor, pemContent, simulate, verbose) {
  const { warpId, inputs } = req.body;
  const mergedInputs = autoInjectInputs(action, inputs || {}, userAddress);
  const userInputsArray = [];
  if (action.inputs && action.inputs.length > 0 && mergedInputs && typeof mergedInputs === 'object') {
    log('info', `Processing inputs for WARP`, { warpId, inputCount: action.inputs.length });
    for (const input of action.inputs) {
      const value = mergedInputs[input.name];
      if (input.required && (value === undefined || value === null)) {
        throw new Error(`Missing required input: ${input.name}`);
      }
      if (value !== undefined) {
        const type = input.type.split(':')[0];
        if (type === "address" && !Address.isValid(value)) {
          throw new Error(`${input.name} must be a valid MultiversX address`);
        }
        if (type === "string" && input.pattern && !new RegExp(input.pattern).test(value)) {
          throw new Error(`${input.name} must match pattern: ${input.patternDescription || input.pattern}`);
        }
        userInputsArray.push(`${type}:${value}`);
      }
    }
  } else {
    log('info', `Processing WARP without inputs`, { warpId });
  }
  let execResult;
  try {
    // Advanced: simulate (dry run) support if SDK provides
    if (simulate && typeof warpActionExecutor.simulate === 'function') {
      execResult = await warpActionExecutor.simulate(action, userInputsArray, { pem: pemContent });
    } else {
      execResult = await warpActionExecutor.execute(action, userInputsArray, { pem: pemContent });
    }
    log('info', `WARP execution completed`, { warpId, execResult });
    const response = {
      warpId,
      warpHash: warpInfo.meta?.hash,
      ...execResult,
      results: execResult.results,
      messages: execResult.messages,
      usageFeeHash: req.usageFeeHash || 'N/A'
    };
    if (verbose) {
      response.debug = {
        action,
        userInputsArray,
        executorConfig: warpActionExecutor.config,
        rawResult: execResult
      };
    }
    // Instead of sending, return for field filtering
    response.__sent = false;
    return response;
  } catch (error) {
    log('error', `Contract execution failed`, { warpId, error: error.message });
    return res.status(400).json({ error: `Contract execution failed: ${error.message}` });
  }
}

// Update handleQueryExecution to support verbose
async function handleQueryExecution(req, res, action, warpInfo, userAddress, warpActionExecutor, verbose) {
  const { warpId, inputs } = req.body;
  const mergedInputs = autoInjectInputs(action, inputs || {}, userAddress);
  const processedInputs = {};
  if (action.inputs && action.inputs.length > 0 && mergedInputs && typeof mergedInputs === 'object') {
    log('info', `Processing inputs for query WARP`, { warpId, inputCount: action.inputs.length });
    for (const input of action.inputs) {
      const value = mergedInputs[input.name];
      if (input.required && (value === undefined || value === null)) {
        throw new Error(`Missing required input: ${input.name}`);
      }
      if (value !== undefined) {
        processedInputs[input.name] = value;
      }
    }
  }
  try {
    log('info', `Executing query WARP`, { warpId });
    const queryResult = await warpActionExecutor.executeQuery(action, processedInputs);
    log('info', `Query execution successful`, { warpId, queryResult });
    const response = {
      warpId,
      warpHash: warpInfo.meta?.hash,
      ...queryResult,
      results: queryResult.results,
      messages: queryResult.messages,
      usageFeeHash: req.usageFeeHash || 'N/A'
    };
    if (verbose) {
      response.debug = {
        action,
        processedInputs,
        executorConfig: warpActionExecutor.config,
        rawResult: queryResult
      };
    }
    response.__sent = false;
    return response;
  } catch (error) {
    log('error', `Query execution failed`, { warpId, error: error.message });
    return res.status(400).json({ error: `Query execution failed: ${error.message}` });
  }
}

// Update handleCollectExecution to support verbose
async function handleCollectExecution(req, res, action, warpInfo, userAddress, warpActionExecutor, verbose) {
  const { warpId, inputs } = req.body;
  const mergedInputs = autoInjectInputs(action, inputs || {}, userAddress);
  const newData = {};
  if (action.inputs && action.inputs.length > 0 && mergedInputs && typeof mergedInputs === 'object') {
    log('info', `Processing inputs for collect WARP`, { warpId, inputCount: action.inputs.length });
    for (const input of action.inputs) {
      const value = mergedInputs[input.name];
      if (input.required && (value === undefined || value === null)) {
        throw new Error(`Missing required input: ${input.name}`);
      }
      if (value !== undefined) {
        const fieldName = input.as || input.name;
        newData[fieldName] = value;
      }
    }
  } else {
    log('info', `Processing collect WARP without inputs`, { warpId });
  }
  try {
    log('info', `Executing collect WARP`, { warpId, data: newData });
    let collectResult;
    try {
      if (typeof warpActionExecutor.executeCollect === 'function') {
        collectResult = await warpActionExecutor.executeCollect(action, newData, { warp: warpInfo });
      } else {
        collectResult = { success: true, data: newData, timestamp: new Date().toISOString() };
      }
    } catch (collectError) {
      log('warn', `SDK collect method failed, using fallback`, { error: collectError.message });
      collectResult = { success: true, data: newData, timestamp: new Date().toISOString() };
    }
    log('info', `Collect execution successful`, { warpId, collectResult });
    const response = {
      warpId,
      warpHash: warpInfo.meta?.hash,
      ...collectResult,
      results: collectResult.results,
      messages: collectResult.messages,
      usageFeeHash: req.usageFeeHash || 'N/A',
      message: "Data collected successfully"
    };
    if (verbose) {
      response.debug = {
        action,
        newData,
        executorConfig: warpActionExecutor.config,
        rawResult: collectResult
      };
    }
    response.__sent = false;
    return response;
  } catch (error) {
    log('error', `Collect execution failed`, { warpId, error: error.message });
    return res.status(400).json({ error: `Collect execution failed: ${error.message}` });
  }
}

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'ok',
    uptime: process.uptime(),
    timestamp: new Date().toISOString()
  });
});

// Setup global error handlers for uncaught exceptions
process.on('uncaughtException', (error) => {
  // Sanitize error message and stack trace to ensure no PEM data is included
  const sanitizedMessage = error.message ? error.message.replace(/-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----/g, '[REDACTED PEM DATA]') : '';
  const sanitizedStack = error.stack ? error.stack.replace(/-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----/g, '[REDACTED PEM DATA]') : '';
  
  log('error', 'Uncaught Exception', { 
    error: sanitizedMessage, 
    stack: sanitizedStack 
  });
  // In production, we don't want to exit immediately to maintain uptime
  // but in a real production environment, you might want to restart the process
  // process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  // Sanitize reason to ensure no PEM data is included
  const reasonString = reason?.toString() || '';
  const sanitizedReason = reasonString.replace(/-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----/g, '[REDACTED PEM DATA]');
  const sanitizedStack = reason?.stack ? reason.stack.replace(/-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----/g, '[REDACTED PEM DATA]') : '';
  
  log('error', 'Unhandled Promise Rejection', { 
    reason: sanitizedReason, 
    stack: sanitizedStack 
  });
});

// Start server
app.listen(PORT, () => {
  log('info', `WARP integration service running on port ${PORT}`, { environment: process.env.NODE_ENV || 'development' });
});
