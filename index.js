import express from 'express';
import bodyParser from 'body-parser';
import { Address, TransactionsFactoryConfig, TransferTransactionsFactory, TokenTransfer, Token, ProxyNetworkProvider, UserSigner, TransactionComputer, Transaction } from '@multiversx/sdk-core';
import { WarpClient, WarpChainName } from '@joai/warps';
import { getAllMultiversxAdapters, MultiversxAdapter } from '@joai/warps-adapter-multiversx';
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

// Request timeout middleware (120 seconds for long-running transactions)
app.use((req, res, next) => {
  const timeout = 120000; // 2 minutes
  req.setTimeout(timeout, () => {
    if (!res.headersSent) {
      log('warn', 'Request timeout', { 
        path: req.path, 
        method: req.method,
        timeout 
      });
      res.status(408).json({ error: 'Request timeout' });
    }
  });
  next();
});

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

// Warp Client Configuration - V3
// Note: WarpClient instances are created per-request with user wallet configuration
// The MultiversX adapter handles wallet operations through the configured provider

// Constants for usage fee
const FIXED_USD_FEE = 0.03; // $0.03 fixed fee
const REWARD_TOKEN = "REWARD-cf6eac";
const TREASURY_WALLET = "erd1t2r97zcjg8uvf0e9nk4psj2kvg27mph9kq5xls6xtnyg2aemp8hszcmn8f";
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const whitelistFilePath = path.join(__dirname, 'whitelist.json');

// In-memory store for tracking pending transactions
const pendingUsageFeeTransactions = new Map();

// Removed active requests tracking for debugging

// Rate limiter for API calls (2 requests per second max)
let lastApiCall = 0;
const API_RATE_LIMIT = 500; // 500ms between calls = 2 per second

// Helper: Rate-limited API call
async function rateLimitedApiCall(url, options = {}) {
  const now = Date.now();
  const timeSinceLastCall = now - lastApiCall;
  
  if (timeSinceLastCall < API_RATE_LIMIT) {
    const delay = API_RATE_LIMIT - timeSinceLastCall;
    await new Promise(resolve => setTimeout(resolve, delay));
  }
  
  lastApiCall = Date.now();
  return fetch(url, options);
}

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
  const response = await rateLimitedApiCall(apiUrl);
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
    const tokenResponse = await rateLimitedApiCall(`https://api.multiversx.com/tokens?search=${REWARD_TOKEN}`, { 
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

// Helper: Check transaction status with improved error detection and rate limiting
async function checkTransactionStatus(txHash, maxRetries = 30, retryInterval = 2000) {
  let consecutiveErrors = 0;
  const MAX_CONSECUTIVE_ERRORS = 3;
  
  // Rate limiting: respect 2tx/second limit
  const rateLimitDelay = 500; // 500ms between requests = 2 requests per second
  
  for (let i = 0; i < maxRetries; i++) {
    try {
      // Only log first, last, and every 5th attempt to reduce noise
      if (i === 0 || i === maxRetries - 1 || i % 5 === 0) {
        log('info', `Checking transaction status`, { txHash, attempt: i + 1, maxRetries });
      }
      
      // Rate limiting delay
      if (i > 0) {
        await new Promise(resolve => setTimeout(resolve, rateLimitDelay));
      }
      
      const txStatusUrl = `https://api.multiversx.com/transactions/${txHash}`;
      const response = await rateLimitedApiCall(txStatusUrl, { 
        timeout: 10000,
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
      
      // Check for failed transactions first
      if (txStatus.status === "fail" || txStatus.status === "invalid") {
        // Extract error details from operations array
        let errorMessage = 'Transaction failed';
        if (txStatus.operations && txStatus.operations.length > 0) {
          const errorOp = txStatus.operations.find(op => op.action === 'signalError' || op.type === 'error');
          if (errorOp && errorOp.message) {
            errorMessage = errorOp.message;
          } else if (errorOp && errorOp.data) {
            // Decode base64 error message
            try {
              errorMessage = Buffer.from(errorOp.data, 'base64').toString('utf8');
            } catch (e) {
              errorMessage = errorOp.data;
            }
          }
        }
        
        log('warn', `Transaction failed`, { 
          txHash, 
          status: txStatus.status,
          errorMessage,
          operations: txStatus.operations?.length || 0
        });
        
        return { 
          status: "fail", 
          txHash, 
          details: errorMessage
        };
      }
      
      // Check for successful transactions
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
      }
      
      // Handle pending status
      if (txStatus.status === "pending") {
        // Still pending, retry after interval
        await new Promise(resolve => setTimeout(resolve, retryInterval));
        continue;
      }
      
      // Unknown status
      log('warn', `Unknown transaction status`, { txHash, status: txStatus.status });
      await new Promise(resolve => setTimeout(resolve, retryInterval));
      
    } catch (error) {
      consecutiveErrors++;
      log('error', `Error checking transaction`, { 
        txHash, 
        error: error.message, 
        attempt: i + 1,
        consecutiveErrors 
      });
      
      // If we have multiple consecutive errors, try backup API
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
          
          const backupResponse = await rateLimitedApiCall(`${backupApiUrl}${txHash}`, { 
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
      const status = await checkTransactionStatus(pendingTx.txHash, 5, 2000); // Reduced retries for usage fee check
      
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

  // Validate REWARD_TOKEN format
  if (!REWARD_TOKEN || typeof REWARD_TOKEN !== 'string') {
    throw new Error(`Invalid REWARD_TOKEN: ${REWARD_TOKEN}`);
  }
  
  // Log token validation
  log('info', 'REWARD_TOKEN validation', {
    token: REWARD_TOKEN,
    length: REWARD_TOKEN.length,
    isValid: REWARD_TOKEN.length > 0
  });

  // Updated for MultiversX SDK v15+ - use the new transaction creation API
  const factoryConfig = new TransactionsFactoryConfig({ chainID: "1" });
  const factory = new TransferTransactionsFactory({ config: factoryConfig });

  // Create the transaction using the updated API for SDK v15+
  let tx;
  
  // First, let's log what methods are available on the factory
  const availableMethods = Object.getOwnPropertyNames(Object.getPrototypeOf(factory))
    .filter(name => name.startsWith('createTransaction'));
  
  log('info', 'Available transaction creation methods', { 
    availableMethods,
    factoryType: factory.constructor.name,
    sdkVersion: 'v15+',
    factoryKeys: Object.keys(factory),
    factoryPrototypeKeys: Object.getOwnPropertyNames(Object.getPrototypeOf(factory))
  });
  
  // Test if the factory is working by checking its basic properties
  if (!factory || typeof factory !== 'object') {
    throw new Error(`Factory is not a valid object: ${typeof factory}`);
  }
  
  log('info', 'Factory validation passed', {
    factoryExists: !!factory,
    factoryType: typeof factory,
    factoryConstructor: factory.constructor.name
  });
  
  // Since all SDK methods are failing consistently, go directly to manual transaction creation
  log('info', 'SDK methods are not working, using manual transaction creation', {
    reason: 'All factory methods fail with SDK v15+ compatibility issues'
  });
  
  // Create transaction manually - this is the working method
  try {
    log('info', 'Creating manual ESDT transfer transaction', { 
      sender: senderAddress.toString(),
      receiver: receiverAddress.toString(),
      token: REWARD_TOKEN,
      amount: dynamicFeeAmount,
      sdkVersion: 'v15+'
    });
    
    // IMPORTANT: Based on the correct example, the entire REWARD-cf6eac should be converted to hex
    // Correct format: ESDTTransfer@5245574152442d636636656163@04690c7e4f
    // Where 5245574152442d636636656163 = REWARD-cf6eac in hex
    let tokenIdentifierHex;
    
    if (REWARD_TOKEN === 'REWARD-cf6eac') {
      // Use the known correct hex encoding for REWARD-cf6eac
      tokenIdentifierHex = '5245574152442d636636656163';
      log('info', 'Using known correct hex encoding for REWARD-cf6eac', { 
        originalToken: REWARD_TOKEN,
        correctHex: tokenIdentifierHex
      });
    } else {
      // For other tokens, convert to hex
      tokenIdentifierHex = Buffer.from(REWARD_TOKEN, 'utf8').toString('hex');
      log('info', 'Converted token identifier to hex', { 
        originalToken: REWARD_TOKEN, 
        tokenHex: tokenIdentifierHex 
      });
    }
    
    // Ensure the amount hex has an even number of characters
    let amountHex = BigInt(dynamicFeeAmount).toString(16);
    if (amountHex.length % 2 !== 0) {
      // Pad with leading zero to make it even
      amountHex = '0' + amountHex;
      log('info', 'Padded amount hex to ensure even length', { 
        originalHex: BigInt(dynamicFeeAmount).toString(16),
        paddedHex: amountHex 
      });
    }
    
    log('info', 'Manual transaction encoding details', {
      originalToken: REWARD_TOKEN,
      tokenHex: tokenIdentifierHex,
      amount: dynamicFeeAmount,
      amountHex: amountHex,
      amountHexLength: amountHex.length,
      isEvenLength: amountHex.length % 2 === 0
    });
    
    tx = new Transaction({
      sender: senderAddress,
      receiver: receiverAddress,
      value: BigInt(0), // ESDT transfers have 0 EGLD value
      data: `ESDTTransfer@${tokenIdentifierHex}@${amountHex}`,
      gasLimit: BigInt(500000),
      chainID: "1"
    });
    
    log('info', 'Manual transaction creation successful');
    
  } catch (error) {
    log('error', 'Manual transaction creation failed', { 
      error: error.message,
      sdkVersion: 'v15+',
      factoryType: factory.constructor.name,
      availableMethods
    });
    
    // Provide detailed error information
    throw new Error(`Failed to create transaction: Manual creation failed. Error: ${error.message}. Please check MultiversX SDK v15+ compatibility.`);
  }

  // Verify transaction was created successfully
  if (!tx) {
    throw new Error('Transaction creation failed: SDK returned undefined transaction object');
  }

  // Final validation: ensure the transaction has the required properties
  if (!tx.sender || !tx.receiver) {
    log('error', 'Transaction validation failed - missing required properties', {
      hasSender: !!tx.sender,
      hasReceiver: !!tx.receiver,
      transactionType: tx.constructor.name,
      transactionKeys: Object.keys(tx)
    });
    throw new Error('Transaction creation failed: Transaction object missing required properties (sender, receiver)');
  }

  // Log successful transaction creation
  log('info', 'Transaction creation successful', {
    method: 'Manual transaction creation',
    transactionType: tx.constructor.name,
    hasSender: !!tx.sender,
    hasReceiver: !!tx.receiver,
    hasValue: !!tx.value,
    hasData: !!tx.data,
    hasNonce: !!tx.nonce,
    hasGasLimit: !!tx.gasLimit
  });

  tx.nonce = nonce;
  tx.gasLimit = BigInt(500000);

  tx.signature = await signer.sign(new TransactionComputer().computeBytesForSigning(tx));
  let txHash;
  try {
    txHash = await provider.sendTransaction(tx);
  } catch (err) {
    throw new Error('Failed to send transaction: ' + err.message);
  }
  if (!txHash) {
    throw new Error('Transaction hash is undefined after sending transaction.');
  }
  
  // Store the pending transaction with timestamp
  pendingUsageFeeTransactions.set(walletAddress, {
    txHash: txHash.toString(),
    timestamp: Date.now()
  });

  // Initial check with reduced retries
  const status = await checkTransactionStatus(txHash.toString(), 5, 2000);
  
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
// V3: Get WarpClient configuration from request
function getWarpClientConfig(req, userAddress, pemContent) {
  // Accept advanced params from body or query
  const env = req.body.chain || req.query.chain || 'mainnet';
  
  // Get wallet address string - handle both old and new SDK versions
  let walletAddress;
  if (userAddress) {
    try {
      // Try the new SDK v15+ method first
      if (typeof userAddress.toString === 'function') {
        walletAddress = userAddress.toString();
      } else if (typeof userAddress.bech32 === 'function') {
        walletAddress = userAddress.bech32();
      } else {
        // Fallback: try to get the address as a string
        walletAddress = String(userAddress);
      }
      log('info', 'Wallet address extracted successfully', { 
        method: 'SDK v15+ compatible',
        address: walletAddress,
        userAddressType: typeof userAddress,
        userAddressMethods: Object.getOwnPropertyNames(Object.getPrototypeOf(userAddress) || {})
      });
    } catch (error) {
      log('warn', 'Error extracting wallet address, using fallback', { error: error.message });
      walletAddress = String(userAddress);
    }
  }
  
  // V3 configuration structure
  const config = {
    env: env,
    currentUrl: process.env.CURRENT_URL || "https://warps-makex.onrender.com",
    user: {
      wallets: {
        multiversx: {
          address: walletAddress,
          provider: provider // Use the existing ProxyNetworkProvider
        }
      }
    }
  };
  
  return config;
}

// Helper: Fetch WARP info using WarpClient (V3)
async function fetchWarpInfo(warpId, req, userAddress, pemContent) {
  // Debug userAddress object
  if (userAddress) {
    log('info', 'UserAddress object details', {
      type: typeof userAddress,
      constructor: userAddress?.constructor?.name || 'Unknown',
      availableMethods: Object.getOwnPropertyNames(Object.getPrototypeOf(userAddress) || {}),
      hasToString: typeof userAddress.toString === 'function',
      hasBech32: typeof userAddress.bech32 === 'function',
      value: String(userAddress)
    });
  }
  
  // V3: Create WarpClient with proper configuration
  const config = getWarpClientConfig(req, userAddress, pemContent);
  const client = new WarpClient(config, {
    chains: getAllMultiversxAdapters()
  });
  
  try {
    log('info', `Resolving WARP`, { warpId });
    // V3: Use detectWarp method
    const warp = await client.detectWarp(warpId);
    if (!warp) {
      throw new Error(`Could not resolve ${warpId}: WARP not found`);
    }
    log('info', `Resolved WARP hash`, { warpId, hash: warp.meta?.hash || 'unknown' });
    validateWarp(warp, warpId);
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

// Utility function to safely serialize objects and prevent circular reference errors
function safeStringify(obj, maxDepth = 3) {
  const seen = new WeakSet();
  
  function safeSerialize(value, depth = 0) {
    if (depth > maxDepth) {
      return '[Max Depth Reached]';
    }
    
    if (value === null || value === undefined) {
      return value;
    }
    
    if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
      return value;
    }
    
    if (value instanceof Date) {
      return value.toISOString();
    }
    
    if (typeof value === 'function') {
      return '[Function]';
    }
    
    if (seen.has(value)) {
      return '[Circular Reference]';
    }
    
    if (Array.isArray(value)) {
      seen.add(value);
      const result = value.map(item => safeSerialize(item, depth + 1));
      seen.delete(value);
      return result;
    }
    
    if (typeof value === 'object') {
      seen.add(value);
      const result = {};
      for (const key in value) {
        if (value.hasOwnProperty(key)) {
          try {
            result[key] = safeSerialize(value[key], depth + 1);
          } catch (err) {
            result[key] = '[Serialization Error]';
          }
        }
      }
      seen.delete(value);
      return result;
    }
    
    return '[Unknown Type]';
  }
  
  try {
    return safeSerialize(obj);
  } catch (error) {
    return { error: 'Failed to serialize object', message: error.message };
  }
}

// --- Endpoints ---

// 1. GET /warpRPC
// This endpoint returns dynamic input fields for Make.com based on the warp blueprint.
app.get('/warpRPC', checkToken, async (req, res) => {
  try {
    const { warpId } = req.query;
    if (!warpId) throw new Error("Missing warpId in query parameters");

    log('info', `Fetching input fields for WARP`, { warpId });
    // V3: For read-only operations, we can use a minimal config without wallet
    const config = {
      env: req.query.chain || 'mainnet',
      currentUrl: process.env.CURRENT_URL || "https://warps-makex.onrender.com"
    };
    const client = new WarpClient(config, {
      chains: getAllMultiversxAdapters()
    });
    const warp = await client.detectWarp(warpId);
    if (!warp) {
      throw new Error(`Could not resolve ${warpId}: WARP not found`);
    }
    validateWarp(warp, warpId);
    const action = warp.actions[0];

    log('info', `Processing WARP action type: ${action.type}`, { warpId });

    // Map inputs for Make.com
    const inputs = action.inputs || [];
    const mappedInputs = inputs
      .filter(input => input.source === "field")
      .map(input => ({
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
// SUPPORTED WARP TYPES:
// - contract/transfer: Smart contract interactions and token transfers
// - query: Read-only blockchain data queries
// - collect: Data collection and storage operations
// 
// NOTE: All WARP types continue to work with the recent SDK v15+ compatibility fixes.
// The userAddress conversion is handled transparently and doesn't affect WARP functionality.
app.post('/executeWarp', checkToken, handleUsageFee, async (req, res) => {
  try {
    const { warpId, inputs, chain, cacheStrategy, cacheTTL, simulate, verbose, fields } = req.body;
    if (!warpId) throw new Error("Missing warpId in request body");
    
    log('info', `Processing WARP execution request`, { 
      warpId, 
      inputs: inputs,
      inputsType: typeof inputs,
      timestamp: new Date().toISOString()
    });
    const pemContent = getPemContent(req);
    const signer = UserSigner.fromPem(pemContent);
    const userAddressObj = signer.getAddress();
    
    // Convert Address object to string - handle both old and new SDK versions
    let userAddress;
    try {
      // Try the new SDK v15+ method first
      if (typeof userAddressObj.toString === 'function') {
        userAddress = userAddressObj.toString();
      } else if (typeof userAddressObj.bech32 === 'function') {
        userAddress = userAddressObj.bech32();
      } else {
        // Fallback: try to get the address as a string
        userAddress = String(userAddressObj);
      }
      log('info', 'UserAddress converted successfully', { 
        method: 'SDK v15+ compatible',
        address: userAddress,
        originalType: userAddressObj.constructor.name
      });
    } catch (error) {
      log('warn', 'Error converting userAddress, using fallback', { error: error.message });
      userAddress = String(userAddressObj);
    }
    
    // V3: Create WarpClient with user wallet configuration
    const config = getWarpClientConfig(req, userAddress, pemContent);
    const client = new WarpClient(config, {
      chains: getAllMultiversxAdapters()
    });
    
    const warpInfo = await fetchWarpInfo(warpId, req, userAddress, pemContent);
    const action = warpInfo.actions[0];
    
    // Log WARP type and ensure compatibility
    log('info', 'WARP execution details', {
      warpId,
      actionType: action.type,
      actionInputs: action.inputs?.length || 0,
      userAddressType: typeof userAddress,
      userAddress: userAddress,
      supportedTypes: ['contract', 'transfer', 'query', 'collect']
    });
    
    let response;
    if (action.type === 'contract' || action.type === 'transfer') {
      log('info', 'Executing contract/transfer WARP', { warpId, actionType: action.type });
      response = await handleContractExecution(req, res, action, warpInfo, userAddress, client, pemContent, simulate, verbose);
    } else if (action.type === 'query') {
      log('info', 'Executing query WARP', { warpId, actionType: action.type });
      response = await handleQueryExecution(req, res, action, warpInfo, userAddress, client, verbose);
    } else if (action.type === 'collect') {
      log('info', 'Executing collect WARP', { warpId, actionType: action.type });
      response = await handleCollectExecution(req, res, action, warpInfo, userAddress, client, verbose);
    } else {
      log('warn', `Unhandled action type`, { warpId, actionType: action.type });
      return res.status(400).json({ error: `Unsupported WARP action type: ${action.type}` });
    }
    
    // If handler returns a response object (not sent yet), filter fields and send
    if (response && typeof response === 'object' && !response.__sent) {
      try {
        const filtered = filterResponseFields(response, fields);
        // Use safe serialization to prevent circular reference errors
        const safeResponse = safeStringify(filtered);
        
        log('info', `Sending successful response`, { 
          warpId, 
          finalStatus: response.finalStatus,
          finalTxHash: response.finalTxHash,
          responseSize: JSON.stringify(safeResponse).length
        });
        
        return res.json(safeResponse);
      } catch (serializeError) {
        log('error', `Failed to serialize response`, { 
          warpId, 
          error: serializeError.message,
          originalResponse: safeStringify(response)
        });
        return res.status(500).json({ 
          success: false,
          error: 'Internal server error: Failed to serialize response',
          warpId 
        });
      }
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
    
    // Check if response has already been sent
    if (!res.headersSent) {
      return res.status(500).json({ 
        success: false,
        error: sanitizedMessage,
        warpId: req.body?.warpId
      });
    } else {
      log('warn', `Response already sent, cannot send error response`, { warpId: req.body?.warpId });
    }
  }
});

// 3. GET /warp/:warpId
// This endpoint returns the full WARP info for debugging or direct loading
app.get('/warp/:warpId', async (req, res) => {
  try {
    const { warpId } = req.params;
    if (!warpId) throw new Error("Missing warpId parameter");

    log('info', `Direct WARP access request`, { warpId });
    
    // V3: Create minimal client for read-only access
    const config = {
      env: req.query.chain || 'mainnet',
      currentUrl: process.env.CURRENT_URL || "https://warps-makex.onrender.com"
    };
    const client = new WarpClient(config, {
      chains: getAllMultiversxAdapters()
    });
    const warp = await client.detectWarp(warpId);
    if (!warp) {
      throw new Error(`Could not resolve ${warpId}: WARP not found`);
    }
    
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

// 4. GET /transaction/:txHash/status
// This endpoint allows users to check transaction status later if they got a pending response
app.get('/transaction/:txHash/status', async (req, res) => {
  try {
    const { txHash } = req.params;
    if (!txHash) throw new Error("Missing txHash parameter");

    log('info', `Transaction status check request`, { txHash });
    
    // Use the existing retry logic with reasonable limits for status checks
    const status = await checkTransactionStatus(txHash, 15, 2000); // 15 retries = 30 seconds
    
    return res.json({
      success: true,
      txHash,
      status: status.status,
      details: status.details || null,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    log('error', `Error checking transaction status`, { 
      txHash: req.params.txHash,
      error: error.message 
    });
    return res.status(400).json({ 
      success: false,
      error: error.message,
      txHash: req.params.txHash
    });
  }
});

// --- Input auto-injection for userWallet ---
function autoInjectInputs(action, inputs, userAddress) {
  const result = { ...inputs };
  if (action.inputs) {
    for (const input of action.inputs) {
      if ((input.source === 'user:wallet' || input.source === 'userWallet') && userAddress) {
        // Get wallet address string - handle both old and new SDK versions
        let walletAddress;
        try {
          // Try the new SDK v15+ method first
          if (typeof userAddress.toString === 'function') {
            walletAddress = userAddress.toString();
          } else if (typeof userAddress.bech32 === 'function') {
            walletAddress = userAddress.bech32();
          } else {
            // Fallback: try to get the address as a string
            walletAddress = String(userAddress);
          }
        } catch (error) {
          log('warn', 'Error extracting wallet address in autoInjectInputs, using fallback', { error: error.message });
          walletAddress = String(userAddress);
        }
        
        result[input.name] = walletAddress;
      }
    }
  }
  return result;
}

// Update handleContractExecution for V3
async function handleContractExecution(req, res, action, warpInfo, userAddress, client, pemContent, simulate, verbose) {
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
    // V3: Use executeWarp method - it handles transaction building, signing, and sending
    log('info', `Executing WARP via V3 client`, { warpId, inputs: userInputsArray });
    
    // V3 executeWarp returns the execution result
    const result = await client.executeWarp(warpId, userInputsArray);
    
    // Extract transaction hash from result
    let txHash = null;
    if (result.txHash) {
      txHash = result.txHash.toString();
    } else if (result.transactionHash) {
      txHash = result.transactionHash.toString();
    } else if (result.hash) {
      txHash = result.hash.toString();
    }
    
    if (!txHash) {
      log('warn', `No transaction hash in result`, { warpId, result });
      // For simulate mode or queries, this might be expected
      if (simulate) {
        txHash = 'simulated';
      }
    }
    
    // V3: Check transaction status if we have a hash
    let txStatus = { status: "success" }; // Default to success if no hash
    if (txHash && txHash !== 'simulated') {
      log('info', `Transaction sent, waiting for confirmation`, { warpId, txHash });
      
      // Use custom retry logic instead of blocking SDK call
      const maxWaitTime = simulate ? 10000 : 60000; // 10s for simulate, 1min for real
      const maxRetries = Math.ceil(maxWaitTime / 2000); // 2-second intervals
      
      txStatus = await checkTransactionStatus(txHash, maxRetries, 2000);
    } else {
      log('info', `No transaction hash to check (simulate mode or query)`, { warpId });
    }
    
    if (txStatus.status === "pending") {
      // Transaction still pending after max wait time
      log('warn', `Transaction still pending after max wait time`, { 
        warpId, 
        txHash, 
        maxWaitTime: maxWaitTime / 1000 + 's' 
      });
      
      // Return early with pending status - user can check later
      const response = {
        warpId,
        warpHash: warpInfo.meta?.hash,
        finalTxHash: txHash,
        finalStatus: "pending",
        message: `Transaction sent but still pending. Check status later with hash: ${txHash}`,
        results: [],
        messages: [],
        next: null,
        usageFeeHash: req.usageFeeHash || 'N/A'
      };
      
      if (verbose) {
        response.debug = {
          action: {
            type: action.type,
            inputs: action.inputs?.map(input => ({
              name: input.name,
              type: input.type,
              required: input.required,
              source: input.source
            }))
          },
          userInputsArray,
          txStatus: txStatus,
          maxWaitTime: maxWaitTime / 1000 + 's',
          v3Client: 'WarpClient'
        };
      }
      response.__sent = false;
      return response;
    }
    
    if (txStatus.status === "fail") {
      // Transaction failed on blockchain
      log('error', `Transaction failed on blockchain`, { 
        warpId, 
        txHash, 
        details: txStatus.details 
      });
      
      const response = {
        warpId,
        warpHash: warpInfo.meta?.hash,
        finalTxHash: txHash,
        finalStatus: "fail",
        message: `Transaction failed: ${txStatus.details}`,
        results: [],
        messages: [txStatus.details],
        next: null,
        usageFeeHash: req.usageFeeHash || 'N/A'
      };
      
      if (verbose) {
        response.debug = {
          action: {
            type: action.type,
            inputs: action.inputs?.map(input => ({
              name: input.name,
              type: input.type,
              required: input.required,
              source: input.source
            }))
          },
          userInputsArray,
          txStatus: txStatus,
          v3Client: 'WarpClient'
        };
      }
      response.__sent = false;
      return response;
    }
    
    // Transaction succeeded - use result from V3 client
    log('info', `Transaction confirmed successful`, { warpId, txHash });
    
    // V3: Use result from executeWarp
    const execResult = {
      success: result.success !== false, // Default to true unless explicitly false
      results: result.results || [],
      messages: result.messages || ['Transaction succeeded'],
      next: result.next || null
    };
    
    log('info', `WARP execution completed`, { warpId, execResult });
    
    // Validate that the execution was truly successful
    if (!execResult || !execResult.success) {
      log('error', `Transaction execution failed despite blockchain success`, { 
        warpId, 
        txHash, 
        execResult 
      });
      
      const response = {
        warpId,
        warpHash: warpInfo.meta?.hash,
        finalTxHash: txHash,
        finalStatus: "fail",
        message: "Transaction succeeded on blockchain but execution failed",
        results: [],
        messages: ["Transaction succeeded on blockchain but execution failed"],
        next: null,
        usageFeeHash: req.usageFeeHash || 'N/A'
      };
      
      response.__sent = false;
      return response;
    }
    
    // Create a safe response object without circular references
    const response = {
      warpId,
      warpHash: warpInfo.meta?.hash,
      finalTxHash: txHash,
      finalStatus: "success",
      results: execResult.results || [],
      messages: execResult.messages || [],
      next: execResult.next || null,
      usageFeeHash: req.usageFeeHash || 'N/A'
    };
    
    if (verbose) {
      // Only include safe, serializable debug info
      response.debug = {
        action: {
          type: action.type,
          inputs: action.inputs?.map(input => ({
            name: input.name,
            type: input.type,
            required: input.required,
            source: input.source
          }))
        },
        userInputsArray,
        txStatus: txStatus,
        execResult: execResult,
        v3Result: result
      };
    }
    response.__sent = false;
    return response;
  } catch (error) {
    log('error', `Contract execution failed`, { warpId, error: error.message });
    // Return error object instead of sending response directly
    throw error;
  }
}

// Update handleQueryExecution for V3
async function handleQueryExecution(req, res, action, warpInfo, userAddress, client, verbose) {
  const { warpId, inputs } = req.body;
  const mergedInputs = autoInjectInputs(action, inputs || {}, userAddress);
  const userInputsArray = [];
  if (action.inputs && action.inputs.length > 0 && mergedInputs && typeof mergedInputs === 'object') {
    log('info', `Processing inputs for query WARP`, { warpId, inputCount: action.inputs.length });
    for (const input of action.inputs) {
      const value = mergedInputs[input.name];
      if (input.required && (value === undefined || value === null)) {
        throw new Error(`Missing required input: ${input.name}`);
      }
      if (value !== undefined) {
        const type = input.type.split(':')[0];
        userInputsArray.push(`${type}:${value}`);
      }
    }
  }
  try {
    log('info', `Executing query WARP`, { warpId });
    // V3: Use executeWarp for queries as well
    const queryResult = await client.executeWarp(warpId, userInputsArray);
    log('info', `Query execution successful`, { warpId, queryResult });
    
    const txHash = queryResult.txHash?.toString?.() || queryResult.transactionHash?.toString?.() || queryResult.hash?.toString?.() || null;
    
    const response = {
      warpId,
      warpHash: warpInfo.meta?.hash,
      finalTxHash: txHash,
      finalStatus: queryResult.success !== false ? "success" : "fail",
      results: queryResult.results || [],
      messages: queryResult.messages || ['Query executed successfully'],
      next: queryResult.next || null,
      usageFeeHash: req.usageFeeHash || 'N/A'
    };
    if (verbose) {
      // Only include safe, serializable debug info
      response.debug = {
        action: {
          type: action.type,
          inputs: action.inputs?.map(input => ({
            name: input.name,
            type: input.type,
            required: input.required,
            source: input.source
          }))
        },
        userInputsArray,
        queryResult: queryResult
      };
    }
    response.__sent = false;
    return response;
  } catch (error) {
    log('error', `Query execution failed`, { warpId, error: error.message });
    // Return error object instead of sending response directly
    throw error;
  }
}

// Update handleCollectExecution for V3
async function handleCollectExecution(req, res, action, warpInfo, userAddress, client, verbose) {
  const { warpId, inputs } = req.body;
  const mergedInputs = autoInjectInputs(action, inputs || {}, userAddress);
  const userInputsArray = [];
  if (action.inputs && action.inputs.length > 0 && mergedInputs && typeof mergedInputs === 'object') {
    log('info', `Processing inputs for collect WARP`, { warpId, inputCount: action.inputs.length });
    for (const input of action.inputs) {
      const value = mergedInputs[input.name];
      if (input.required && (value === undefined || value === null)) {
        throw new Error(`Missing required input: ${input.name}`);
      }
      if (value !== undefined) {
        const type = input.type.split(':')[0];
        userInputsArray.push(`${type}:${value}`);
      }
    }
  } else {
    log('info', `Processing collect WARP without inputs`, { warpId });
  }
  try {
    log('info', `Executing collect WARP`, { warpId, inputs: userInputsArray });
    // V3: Use executeWarp for collect as well
    let collectResult;
    try {
      collectResult = await client.executeWarp(warpId, userInputsArray);
    } catch (collectError) {
      log('warn', `SDK collect method failed`, { error: collectError.message });
      collectResult = { success: false, error: collectError.message };
    }
    log('info', 'Collect result details', { collectResult });
    log('info', `Collect execution successful`, { warpId, collectResult });
    
    const txHash = collectResult.txHash?.toString?.() || collectResult.transactionHash?.toString?.() || collectResult.hash?.toString?.() || null;
    
    const response = {
      warpId,
      warpHash: warpInfo.meta?.hash,
      finalTxHash: txHash,
      finalStatus: collectResult.success !== false ? "success" : "fail",
      results: collectResult.results || [],
      messages: collectResult.messages || ['Data collected successfully'],
      next: collectResult.next || null,
      usageFeeHash: req.usageFeeHash || 'N/A',
      message: "Data collected successfully"
    };
    if (verbose) {
      // Only include safe, serializable debug info
      response.debug = {
        action: {
          type: action.type,
          inputs: action.inputs?.map(input => ({
            name: input.name,
            type: input.type,
            required: input.required,
            source: input.source
          }))
        },
        userInputsArray,
        collectResult: collectResult
      };
    }
    response.__sent = false;
    return response;
  } catch (error) {
    log('error', `Collect execution failed`, { warpId, error: error.message });
    // Return error object instead of sending response directly
    throw error;
  }
}

// Global error handling middleware
app.use((error, req, res, next) => {
  // Check if response has already been sent
  if (res.headersSent) {
    log('warn', 'Response already sent, cannot send error response', { 
      path: req.path,
      method: req.method,
      error: error.message 
    });
    return;
  }
  
  // Sanitize error message
  const sanitizedMessage = error.message ? 
    error.message.replace(/-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----/g, '[REDACTED PEM DATA]') : 
    'Internal server error';
  
  // Log the error
  log('error', 'Global error handler caught error', { 
    path: req.path,
    method: req.method,
    error: sanitizedMessage,
    stack: error.stack ? error.stack.replace(/-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----/g, '[REDACTED PEM DATA]') : ''
  });
  
  // Send error response
  res.status(500).json({ 
    error: sanitizedMessage,
    path: req.path,
    method: req.method
  });
});

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
