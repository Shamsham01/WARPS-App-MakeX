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
const WEGLD_TOKEN = "WEGLD-bd4d79";
const LP_CONTRACT = "erd1qqqqqqqqqqqqqpgq5e30gcakgtam8dpzj9xl2yd45fzdrw6c2jpsxe7ldq";
const TREASURY_WALLET = "erd158k2c3aserjmwnyxzpln24xukl2fsvlk9x46xae4dxl5xds79g6sdz37qn";
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const whitelistFilePath = path.join(__dirname, 'whitelist.json');

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

// Helper: Fetch REWARD token price from LP pool
const getRewardPrice = async () => {
  try {
    // Fetch EGLD price from CoinGecko
    const coingeckoResponse = await fetch('https://api.coingecko.com/api/v3/simple/price?ids=elrond-erd-2&vs_currencies=usd');
    const coingeckoData = await coingeckoResponse.json();
    const eglPriceUsd = new BigNumber(coingeckoData['elrond-erd-2'].usd);

    // Get LP pool data
    const lpResponse = await fetch(`https://api.multiversx.com/accounts/${LP_CONTRACT}/tokens`);
    const lpData = await lpResponse.json();

    // Find REWARD and WEGLD reserves
    const rewardReserve = lpData.find(token => token.identifier === REWARD_TOKEN)?.balance || '0';
    const wegldReserve = lpData.find(token => token.identifier === WEGLD_TOKEN)?.balance || '0';

    // Get token decimals
    const rewardDecimals = await getTokenDecimals(REWARD_TOKEN);
    const wegldDecimals = await getTokenDecimals(WEGLD_TOKEN);

    // Calculate price using BigNumber for precise decimal arithmetic
    const rewardReserveBN = new BigNumber(rewardReserve);
    const wegldReserveBN = new BigNumber(wegldReserve);
    
    if (rewardReserveBN.isZero()) {
      throw new Error('REWARD reserve is zero');
    }

    // Calculate REWARD/WEGLD ratio
    const rewardInWegld = wegldReserveBN
      .multipliedBy(new BigNumber(10).pow(rewardDecimals))
      .dividedBy(rewardReserveBN.multipliedBy(new BigNumber(10).pow(wegldDecimals)));

    // Calculate final USD price using EGLD price from CoinGecko
    const rewardPriceUsd = rewardInWegld.multipliedBy(eglPriceUsd);

    if (!rewardPriceUsd.isFinite() || rewardPriceUsd.isZero()) {
      throw new Error('Invalid REWARD price calculation');
    }

    return rewardPriceUsd.toNumber();
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

// Helper: Send usage fee transaction
const sendUsageFee = async (pemContent) => {
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

  const status = await checkTransactionStatus(txHash.toString());
  if (status.status !== "success") {
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
      console.log(`Wallet ${walletAddress} is whitelisted. Skipping usage fee.`);
      return next();
    }

    const txHash = await sendUsageFee(pemContent);
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
