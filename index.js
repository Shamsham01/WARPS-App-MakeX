/**************************************************************************
 * index.js
 **************************************************************************/
import express from 'express';
import bodyParser from 'body-parser';
import fetch from 'node-fetch';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import BigNumber from 'bignumber.js';

import { Address, Transaction } from '@multiversx/sdk-core';
import { ProxyNetworkProvider } from '@multiversx/sdk-network-providers';
const provider = new ProxyNetworkProvider("https://gateway.multiversx.com", { clientName: "warp-integration" });

import { UserSigner } from '@multiversx/sdk-wallet';
import { WarpBuilder, WarpActionExecutor } from '@vleap/warps';

// -------------------------------------------------------------
// Configuration & Environment variables
// -------------------------------------------------------------
const SECURE_TOKEN = process.env.SECURE_TOKEN || 'MY_SECURE_TOKEN';
const USAGE_FEE = 500; // Fee in REWARD tokens
const REWARD_TOKEN = 'REWARD-cf6eac';
const TREASURY_WALLET = process.env.TREASURY_WALLET || 'erd158k2c3aserjmwnyxzpln24xukl2fsvlk9x46xae4dxl5xds79g6sdz37qn';
const WARP_HASH = '5d765600d47904e135ef66e45d57596fab8953ea7f12b2f287159df3480d1e85'; // Warp transaction hash

// Warp configuration – note that later we’ll add userAddress to config.
const warpConfig = {
  providerUrl: "https://gateway.multiversx.com",
  currentUrl: process.env.CURRENT_URL || "https://warps-makex.onrender.com"
};

// -------------------------------------------------------------
// Express and local file setup
// -------------------------------------------------------------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const PORT = process.env.PORT || 3000;
const whitelistFilePath = path.join(__dirname, 'whitelist.json');

app.use(bodyParser.json());

// -------------------------------------------------------------
// Middleware: Authorization check
// -------------------------------------------------------------
const checkToken = (req, res, next) => {
  const token = req.headers.authorization;
  if (token === `Bearer ${SECURE_TOKEN}`) {
    next();
  } else {
    res.status(401).json({ error: 'Unauthorized' });
  }
};

// -------------------------------------------------------------
// Helper Functions
// -------------------------------------------------------------
function loadWhitelist() {
  if (!fs.existsSync(whitelistFilePath)) {
    fs.writeFileSync(whitelistFilePath, JSON.stringify([], null, 2));
  }
  const data = fs.readFileSync(whitelistFilePath);
  return JSON.parse(data);
}

function isWhitelisted(walletAddress) {
  const whitelist = loadWhitelist();
  return whitelist.some(entry => entry.walletAddress === walletAddress);
}

function getPemContent(req) {
  const pemContent = req.body.walletPem;
  if (
    !pemContent ||
    typeof pemContent !== 'string' ||
    !pemContent.includes('-----BEGIN PRIVATE KEY-----')
  ) {
    throw new Error('Invalid PEM content');
  }
  return pemContent;
}

function deriveWalletAddressFromPem(pemContent) {
  const signer = UserSigner.fromPem(pemContent);
  return signer.getAddress(); // Return the Address object directly.
}

async function checkTransactionStatus(txHash, retries = 40, delay = 5000) {
  const txStatusUrl = `https://api.multiversx.com/transactions/${txHash}`;
  for (let i = 0; i < retries; i++) {
    try {
      const response = await fetch(txStatusUrl);
      if (!response.ok) {
        console.warn(`Non-200 response for ${txHash}: ${response.status}`);
        throw new Error(`HTTP error ${response.status}`);
      }
      const txStatus = await response.json();
      if (txStatus.status === "success") {
        return { status: "success", txHash };
      } else if (txStatus.status === "fail") {
        return { status: "fail", txHash };
      }
      console.log(`Transaction ${txHash} pending, retrying...`);
    } catch (error) {
      console.error(`Error fetching transaction ${txHash}: ${error.message}`);
    }
    await new Promise(resolve => setTimeout(resolve, delay));
  }
  throw new Error(`Transaction ${txHash} not determined after ${retries} retries.`);
}

async function getTokenDecimals(tokenTicker) {
  const apiUrl = `https://api.multiversx.com/tokens/${tokenTicker}`;
  const response = await fetch(apiUrl);
  if (!response.ok) {
    throw new Error(`Failed to fetch token info: ${response.statusText}`);
  }
  const tokenInfo = await response.json();
  return tokenInfo.decimals || 0;
}

function convertAmountToBlockchainValue(amount, decimals) {
  const factor = new BigNumber(10).pow(decimals);
  return new BigNumber(amount).times(factor).toFixed(0);
}

async function sendUsageFee(pemContent) {
  const signer = UserSigner.fromPem(pemContent);
  const senderAddress = signer.getAddress();
  const receiverAddress = new Address(TREASURY_WALLET);

  const accountOnNetwork = await provider.getAccount(senderAddress);
  const nonce = accountOnNetwork.nonce;
  const decimals = await getTokenDecimals(REWARD_TOKEN);
  const convertedAmount = convertAmountToBlockchainValue(USAGE_FEE, decimals);

  // Build a simple ESDT transfer payload (using basic JSON payload)
  const payload = Buffer.from(
    JSON.stringify({
      func: "ESDTTransfer",
      args: [REWARD_TOKEN, convertedAmount.toString()]
    })
  );

  const tx = new Transaction({
    nonce,
    receiver: receiverAddress,
    sender: senderAddress,
    value: 0,
    gasLimit: 500000n,
    data: payload,
    chainID: "1"
  });

  await signer.sign(tx);
  const txHash = await provider.sendTransaction(tx);
  const status = await checkTransactionStatus(txHash.toString());
  if (status.status !== "success") {
    throw new Error('UsageFee transaction failed. Ensure you have enough REWARD tokens.');
  }
  return txHash.toString();
}

async function handleUsageFee(req, res, next) {
  try {
    const pemContent = getPemContent(req);
    const walletAddress = deriveWalletAddressFromPem(pemContent);
    if (isWhitelisted(walletAddress.toString())) {
      console.log(`Wallet ${walletAddress.toString()} is whitelisted. Skipping usage fee.`);
      return next();
    }
    const txHash = await sendUsageFee(pemContent);
    req.usageFeeHash = txHash;
    return next();
  } catch (error) {
    console.error('Error processing usageFee:', error.message);
    return res.status(400).json({ error: error.message });
  }
}

// -------------------------------------------------------------
// Authorization Endpoint for Make.com
// -------------------------------------------------------------
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

// -------------------------------------------------------------
// Execute Warp Endpoint
// -------------------------------------------------------------
app.post('/executeWarp', checkToken, handleUsageFee, async (req, res) => {
  try {
    // Extract PEM and create a signer
    const pemContent = getPemContent(req);
    const signer = UserSigner.fromPem(pemContent);
    // Do NOT convert the address to a string here; keep the Address object.
    const userAddress = signer.getAddress();

    // Extract user inputs from request body
    // Expected order: [Token Name, Token Ticker, Initial Supply, Token Decimals]
    const { tokenName, tokenTicker, initialSupply, tokenDecimals } = req.body;
    if (!tokenName || !tokenTicker || !initialSupply || tokenDecimals === undefined) {
      throw new Error("Missing one or more required input fields.");
    }

    // Build an array of arguments using Warp typed notation.
    const args = [
      `string:${tokenName}`,    // Token Name
      `string:${tokenTicker}`,  // Token Ticker
      `biguint:${initialSupply}`, // Initial Supply
      `uint8:${tokenDecimals}`    // Token Decimals
    ];

    // Build the Warp using the provided on-chain warp hash
    const warpBuilder = new WarpBuilder(warpConfig);
    const warp = await warpBuilder.createFromTransactionHash(WARP_HASH);
    if (!warp) {
      throw new Error(`Could not load Warp from hash: ${WARP_HASH}`);
    }

    // Use the first action from the Warp blueprint (for ESDT Creator, this should be "issue")
    const action = warp.actions[0];
    if (!action) {
      throw new Error("No action found in this Warp blueprint!");
    }

    // Create a WarpActionExecutor with updated config (including userAddress)
    const executorConfig = { ...warpConfig, userAddress };
    const warpActionExecutor = new WarpActionExecutor(executorConfig);

    // Create the transaction based on the array of arguments; assuming no extra transfers.
    const tx = warpActionExecutor.createTransactionForExecute(action, args, []);

    // Set nonce from network for the user's account
    const accountOnNetwork = await provider.getAccount(userAddress.toString());
    tx.nonce = accountOnNetwork.nonce;

    // Sign and send the transaction
    await signer.sign(tx);
    const txHash = await provider.sendTransaction(tx);
    const status = await checkTransactionStatus(txHash.toString());

    return res.json({
      usageFeeHash: req.usageFeeHash || null,
      warpHash: WARP_HASH,
      finalTxHash: txHash.toString(),
      finalStatus: status.status
    });
  } catch (error) {
    console.error("Error in /executeWarp:", error.message);
    return res.status(400).json({ error: error.message });
  }
});

// -------------------------------------------------------------
// Start the Express server
// -------------------------------------------------------------
app.listen(PORT, () => {
  console.log(`Warp integration app is running on port ${PORT}`);
});
