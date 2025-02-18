/**************************************************************************
 * index.js
 * 
 * This Express API demonstrates:
 *   • An /authorization endpoint to check a Bearer token.
 *   • An /executeWarp endpoint that uses a user’s PEM and input data 
 *     to execute a WARPS action (here, the "ESDT Creator" warp).
 *   • Usage fee processing (unless the wallet is whitelisted).
 *
 * The WARPS integration uses the WarpBuilder and WarpActionExecutor from
 * the @vleap/warps package.
 *
 * Note: In SDK v13 the old TransactionPayload.contractCall() method is not
 * available. Here we use TransactionPayload.fromString() to construct a payload 
 * for sending usage fee via an ESDT transfer.
 **************************************************************************/

import express from 'express';
import bodyParser from 'body-parser';
import fetch from 'node-fetch';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import BigNumber from 'bignumber.js';

import {
  Address,
  Transaction,
  TransactionPayload
} from '@multiversx/sdk-core';
import { ProxyNetworkProvider } from '@multiversx/sdk-network-providers';
import { UserSigner } from '@multiversx/sdk-wallet';

import { WarpBuilder, WarpActionExecutor } from '@vleap/warps';

// ---------------------------------------------
// Configuration & Environment Variables
// ---------------------------------------------
const SECURE_TOKEN = process.env.SECURE_TOKEN || 'MY_SECURE_TOKEN';
const USAGE_FEE = 500; // fee in REWARD tokens
const REWARD_TOKEN = 'REWARD-cf6eac';
const TREASURY_WALLET = 'erd158k2c3aserjmwnyxzpln24xukl2fsvlk9x46xae4dxl5xds79g6sdz37qn'; // update with your treasury wallet
const WARP_HASH = '5d765600d47904e135ef66e45d57596fab8953ea7f12b2f287159df3480d1e85'; // ESDT Creator warp hash

// For warps SDK, minimal config (adjust as needed)
const warpConfig = {
  providerUrl: "https://gateway.multiversx.com"
};

// ---------------------------------------------
// Express Setup
// ---------------------------------------------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const PORT = process.env.PORT || 3000;

app.use(bodyParser.json());

// ---------------------------------------------
// Authorization Middleware
// ---------------------------------------------
const checkToken = (req, res, next) => {
  const token = req.headers.authorization;
  if (token === `Bearer ${SECURE_TOKEN}`) {
    next();
  } else {
    res.status(401).json({ error: 'Unauthorized' });
  }
};

// ---------------------------------------------
// Whitelist Helpers (if you use a whitelist file)
// ---------------------------------------------
const whitelistFilePath = path.join(__dirname, 'whitelist.json');
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

// ---------------------------------------------
// PEM & Wallet Helpers
// ---------------------------------------------
function getPemContent(req) {
  const pemContent = req.body.walletPem;
  if (!pemContent || typeof pemContent !== 'string' || !pemContent.includes('-----BEGIN PRIVATE KEY-----')) {
    throw new Error('Invalid PEM content');
  }
  return pemContent;
}
function deriveWalletAddressFromPem(pemContent) {
  const signer = UserSigner.fromPem(pemContent);
  return signer.getAddress().toString();
}

// ---------------------------------------------
// Transaction Helpers (usage fee)
// ---------------------------------------------
const provider = new ProxyNetworkProvider("https://gateway.multiversx.com", { clientName: "warp-integration" });

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

// Replace the old TransactionPayload.contractCall() approach with fromString
async function sendUsageFee(pemContent) {
  const signer = UserSigner.fromPem(pemContent);
  const senderAddress = signer.getAddress();
  const receiverAddress = new Address(TREASURY_WALLET);

  const accountOnNetwork = await provider.getAccount(senderAddress);
  const nonce = accountOnNetwork.nonce;

  const decimals = await getTokenDecimals(REWARD_TOKEN);
  const convertedAmount = convertAmountToBlockchainValue(USAGE_FEE, decimals);

  // Build payload using fromString; this encodes a contract call for ESDTTransfer
  const payload = TransactionPayload.fromString(`ESDTTransfer@${REWARD_TOKEN}@${convertedAmount}`);

  const tx = new Transaction({
    nonce,
    receiver: receiverAddress,
    sender: senderAddress,
    value: 0, // no EGLD transfer
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
    if (isWhitelisted(walletAddress)) {
      console.log(`Wallet ${walletAddress} is whitelisted. Skipping usage fee.`);
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

// ---------------------------------------------
// Endpoint: /authorization
// ---------------------------------------------
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

// ---------------------------------------------
// Endpoint: /executeWarp
// This endpoint receives user input data and PEM file content,
// loads the "ESDT Creator" Warp from the blockchain using its transaction hash,
// creates a transaction using the first action (e.g. "issue"), and sends it.
// ---------------------------------------------
app.post('/executeWarp', checkToken, handleUsageFee, async (req, res) => {
  try {
    // Extract PEM content and create a signer
    const pemContent = getPemContent(req);
    const signer = UserSigner.fromPem(pemContent);
    const userAddress = signer.getAddress();

    // Get user inputs from request body (ensure these keys match your Warp blueprint)
    const { tokenName, tokenTicker, initialSupply, tokenDecimals } = req.body;
    if (!tokenName || !tokenTicker || !initialSupply || !tokenDecimals) {
      throw new Error("Missing one or more required parameters: tokenName, tokenTicker, initialSupply, tokenDecimals");
    }

    // Build the Warp from its on-chain transaction hash
    const warpBuilder = new WarpBuilder(warpConfig);
    const warp = await warpBuilder.createFromTransactionHash(WARP_HASH);
    if (!warp) {
      throw new Error(`Could not load Warp from hash: ${WARP_HASH}`);
    }

    // For the esdtCreator warp, we expect the first action to be the contract call (e.g. "issue")
    const action = warp.actions[0];
    if (!action) {
      throw new Error("No action found in this Warp blueprint!");
    }

    // Build userInputs object matching the Warp blueprint field names exactly.
    const userInputs = {
      "Token Name": tokenName,
      "Token Ticker": tokenTicker,
      "Initial Supply": initialSupply,
      "Token Decimals": tokenDecimals
    };

    // Create the transaction using the WarpActionExecutor.
    const warpActionExecutor = new WarpActionExecutor(warpConfig);
    const tx = warpActionExecutor.createTransactionForExecute(action, userInputs, []); // no extra transfers

    // Get current nonce for the user's account and set it on the transaction.
    const accountOnNetwork = await provider.getAccount(userAddress);
    tx.nonce = accountOnNetwork.nonce;

    // Sign and send the transaction.
    await signer.sign(tx);
    const txHash = await provider.sendTransaction(tx);
    const status = await checkTransactionStatus(txHash.toString());

    // Return response including the usage fee tx hash (if any) and the warp execution tx info.
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

// ---------------------------------------------
// Start the Server
// ---------------------------------------------
app.listen(PORT, () => {
  console.log(`Warp integration app is running on port ${PORT}`);
});
