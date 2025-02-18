/**************************************************************************/
/* index.js                                                               */
/**************************************************************************/
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
// Configuration & constants
// ---------------------------------------------
const SECURE_TOKEN = process.env.SECURE_TOKEN || 'MY_SECURE_TOKEN';
const USAGE_FEE = 500;                     // Fee in "REWARD" tokens
const REWARD_TOKEN = 'REWARD-cf6eac';      // Your usage-fee token identifier
const TREASURY_WALLET = 'erd158k2c3aserjmwnyxzpln24xukl2fsvlk9x46xae4dxl5xds79g6sdz37qn'; // Treasury wallet
const // The on-chain transaction hash of your ESDT Creator Warp blueprint
      WARP_HASH = '5d765600d47904e135ef66e45d57596fab8953ea7f12b2f287159df3480d1e85';

// ---------------------------------------------
// Express setup
// ---------------------------------------------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const PORT = process.env.PORT || 3000;

// Use JSON body parser
app.use(bodyParser.json());

// ---------------------------------------------
// Network Provider & Warp configuration
// ---------------------------------------------
const provider = new ProxyNetworkProvider("https://gateway.multiversx.com", { clientName: "warp-integration" });
const warpConfig = {
  providerUrl: "https://gateway.multiversx.com",
  // additional config values if needed
};

// ---------------------------------------------
// Middleware: Authorization check (for Make.com custom app)
// ---------------------------------------------
const checkToken = (req, res, next) => {
  const token = req.headers.authorization;
  console.log("Received token:", token);
  console.log("Expected token:", `Bearer ${SECURE_TOKEN}`);
  if (token === `Bearer ${SECURE_TOKEN}`) {
    next();
  } else {
    res.status(401).json({ error: 'Unauthorized' });
  }
};

// ---------------------------------------------
// Helper: Load whitelist (if used)
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
// Helpers: PEM and wallet address extraction
// ---------------------------------------------
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
  return signer.getAddress().toString();
}

// ---------------------------------------------
// Helper: Check transaction status (with retries)
// ---------------------------------------------
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

// ---------------------------------------------
// Helper: Token decimals & amount conversion
// ---------------------------------------------
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
  return new BigNumber(amount).multipliedBy(factor).toFixed(0);
}

// ---------------------------------------------
// Helper: Send usage fee (in REWARD tokens)
// ---------------------------------------------
async function sendUsageFee(pemContent) {
  const signer = UserSigner.fromPem(pemContent);
  const senderAddress = signer.getAddress();
  const receiverAddress = new Address(TREASURY_WALLET);

  const accountOnNetwork = await provider.getAccount(senderAddress);
  const nonce = accountOnNetwork.nonce;

  const decimals = await getTokenDecimals(REWARD_TOKEN);
  const convertedAmount = convertAmountToBlockchainValue(USAGE_FEE, decimals);

  // Construct a simple transaction payload for a token transfer (usage fee)
  const payload = TransactionPayload.contractCall()
    .setFunction("ESDTTransfer")
    .addArg(REWARD_TOKEN)
    .addArg(convertedAmount)
    .build();

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
    throw new Error('Usage fee transaction failed. Ensure you have enough REWARD tokens.');
  }
  return txHash.toString();
}

// ---------------------------------------------
// Middleware: Handle usage fee
// ---------------------------------------------
async function handleUsageFee(req, res, next) {
  try {
    const pemContent = getPemContent(req);
    const walletAddress = deriveWalletAddressFromPem(pemContent);

    // If wallet is whitelisted, skip fee collection
    if (isWhitelisted(walletAddress)) {
      console.log(`Wallet ${walletAddress} is whitelisted. Skipping usage fee.`);
      return next();
    }
    const txHash = await sendUsageFee(pemContent);
    req.usageFeeHash = txHash;
    return next();
  } catch (error) {
    console.error('Error processing usage fee:', error.message);
    return res.status(400).json({ error: error.message });
  }
}

// ---------------------------------------------
// 1) Authorization Endpoint (for Make.com)
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
// 2) Warp Execution Endpoint: /executeWarp
//    This endpoint accepts user input (for the ESDT Creator warp)
//    along with the user's PEM file. It then executes the Warp action.
// ---------------------------------------------
app.post('/executeWarp', checkToken, handleUsageFee, async (req, res) => {
  try {
    // Extract user PEM and create a signer
    const pemContent = getPemContent(req);
    const signer = UserSigner.fromPem(pemContent);
    const userAddress = signer.getAddress();

    // Gather user inputs required by the ESDT Creator warp:
    // "Token Name", "Token Ticker", "Initial Supply", "Token Decimals"
    const { tokenName, tokenTicker, initialSupply, tokenDecimals } = req.body;
    if (!tokenName || !tokenTicker || !initialSupply || !tokenDecimals) {
      throw new Error("Missing required input fields.");
    }

    // Build the Warp from the on-chain transaction hash (ESDT Creator blueprint)
    const warpBuilder = new WarpBuilder(warpConfig);
    const warp = await warpBuilder.createFromTransactionHash(WARP_HASH);
    if (!warp) {
      throw new Error(`Could not load Warp from hash: ${WARP_HASH}`);
    }

    // Use the first action from the Warp (assumed to be the 'issue' function)
    const action = warp.actions[0];
    if (!action) {
      throw new Error("No action found in the Warp blueprint!");
    }

    // Create the userInputs object matching the Warp blueprint fields exactly:
    const userInputs = {
      "Token Name": tokenName,
      "Token Ticker": tokenTicker,
      "Initial Supply": initialSupply,
      "Token Decimals": tokenDecimals
    };

    // Execute the Warp action to create a signable transaction
    const warpActionExecutor = new WarpActionExecutor(warpConfig);
    const tx = warpActionExecutor.createTransactionForExecute(action, userInputs, []);

    // Set the transaction nonce
    const accountOnNetwork = await provider.getAccount(userAddress);
    tx.setNonce(accountOnNetwork.nonce);

    // Sign and send the transaction
    await signer.sign(tx);
    const txHash = await provider.sendTransaction(tx);

    // Wait for final transaction status
    const status = await checkTransactionStatus(txHash.toString());

    // Return the result
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
// Start the server
// ---------------------------------------------
app.listen(PORT, () => {
  console.log(`Warp integration app is running on port ${PORT}`);
});
