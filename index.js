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
// For now we remove usage fee logic
const WARP_HASH = '5d765600d47904e135ef66e45d57596fab8953ea7f12b2f287159df3480d1e85'; // Warp transaction hash

// Warp configuration – note: we add userAddress later (as an Address instance)
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
// (Whitelist logic omitted for simplicity)

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

// IMPORTANT: Do not convert the address to string!
// Return the Address instance directly so that methods like .bech32() are available.
function deriveWalletAddressFromPem(pemContent) {
  const signer = UserSigner.fromPem(pemContent);
  return signer.getAddress();
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
app.post('/executeWarp', checkToken, async (req, res) => {
  try {
    // Extract PEM and create a signer
    const pemContent = getPemContent(req);
    const signer = UserSigner.fromPem(pemContent);
    // IMPORTANT: Do not convert to string; use the Address instance directly.
    const userAddress = signer.getAddress().trim();

    // Extract user inputs from request body for the ESDT Creator warp
    const { tokenName, tokenTicker, initialSupply, tokenDecimals } = req.body;
    if (!tokenName || !tokenTicker || !initialSupply || tokenDecimals === undefined) {
      throw new Error("Missing one or more required input fields.");
    }

    // The Warp blueprint expects arguments as an array in the correct order,
    // using the Warp custom notation.
    // For example:
    // - For token name: "string:MyToken"
    // - For token ticker: "string:MYTKN"
    // - For initial supply: "biguint:1000000"
    // - For token decimals: "uint8:18"
    // (If you need to adjust the notation, do so here.)
    const userInputsArray = [
      `string:${tokenName}`,
      `string:${tokenTicker}`,
      `biguint:${initialSupply}`,
      `uint8:${tokenDecimals}`
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

    // Create the transaction based on user inputs; assuming no extra transfers are needed
    // Note: we pass an array of arguments, not an object.
    const tx = warpActionExecutor.createTransactionForExecute(action, userInputsArray, []);

    // Set nonce from network for the user's account
    const accountOnNetwork = await provider.getAccount(userAddress);
    tx.nonce = accountOnNetwork.nonce;

    // Sign and send the transaction
    await signer.sign(tx);
    const txHash = await provider.sendTransaction(tx);
    const status = await checkTransactionStatus(txHash.toString());

    return res.json({
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
