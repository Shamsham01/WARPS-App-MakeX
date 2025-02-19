/**************************************************************************
 * index.js
 **************************************************************************/
import express from 'express';
import bodyParser from 'body-parser';
import fetch from 'node-fetch';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

import { Address, Transaction } from '@multiversx/sdk-core';
import { ProxyNetworkProvider } from '@multiversx/sdk-network-providers';
const provider = new ProxyNetworkProvider("https://gateway.multiversx.com", { clientName: "warp-integration" });

import { UserSigner } from '@multiversx/sdk-wallet';
import { WarpBuilder, WarpActionExecutor } from '@vleap/warps';

// -------------------------------------------------------------
// Configuration & Environment variables
// -------------------------------------------------------------
const SECURE_TOKEN = process.env.SECURE_TOKEN || 'MY_SECURE_TOKEN';
const WARP_HASH = '5d765600d47904e135ef66e45d57596fab8953ea7f12b2f287159df3480d1e85'; // Warp transaction hash for ESDT Creator

// Warp configuration – note that we add currentUrl and later userAddress to the config.
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

// -------------------------------------------------------------
// Endpoint: Authorization (for Make.com)
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
// Endpoint: Execute Warp
// -------------------------------------------------------------
app.post('/executeWarp', checkToken, async (req, res) => {
  try {
    // 1) Extract PEM and create a signer
    const pemContent = getPemContent(req);
    const signer = UserSigner.fromPem(pemContent);
    const userAddress = signer.getAddress().toString();

    // 2) Extract user inputs from request body
    // Expecting: tokenName, tokenTicker, initialSupply, tokenDecimals
    const { tokenName, tokenTicker, initialSupply, tokenDecimals } = req.body;
    if (!tokenName || !tokenTicker || !initialSupply || tokenDecimals === undefined) {
      throw new Error("Missing one or more required input fields.");
    }
    // IMPORTANT: The Warp blueprint expects an array of inputs in order with type prefixes.
    // Here we convert the native values into typed strings.
    const userInputs = [
      `string:${tokenName}`,
      `string:${tokenTicker}`,
      `biguint:${initialSupply}`,
      `uint8:${tokenDecimals}`
    ];

    // 3) Build the Warp using the provided on-chain warp hash
    const warpBuilder = new WarpBuilder(warpConfig);
    const warp = await warpBuilder.createFromTransactionHash(WARP_HASH);
    if (!warp) {
      throw new Error(`Could not load Warp from hash: ${WARP_HASH}`);
    }

    // 4) Use the first action from the Warp blueprint (for ESDT Creator, this should be "issue")
    const action = warp.actions[0];
    if (!action) {
      throw new Error("No action found in this Warp blueprint!");
    }

    // 5) Create a WarpActionExecutor with updated config (including userAddress)
    const executorConfig = { ...warpConfig, userAddress };
    const warpActionExecutor = new WarpActionExecutor(executorConfig);

    // 6) Create the transaction for executing the Warp action
    const tx = warpActionExecutor.createTransactionForExecute(action, userInputs, []);

    // 7) Set nonce from network for the user's account
    const accountOnNetwork = await provider.getAccount(userAddress);
    tx.nonce = accountOnNetwork.nonce;

    // 8) Sign and send the transaction
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
