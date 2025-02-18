/**************************************************************************
 * index.js
 *
 * This Express API demonstrates:
 *  • An /authorization endpoint to check a Bearer token.
 *  • An /executeWarp endpoint that uses a user’s PEM and input data
 *    to execute a WARPS action (here, the "ESDT Creator" warp).
 *
 * This version does NOT include usage fee logic.
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
import { UserSigner } from '@multiversx/sdk-wallet';

import { WarpBuilder, WarpActionExecutor } from '@vleap/warps';

// ----------------------------
// Configuration & Environment Variables
// ----------------------------
const SECURE_TOKEN = process.env.SECURE_TOKEN || 'MY_SECURE_TOKEN';
// The on-chain transaction hash for your ESDT Creator Warp
const WARP_HASH = '5d765600d47904e135ef66e45d57596fab8953ea7f12b2f287159df3480d1e85';

const warpConfig = {
  // Minimal configuration for the warps SDK; adjust if needed.
  providerUrl: "https://gateway.multiversx.com"
};

// ----------------------------
// Express Setup
// ----------------------------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const PORT = process.env.PORT || 3000;

app.use(bodyParser.json());

// ----------------------------
// Authorization Middleware
// ----------------------------
const checkToken = (req, res, next) => {
  const token = req.headers.authorization;
  if (token === `Bearer ${SECURE_TOKEN}`) {
    return next();
  } else {
    return res.status(401).json({ error: 'Unauthorized' });
  }
};

// ----------------------------
// PEM & Wallet Helpers
// ----------------------------
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

// ----------------------------
// Transaction Helper: Check Transaction Status
// ----------------------------
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

// ----------------------------
// Provider Initialization (for broadcasting transactions)
// ----------------------------
const provider = new ProxyNetworkProvider("https://gateway.multiversx.com", {
  clientName: "warp-integration"
});

// ----------------------------
// Endpoint: /authorization
// ----------------------------
app.post('/authorization', (req, res) => {
  try {
    const token = req.headers.authorization;
    if (token === `Bearer ${SECURE_TOKEN}`) {
      return res.json({ message: "Authorization successful" });
    } else {
      return res.status(401).json({ error: "Unauthorized" });
    }
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

// ----------------------------
// Endpoint: /executeWarp
// Accepts user input for ESDT creation and executes the warp action.
// ----------------------------
app.post('/executeWarp', checkToken, async (req, res) => {
  try {
    // 1) Extract user PEM and create a signer
    const pemContent = getPemContent(req);
    const signer = UserSigner.fromPem(pemContent);
    const userAddress = signer.getAddress();

    // 2) Gather user inputs from the request body.
    //    Expected inputs for the ESDT Creator warp:
    //    "Token Name", "Token Ticker", "Initial Supply", "Token Decimals"
    const { tokenName, tokenTicker, initialSupply, tokenDecimals } = req.body;
    if (!tokenName || !tokenTicker || !initialSupply || !tokenDecimals) {
      throw new Error("Missing required input parameters.");
    }

    // 3) Build the Warp from the on-chain transaction hash.
    const warpBuilder = new WarpBuilder(warpConfig);
    const warp = await warpBuilder.createFromTransactionHash(WARP_HASH);
    if (!warp) {
      throw new Error(`Could not load Warp from hash: ${WARP_HASH}`);
    }

    // 4) Get the first action from the Warp blueprint.
    const action = warp.actions[0];
    if (!action) {
      throw new Error("No action found in the Warp blueprint!");
    }

    // 5) Build the userInputs object (keys must exactly match those in the Warp blueprint).
    const userInputs = {
      "Token Name": tokenName,
      "Token Ticker": tokenTicker,
      "Initial Supply": initialSupply,
      "Token Decimals": tokenDecimals
    };

    // 6) Create the transaction using the WarpActionExecutor.
    const warpActionExecutor = new WarpActionExecutor(warpConfig);
    const tx = warpActionExecutor.createTransactionForExecute(action, userInputs, /*transfers*/ []);

    // 7) Synchronize nonce with the network.
    const accountOnNetwork = await provider.getAccount(userAddress);
    tx.nonce = accountOnNetwork.nonce;

    // 8) Sign and send the transaction.
    await signer.sign(tx);
    const txHash = await provider.sendTransaction(tx);

    // 9) Wait for the transaction to complete.
    const status = await checkTransactionStatus(txHash.toString());

    // 10) Return the result.
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

// ----------------------------
// Start the Express server
// ----------------------------
app.listen(PORT, () => {
  console.log(`Warp integration app is running on port ${PORT}`);
});
