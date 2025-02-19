/**************************************************************************
 * index.js
 **************************************************************************/
import express from 'express';
import bodyParser from 'body-parser';
import fetch from 'node-fetch';
import { fileURLToPath } from 'url';
import path from 'path';
import BigNumber from 'bignumber.js';

import { Address, Transaction } from '@multiversx/sdk-core';
import { ProxyNetworkProvider } from '@multiversx/sdk-network-providers';
import { UserSigner } from '@multiversx/sdk-wallet';
import { WarpBuilder, WarpActionExecutor } from '@vleap/warps';

// -------------------------------------------------------------
// Configuration & Environment variables
// -------------------------------------------------------------
const SECURE_TOKEN = process.env.SECURE_TOKEN || 'MY_SECURE_TOKEN';
// The on-chain transaction hash for the ESDT Creator Warp
const WARP_HASH = '5d765600d47904e135ef66e45d57596fab8953ea7f12b2f287159df3480d1e85';

// Warp configuration – note that later we add the userAddress to the config
const warpConfig = {
  providerUrl: "https://gateway.multiversx.com",
  currentUrl: process.env.CURRENT_URL || "https://warps-makex.onrender.com"
};

// -------------------------------------------------------------
// Express setup
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
// Extract the full PEM content from the request body
const getPemContent = (req) => {
  const pemContent = req.body.walletPem;
  if (
    !pemContent ||
    typeof pemContent !== 'string' ||
    !pemContent.includes('-----BEGIN PRIVATE KEY-----')
  ) {
    throw new Error('Invalid PEM content');
  }
  return pemContent;
};

// Derive a wallet address from the PEM using the SDK;
// IMPORTANT: Return the Address instance so that methods like .bech32() are available.
const deriveWalletAddressFromPem = (pemContent) => {
  const signer = UserSigner.fromPem(pemContent);
  return signer.getAddress();
};

async function checkTransactionStatus(txHash, retries = 40, delay = 5000) {
  const txStatusUrl = `https://api.multiversx.com/transactions/${txHash}`;
  for (let i = 0; i < retries; i++) {
    try {
      const response = await fetch(txStatusUrl);
      if (!response.ok) {
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
    // 1) Extract the PEM and create a signer
    const pemContent = getPemContent(req);
    const signer = UserSigner.fromPem(pemContent);
    // Use the full Address instance (do not convert to string)
    const userAddress = signer.getAddress();

    // 2) Extract user inputs from the request body.
    // The ESDT Creator warp expects four inputs (in this order):
    //   - Token Name (string)
    //   - Token Ticker (string)
    //   - Initial Supply (biguint)
    //   - Token Decimals (uint8)
    const { tokenName, tokenTicker, initialSupply, tokenDecimals } = req.body;
    if (!tokenName || !tokenTicker || !initialSupply || tokenDecimals === undefined) {
      throw new Error("Missing one or more required input fields.");
    }

    // 3) Build the array of user inputs using the custom typed notation.
    // Note: Make sure the order matches the blueprint.
    const userInputsArray = [
      `string:${tokenName}`,
      `string:${tokenTicker}`,
      `biguint:${initialSupply}`,
      `uint8:${tokenDecimals}`
    ];

    // 4) Build the Warp using the provided on-chain warp hash.
    const warpBuilder = new WarpBuilder(warpConfig);
    const warp = await warpBuilder.createFromTransactionHash(WARP_HASH);
    if (!warp) {
      throw new Error(`Could not load Warp from hash: ${WARP_HASH}`);
    }

    // 5) Select the first action from the Warp blueprint.
    const action = warp.actions[0];
    if (!action) {
      throw new Error("No action found in this Warp blueprint!");
    }

    // 6) Create a WarpActionExecutor with updated config (including the userAddress).
    const executorConfig = { ...warpConfig, userAddress };
    const warpActionExecutor = new WarpActionExecutor(executorConfig);

    // 7) Create the transaction using the array of user inputs.
    const tx = warpActionExecutor.createTransactionForExecute(action, userInputsArray, []);

    // 8) Retrieve the account nonce from the network and set it on the transaction.
    const provider = new ProxyNetworkProvider("https://gateway.multiversx.com", { clientName: "warp-integration" });
    const accountOnNetwork = await provider.getAccount(userAddress);
    tx.nonce = accountOnNetwork.nonce;

    // 9) Sign and send the transaction.
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
