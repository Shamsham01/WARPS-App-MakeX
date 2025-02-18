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
// Example usage fee settings & environment
// ---------------------------------------------
const SECURE_TOKEN = process.env.SECURE_TOKEN || 'MY_SECURE_TOKEN'; 
const USAGE_FEE = 500;                    // Fee in "REWARD" tokens
const REWARD_TOKEN = 'REWARD-cf6eac';     // Your usage-fee token
const TREASURY_WALLET = 'erd1...';        // Your treasury wallet for usage fees
const WARP_HASH = '5d765600d47904e1...';  // The on-chain transaction hash of your Warp

// ---------------------------------------------
// For local files & express setup
// ---------------------------------------------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const PORT = process.env.PORT || 3000;

// If you keep a local whitelist file:
const whitelistFilePath = path.join(__dirname, 'whitelist.json');

// The provider for sending transactions on mainnet:
const provider = new ProxyNetworkProvider("https://gateway.multiversx.com", { clientName: "warp-integration" });

// For WarpBuilder and WarpActionExecutor, define a config object:
const warpConfig = {
  // environment, gateway, etc. - minimal example:
  providerUrl: "https://gateway.multiversx.com",
};

// Middleware to parse JSON body
app.use(bodyParser.json());

// -------------------------------------------------------------------------
// 1) Authorization Endpoint for Make.com
// -------------------------------------------------------------------------
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

// -------------------------------------------------------------------------
// Helper: Load local whitelist (if you maintain one)
// -------------------------------------------------------------------------
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

// -------------------------------------------------------------------------
// Helper: Check & parse PEM from request
// -------------------------------------------------------------------------
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

// -------------------------------------------------------------------------
// Helper: Check transaction status
// -------------------------------------------------------------------------
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
  throw new Error(
    `Transaction ${txHash} not determined after ${retries} retries.`
  );
}

// -------------------------------------------------------------------------
// Helper: Convert numeric amount to blockchain representation
// -------------------------------------------------------------------------
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

// -------------------------------------------------------------------------
// Helper: Send usage fee (in REWARD tokens)
// -------------------------------------------------------------------------
async function sendUsageFee(pemContent) {
  const signer = UserSigner.fromPem(pemContent);
  const senderAddress = signer.getAddress();
  const receiverAddress = new Address(TREASURY_WALLET);

  const accountOnNetwork = await provider.getAccount(senderAddress);
  const nonce = accountOnNetwork.nonce;

  // Convert usage fee
  const decimals = await getTokenDecimals(REWARD_TOKEN);
  const convertedAmount = convertAmountToBlockchainValue(USAGE_FEE, decimals);

  // Construct a token-transfer transaction
  // (Manually using sdk-core or your own factory approach)
  const payload = TransactionPayload.contractCall()
    .setFunction("ESDTTransfer")
    .addArg(REWARD_TOKEN)              // token ID
    .addArg(convertedAmount)           // amount
    .build();

  const tx = new Transaction({
    nonce,
    receiver: receiverAddress,
    sender: senderAddress,
    value: 0, // no EGLD
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

// -------------------------------------------------------------------------
// Middleware: handle usage fee
// -------------------------------------------------------------------------
async function handleUsageFee(req, res, next) {
  try {
    const pemContent = getPemContent(req);
    const walletAddress = deriveWalletAddressFromPem(pemContent);

    // Check if the wallet is whitelisted => skip usage fee
    if (isWhitelisted(walletAddress)) {
      console.log(`Wallet ${walletAddress} is whitelisted. Skipping usage fee.`);
      return next();
    }

    // Otherwise, collect usage fee
    const txHash = await sendUsageFee(pemContent);
    req.usageFeeHash = txHash; 
    return next();
  } catch (error) {
    console.error('Error processing usageFee:', error.message);
    return res.status(400).json({ error: error.message });
  }
}

// Middleware to check authorization token for protected routes
const checkToken = (req, res, next) => {
  const token = req.headers.authorization;
  if (token === `Bearer ${SECURE_TOKEN}`) {
    next();
  } else {
    res.status(401).json({ error: 'Unauthorized' });
  }
};


// -------------------------------------------------------------------------
// 2) Example endpoint: /executeWarp
//    Accept user input, user PEM, and run the warp action
// -------------------------------------------------------------------------
app.post('/executeWarp', checkToken, handleUsageFee, async (req, res) => {
  try {
    // 1) Extract user PEM
    const pemContent = getPemContent(req);
    const signer = UserSigner.fromPem(pemContent);
    const userAddress = signer.getAddress();

    // 2) Gather user inputs for the Warp action
    //    For example, if your Warp blueprint requires:
    //    "Token Name", "Token Ticker", "Initial Supply", "Token Decimals"
    //    then parse them from request body:
    const {
      tokenName,
      tokenTicker,
      initialSupply,
      tokenDecimals
    } = req.body;

    // 3) Build the Warp from the on-chain transaction hash
    const warpBuilder = new WarpBuilder(warpConfig);
    const warp = await warpBuilder.createFromTransactionHash(WARP_HASH);
    if (!warp) {
      throw new Error(`Could not load Warp from hash: ${WARP_HASH}`);
    }

    // This example uses the FIRST action in warp.actions:
    // (In your "ESDT Creator" warp, the first action might be "issue")
    const action = warp.actions[0];
    if (!action) {
      throw new Error("No action found in this Warp blueprint!");
    }

    // 4) Build the userInputs object that matches your Warp blueprint fields
    //    e.g. if the Warp expects:
    //    "Token Name", "Token Ticker", "Initial Supply", "Token Decimals"
    //    then pass them exactly as named:
    const userInputs = {
      "Token Name": tokenName,
      "Token Ticker": tokenTicker,
      "Initial Supply": initialSupply,
      "Token Decimals": tokenDecimals
    };

    // 5) Create the transaction
    const warpActionExecutor = new WarpActionExecutor(warpConfig);
    const tx = warpActionExecutor.createTransactionForExecute(action, userInputs, /*transfers*/ []);

    // 6) Sign & broadcast
    //    The transaction returned by warpActionExecutor is a standard
    //    @multiversx/sdk-core Transaction, so we can sign & send:
    const accountOnNetwork = await provider.getAccount(userAddress);
    tx.setNonce(accountOnNetwork.nonce);

    await signer.sign(tx);
    const txHash = await provider.sendTransaction(tx);

    // 7) Wait for final status
    const status = await checkTransactionStatus(txHash.toString());

    // 8) Return the result
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

// -------------------------------------------------------------------------
app.listen(PORT, () => {
  console.log(`Warp integration app is running on port ${PORT}`);
});
