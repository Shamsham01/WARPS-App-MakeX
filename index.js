import express from 'express';
import bodyParser from 'body-parser';
import { Address } from '@multiversx/sdk-core';
import { ProxyNetworkProvider } from '@multiversx/sdk-network-providers';
import { UserSigner } from '@multiversx/sdk-wallet';
import { WarpBuilder, WarpActionExecutor, WarpLink, WarpRegistry } from '@vleap/warps';
import BigNumber from 'bignumber.js';

const provider = new ProxyNetworkProvider('https://gateway.multiversx.com', { clientName: 'warp-integration' });

const app = express();
const PORT = process.env.PORT || 3000;
const SECURE_TOKEN = process.env.SECURE_TOKEN || 'MY_SECURE_TOKEN';

app.use(bodyParser.json());

const warpConfig = {
  providerUrl: 'https://gateway.multiversx.com',
  currentUrl: process.env.CURRENT_URL || 'https://warps-makex.onrender.com',
  chainApiUrl: 'https://api.multiversx.com',
  env: 'mainnet',
  registryContract: 'erd1qqqqqqqqqqqqqpgq3mrpj3u6q7tejv6d7eqhnyd27n9v5c5tl3ts08mffe',
  userAddress: undefined
};

const checkToken = (req, res, next) => {
  const token = req.headers.authorization;
  if (token === `Bearer ${SECURE_TOKEN}`) {
    next();
  } else {
    res.status(401).json({ error: 'Unauthorized' });
  }
};

function getPemContent(req) {
  const pemContent = req.body.walletPem;
  if (!pemContent || typeof pemContent !== 'string' || !pemContent.includes('-----BEGIN PRIVATE KEY-----')) {
    throw new Error('Invalid PEM content'); // Added semicolon
  }
  return pemContent;
}

async function fetchWarpInfo(warpId) {
  const warpBuilder = new WarpBuilder(warpConfig);
  const warpLink = new WarpLink(warpConfig);
  const warpRegistry = new WarpRegistry(warpConfig);

  try {
    console.log(`Resolving ${warpId} via WarpLink...`);
    const result = await warpLink.detect(warpId);
    if (!result.match || !result.warp) {
      throw new Error(`Could not resolve ${warpId}`);
    }
    console.log(`Resolved ${warpId} to hash: ${result.warp.meta?.hash || 'unknown hash'}`);

    const registryInfo = await warpRegistry.getInfoByAlias(warpId);
    if (!registryInfo || !registryInfo.inputs) {
      console.warn(`No registry info or inputs found for ${warpId}, using default warp data`);
    }

    return {
      ...result.warp,
      registryInputs: registryInfo?.inputs || result.warp.actions[0]?.inputs || []
    };
  } catch (error) {
    console.error(`Error resolving ${warpId} via WarpLink/Registry: ${error.message}`);
    throw new Error(`Failed to resolve ${warpId}. Use a valid alias or hash.`);
  }
}

async function checkTransactionStatus(txHash, retries = 20, delay = 3000) {
  const txStatusUrl = `https://api.multiversx.com/transactions/${txHash}`;
  for (let i = 0; i < retries; i++) {
    try {
      console.log(`Attempt ${i + 1}/${retries} to check transaction ${txHash} status at ${new Date().toISOString()}...`);
      const response = await fetch(txStatusUrl, { timeout: 5000 });
      if (!response.ok) {
        console.warn(`Non-200 response for ${txHash}: ${response.status}`);
        throw new Error(`HTTP error ${response.status}`);
      }
      const txStatus = await response.json();
      console.log(`Transaction ${txHash} status: ${txStatus.status || 'undefined'}`);

      if (txStatus.status === 'success') {
        return { status: 'success', txHash };
      } else if (txStatus.status === 'fail' || txStatus.status === 'invalid') {
        return { status: 'fail', txHash, details: txStatus.error || txStatus.receipt?.data || 'No error details provided' };
      }

      console.log(`Transaction ${txHash} still pending, retrying...`);
      await new Promise(resolve => setTimeout(resolve, delay));
    } catch (error) {
      console.error(`Error fetching transaction ${txHash} (attempt ${i + 1}): ${error.message}`);
    }
  }
  throw new Error(`Transaction ${txHash} status could not be determined after ${retries} retries.`);
}

function mapTypeFromRegistryOrDefault(input) {
  const type = input.type.split(':')[0];
  const registryType = input.registryType || type;

  switch (registryType.toLowerCase()) {
    case 'string':
      return { makeType: 'text', validation: { pattern: input.pattern, minLength: input.min, maxLength: input.max } };
    case 'uint8':
    case 'uint16':
    case 'uint32':
    case 'uint64':
    case 'biguint':
      return { makeType: 'number', validation: { min: input.min, max: input.max, scale: input.modifier?.startsWith('scale:') ? input.modifier.split(':')[1] : null } };
    case 'bool':
      return { makeType: 'boolean', validation: {} };
    case 'address':
      return { makeType: 'text', validation: { address: true } };
    case 'token':
    case 'codesdata':
    case 'hex':
    case 'esdt':
    case 'nft':
      return { makeType: 'text', validation: {} };
    case 'date':
      return { makeType: 'date', validation: {} };
    case 'option':
    case 'optional':
      const baseType = input.type.split(':')[1] || 'text';
      const baseMapping = mapTypeFromRegistryOrDefault({ type: baseType });
      return { makeType: baseMapping.makeType, validation: { ...baseMapping.validation, optional: true } };
    case 'list':
      const listType = input.type.split(':')[1] || 'text';
      const listMapping = mapTypeFromRegistryOrDefault({ type: listType });
      return { makeType: 'array', validation: { itemType: listMapping.makeType, ...listMapping.validation } };
    case 'varladic':
      const varladicType = input.type.split(':')[1].split('|')[0] || 'text';
      const varladicMapping = mapTypeFromRegistryOrDefault({ type: varladicType });
      return { makeType: 'array', validation: { itemType: varladicMapping.makeType, ...varladicMapping.validation } };
    case 'composite':
      return { makeType: 'text', validation: { composite: true, types: input.type.split(':')[1].split('|') || [] } };
    default:
      console.warn(`Unknown type ${registryType} for input ${input.name}, defaulting to text`);
      return { makeType: 'text', validation: {} };
  }
}

app.get('/warpInfo', checkToken, async (req, res) => {
  try {
    const { warpId } = req.query;
    if (!warpId) throw new Error('Missing warpId in query parameters');

    console.log(`Fetching WARP input requirements for warpId: ${warpId}`);
    const warp = await fetchWarpInfo(warpId);
    const action = warp.actions[0];
    if (!action || action.type !== 'contract') {
      throw new Error(`WARP ${warpId} must have a 'contract' action`);
    }

    const inputs = warp.registryInputs || action.inputs || [];
    const mappedInputs = inputs.map(input => {
      const { makeType, validation } = mapTypeFromRegistryOrDefault(input);
      return {
        name: input.name,
        type: makeType,
        label: input.name,
        required: input.required || false,
        ...validation
      };
    });

    console.log(`WARP Input Requirements Response:`, mappedInputs);
    return res.json(mappedInputs);
  } catch (error) {
    console.error('Error in /warpInfo:', error.message);
    return res.status(400).json({ error: error.message });
  }
});

app.post('/executeWarp', checkToken, async (req, res) => {
  try {
    const { warpId, inputs } = req.body;
    if (!warpId) throw new Error('Missing warpId in request body');

    let normalizedInputs = {};
    if (!inputs) {
      console.warn('No inputs provided in request body, checking WARP requirements...');
      const warpInfo = await fetchWarpInfo(warpId);
      const action = warpInfo.actions[0];
      if (!action || !action.inputs || action.inputs.length === 0) {
        normalizedInputs = {};
      } else {
        throw new Error('Missing required \'inputs\' object in request body');
      }
    } else if (typeof inputs === 'object' && !Array.isArray(inputs)) {
      normalizedInputs = inputs;
    } else if (Array.isArray(inputs)) {
      inputs.forEach(input => {
        if (input.name && input.value !== undefined) {
          normalizedInputs[input.name] = input.value;
        }
      });
    } else {
      throw new Error('Invalid \'inputs\' format in request body; must be an object or array');
    }

    console.log(`Normalized Inputs for warpId ${warpId}:`, normalizedInputs);

    const pemContent = getPemContent(req);
    const signer = UserSigner.fromPem(pemContent);
    const userAddress = signer.getAddress();

    const warpInfo = await fetchWarpInfo(warpId);
    const action = warpInfo.actions[0];
    if (!action || action.type !== 'contract') {
      throw new Error(`WARP ${warpId} must have a 'contract' action`);
    }

    const inputsSpec = warpInfo.registryInputs || action.inputs || [];
    const userInputsArray = [];

    for (const inputSpec of inputsSpec) {
      const fieldName = inputSpec.name;
      const value = normalizedInputs[fieldName];

      if (inputSpec.required && (value === undefined || value === null || value === '')) {
        throw new Error(`Missing required input: ${fieldName}`);
      }

      if (value !== undefined && value !== null && value !== '') {
        let typedValue = value;
        const { makeType, validation } = mapTypeFromRegistryOrDefault(inputSpec);
        try {
          switch (makeType) {
            case 'text':
              if (typeof typedValue !== 'string') throw new Error(`${fieldName} must be a string`);
              if (validation.pattern && !new RegExp(validation.pattern).test(typedValue)) {
                throw new Error(`${fieldName} must match pattern: ${validation.patternDescription || validation.pattern}`);
              }
              if (validation.minLength && typedValue.length < validation.minLength) {
                throw new Error(`${fieldName} must be at least ${validation.minLength} characters`);
              }
              if (validation.maxLength && typedValue.length > validation.maxLength) {
                throw new Error(`${fieldName} must not exceed ${validation.maxLength} characters`);
              }
              break;
            case 'number':
              if (isNaN(typedValue) || typeof typedValue !== 'string' && typeof typedValue !== 'number') {
                throw new Error(`${fieldName} must be a number or numeric string`);
              }
              typedValue = new BigNumber(typedValue).toFixed(0).toString();
              if (validation.scale) {
                if (validation.scale === 'Token Decimals') {
                  const decimals = normalizedInputs['Token Decimals'];
                  if (decimals === undefined || isNaN(decimals)) {
                    throw new Error(`Missing or invalid 'Token Decimals' for scaling ${fieldName}`);
                  }
                  const actualDecimals = parseInt(decimals, 10);
                  if (actualDecimals < 0 || actualDecimals > 18) {
                    throw new Error(`'Token Decimals' must be between 0 and 18`);
                  }
                  typedValue = new BigNumber(typedValue).times(new BigNumber(10).pow(actualDecimals)).toFixed(0);
                } else {
                  const decimals = parseInt(validation.scale, 10);
                  if (isNaN(decimals)) throw new Error(`Invalid scale modifier for ${fieldName}`);
                  typedValue = new BigNumber(typedValue).times(new BigNumber(10).pow(decimals)).toFixed(0);
                }
              }
              if (validation.min && new BigNumber(typedValue).lt(validation.min)) {
                throw new Error(`${fieldName} must be at least ${validation.min}`);
              }
              if (validation.max && new BigNumber(typedValue).gt(validation.max)) {
                throw new Error(`${fieldName} must not exceed ${validation.max}`);
              }
              break;
            case 'boolean':
              if (typedValue !== true && typedValue !== false && typedValue !== 'true' && typedValue !== 'false') {
                throw new Error(`${fieldName} must be a boolean value (true/false)`);
              }
              typedValue = typedValue === true || typedValue === 'true';
              break;
            case 'date':
              if (!new Date(typedValue).getTime()) throw new Error(`${fieldName} must be a valid date`);
              typedValue = new Date(typedValue).toISOString();
              break;
            case 'array':
              if (typeof typedValue !== 'string' && !Array.isArray(typedValue)) {
                throw new Error(`${fieldName} must be a string or array of values`);
              }
              if (typeof typedValue === 'string') typedValue = typedValue.split(',').map(v => v.trim());
              typedValue = typedValue.map(v => handleNestedType(v, validation.itemType || 'text'));
              break;
            default:
              if (typeof typedValue !== 'string') throw new Error(`${fieldName} must be a string for type ${makeType}`);
              break;
          }

          if (Array.isArray(typedValue)) {
            userInputsArray.push(...typedValue.map(v => `${makeType}:${v}`));
          } else if (typedValue !== null) {
            userInputsArray.push(`${makeType}:${typedValue}`);
          }
        } catch (validationError) {
          throw new Error(`Validation error for ${fieldName}: ${validationError.message}`);
        }
      }
    }

    function handleNestedType(value, baseType) {
      switch (baseType.toLowerCase()) {
        case 'text':
          if (typeof value !== 'string') throw new Error(`Value must be a string`);
          return value;
        case 'number':
          if (isNaN(value)) throw new Error(`Value must be a number`);
          return new BigNumber(value).toFixed(0).toString();
        case 'boolean':
          if (value !== true && value !== false && value !== 'true' && value !== 'false') {
            throw new Error(`Value must be a boolean (true/false)`);
          }
          return value === true || value === 'true';
        case 'address':
          if (!Address.isValid(value)) throw new Error(`Value must be a valid Multiversx address`);
          return value;
        default:
          return value.toString();
      }
    }

    const executorConfig = { ...warpConfig, userAddress: userAddress.bech32() };
    const warpActionExecutor = new WarpActionExecutor(executorConfig);
    const tx = warpActionExecutor.createTransactionForExecute(action, userInputsArray, []);

    const accountOnNetwork = await provider.getAccount(userAddress);
    tx.nonce = accountOnNetwork.nonce;
    await signer.sign(tx);
    const txHash = await provider.sendTransaction(tx);
    const status = await checkTransactionStatus(txHash.toString());

    if (status.status === 'fail') {
      return res.status(400).json({
        error: `Transaction failed: ${status.details || 'Unknown reason'}`
      });
    }

    return res.json({
      warpId,
      warpHash: warpInfo.meta?.hash,
      finalTxHash: txHash.toString(),
      finalStatus: status.status
    });
  } catch (error) {
    console.error('Error in /executeWarp:', error.message, 'Request Body:', req.body);
    return res.status(400).json({ error: error.message });
  }
});

app.listen(PORT, () => {
  console.log(`Warp integration app is running on port ${PORT}`);
});
