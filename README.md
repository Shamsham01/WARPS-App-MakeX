# WARPS-App-MakeX

A powerful integration between MultiversX WARPS Protocol and Make.com (formerly Integromat) enabling no-code blockchain interactions.

## Overview

WARPS-App-MakeX serves as a middleware API that connects [MultiversX WARPS Protocol](https://usewarp.to/) with [Make.com](https://make.com/), allowing users to create automated blockchain workflows without writing code. This service facilitates the execution of blockchain operations through a simple HTTP API, making blockchain technology accessible to a wider audience.

## Features

- **Dynamic WARP Integration**: Automatically generates input fields from WARP requirements
- **Secure Wallet Handling**: Uses PEM format for secure transaction signing
- **Usage Fee System**: Implements a dynamic fee system based on REWARD token value
- **Whitelisting**: Allows specific wallets to bypass the usage fee
- **Transaction Monitoring**: Provides transaction status tracking
- **Rate Limiting & Security**: Implements best practices for API security

## Important Notice

**This service is already deployed and available for use.** Users do not need to deploy this code themselves. A usage fee is charged to cover server costs and maintenance. The deployment instructions in this repository are provided for developers who wish to host their own instance of the service.

## API Endpoints

### 1. Authorization Check
- **Endpoint**: `POST /authorization`
- **Description**: Validates API access tokens
- **Headers**: `Authorization: Bearer YOUR_SECURE_TOKEN`

### 2. Fetch Dynamic Input Fields
- **Endpoint**: `GET /warpRPC?warpId=YOUR_WARP_ID`
- **Description**: Returns the expected input fields for a specific WARP
- **Headers**: `Authorization: Bearer YOUR_SECURE_TOKEN`

### 3. Execute WARP
- **Endpoint**: `POST /executeWarp`
- **Description**: Executes a WARP with the provided inputs
- **Headers**: `Authorization: Bearer YOUR_SECURE_TOKEN`
- **Body**:
  ```json
  {
    "warpId": "your-warp-identifier",
    "walletPem": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----",
    "inputs": {
      "param1": "value1",
      "param2": "value2"
    }
  }
  ```

### 4. Health Check
- **Endpoint**: `GET /health`
- **Description**: Provides server status information

## PEM File Security & Generation

### Important Security Notice
- PEM files contain your private keys and should **NEVER** be shared with anyone
- During the authorization process, users must provide the wallet PEM file content
- After successful authorization with the custom app, the PEM file content will be stored under the user's profile connection settings on Make.com
- We **strongly advise** creating and funding a new wallet specifically for automation purposes
  - Fund this wallet with:
    - EGLD for transaction fees
    - REWARD tokens for usage fees

### MultiversX PEM Generator
We have developed a web application that helps users safely derive and download PEM files from their secret phrases:
- **PEM Generator Tool**: [https://subtle-crepe-8124c7.netlify.app/](https://subtle-crepe-8124c7.netlify.app/)
- This tool allows you to securely generate PEM files without exposing your mnemonic phrase to third parties

## Using with Make.com

We have already developed custom apps for Make.com that utilize this service. Users can simply:

1. Access the existing custom app in Make.com
2. Create a connection and authorize it with your PEM file content
3. Set up scenarios that utilize the WARPS functionality
4. Ensure your connected wallet has sufficient EGLD and REWARD tokens

**Note:** If you prefer to own the solution entirely, you can create your own custom app on Make.com based on this code and deploy your own instance of the service. This approach requires technical knowledge and additional setup.

## Security Considerations

- **Private Key Protection**: PEM files contain your private keys and should be handled with extreme caution. Only enter your PEM data in trusted applications like our Make.com custom app connection.
- **Connection Security**: When you set up a connection in Make.com, your PEM data is stored securely in your Make.com account settings, not on our servers.
- **Dedicated Wallets**: Use dedicated wallets for automation with limited funds to minimize risk in case of compromised credentials.
- **HTTPS Only**: All API communication must use HTTPS to ensure encrypted data transmission.
- **Usage Limitations**: Consider implementing usage limits and monitoring to detect unusual activity.
- **Regular Auditing**: Periodically review your automation scenarios and connected wallets for security.

## For Developers

The following sections are relevant only if you wish to deploy your own instance of this service.

### Prerequisites
- Node.js >= 14.0.0
- MultiversX account and wallet
- REWARD tokens for transaction fees (unless whitelisted)

### Environment Variables
The following environment variables must be configured:

- `SECURE_TOKEN`: API security token
- `PORT`: Server port (default: 10000)
- `CURRENT_URL`: Your application's public URL
- `REWARD_TOKEN`: Token identifier for usage fees (default: REWARD-cf6eac)
- `TREASURY_WALLET`: Wallet address for collecting fees

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/Shamsham01/WARPS-App-MakeX.git
   cd WARPS-App-MakeX
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Configure environment variables (create a `.env` file):
   ```
   SECURE_TOKEN=your_secure_token
   PORT=10000
   CURRENT_URL=https://your-app-url.com
   ```

4. Start the server:
   ```bash
   npm start
   ```

### Deployment on Render

This application is configured for easy deployment on [Render](https://render.com/) using the included `render.yaml` file.

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy)

### Whitelisting

To add wallets to the whitelist (exempt from usage fees):

1. Edit the `whitelist.json` file to include wallet addresses:
   ```json
   [
     {
       "walletAddress": "erd1...",
       "label": "Description",
       "whitelistStart": "2024-01-01T00:00:00Z"
     }
   ]
   ```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Support

For support or questions, please open an issue in the GitHub repository or contact the maintainers directly.
