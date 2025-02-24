const Web3 = require('web3');
require('dotenv').config({ path: __dirname + '/../.env' });

console.log("🔹 BLOCKCHAIN_NODE_URL:", process.env.BLOCKCHAIN_NODE_URL);

if (!process.env.BLOCKCHAIN_NODE_URL) {
    console.error("❌ Error: BLOCKCHAIN_NODE_URL is not set in .env file.");
    process.exit(1);
}

const web3 = new Web3(new Web3.providers.HttpProvider(process.env.BLOCKCHAIN_NODE_URL));

console.log("✅ Web3 initialized successfully!");

// Ethereum Smart Contract Details (Replace with your deployed contract address and ABI)
const CONTRACT_ADDRESS = "0xYourSmartContractAddress";
const CONTRACT_ABI = [/* Your Smart Contract ABI JSON Here */];

const contract = new web3.eth.Contract(CONTRACT_ABI, CONTRACT_ADDRESS);
const account = "0xYourEthereumWalletAddress"; // Change this to your Ethereum wallet address

// 🔹 Store File Hash on Blockchain
async function storeFileHash(hash) {
    try {
        const tx = await contract.methods.storeFileHash(hash).send({
            from: account,
            gas: 3000000
        });
        console.log("✅ File hash stored on blockchain:", hash);
        return tx.transactionHash;
    } catch (error) {
        console.error("❌ Error storing file hash:", error);
        throw error;
    }
}

// 🔹 Verify File Ownership
async function verifyFileOwnership(hash) {
    try {
        const isStored = await contract.methods.checkFileHash(hash).call();
        console.log(`🔍 File Ownership Verified: ${isStored}`);
        return isStored;
    } catch (error) {
        console.error("❌ Error verifying file ownership:", error);
        throw error;
    }
}

module.exports = { storeFileHash, verifyFileOwnership };
