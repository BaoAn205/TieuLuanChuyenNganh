import { network } from "hardhat";

const walletAddress = process.env.CUSTOMER_WALLET_ADDRESS;
const userId = process.env.CUSTOMER_USER_ID;
const contractAddress = process.env.BLOCKCHAIN_CONTRACT_ADDRESS;

if (!walletAddress || !userId || !contractAddress) {
  throw new Error(
    "Set CUSTOMER_WALLET_ADDRESS, CUSTOMER_USER_ID, and BLOCKCHAIN_CONTRACT_ADDRESS.",
  );
}

const { ethers } = await network.getOrCreate();
const [admin] = await ethers.getSigners();
if (!admin) throw new Error("No Ganache signer found.");

const contract = await ethers.getContractAt(
  "AccessAndAudit",
  contractAddress,
  admin,
);
const role = 4; // CUSTOMER
const userIdHash = ethers.sha256(ethers.toUtf8Bytes(userId));

console.log(`Granting CUSTOMER to ${walletAddress} as ${admin.address}`);
const tx = await contract.grantRole(walletAddress, role, userIdHash);
console.log(`Transaction submitted: ${tx.hash}`);
await tx.wait();
console.log(`CUSTOMER role granted to ${walletAddress} for ${userId}.`);
