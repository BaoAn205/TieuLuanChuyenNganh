import { network } from "hardhat";

const { ethers } = await network.getOrCreate();

const [deployer] = await ethers.getSigners();

console.log("Deploying with account:", deployer.address);

const AccessAndAudit =
  await ethers.getContractFactory("AccessAndAudit");

const contract =
  await AccessAndAudit.deploy();

await contract.waitForDeployment();

const contractAddress =
  await contract.getAddress();

console.log(
  "AccessAndAudit deployed to:",
  contractAddress
);