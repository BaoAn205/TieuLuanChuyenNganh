import { network } from "hardhat";

const { ethers } = await network.getOrCreate();

const signers = await ethers.getSigners();
const [deployer] = signers;

console.log("Deploying with account:", deployer.address);

const AccessAndAudit =
  await ethers.getContractFactory("AccessAndAudit");

const contract =
  await AccessAndAudit.deploy();

await contract.waitForDeployment();

const demoRoles = [
  { signerIndex: 1, role: 2, userId: "staff-001" },
  { signerIndex: 2, role: 3, userId: "auditor-001" },
  { signerIndex: 3, role: 4, userId: "customer-001" },
];

for (const assignment of demoRoles) {
  const signer = signers[assignment.signerIndex];
  if (!signer) continue;
  const userIdHash = ethers.sha256(ethers.toUtf8Bytes(assignment.userId));
  await (await contract.grantRole(signer.address, assignment.role, userIdHash)).wait();
  console.log(`Granted role ${assignment.role} to ${signer.address}`);
}

const contractAddress =
  await contract.getAddress();

console.log(
  "AccessAndAudit deployed to:",
  contractAddress
);