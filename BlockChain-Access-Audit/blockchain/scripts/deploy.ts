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

const initialAssignments = process.env.INITIAL_ROLE_ASSIGNMENTS;
if (initialAssignments) {
  const assignments: Array<{ address: string; role: number; userId: string }> =
    JSON.parse(initialAssignments);
  for (const assignment of assignments) {
    if (![2, 3, 4].includes(assignment.role) || !assignment.userId) {
      throw new Error("Each initial role needs role 2/3/4 and a userId.");
    }
    const userIdHash = ethers.sha256(ethers.toUtf8Bytes(assignment.userId));
    await (await contract.grantRole(assignment.address, assignment.role, userIdHash)).wait();
    console.log(`Granted role ${assignment.role} to ${assignment.address}`);
  }
}

const contractAddress =
  await contract.getAddress();

console.log(
  "AccessAndAudit deployed to:",
  contractAddress
);
