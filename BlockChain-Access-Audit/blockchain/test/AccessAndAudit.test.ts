import { expect } from "chai";
import { network } from "hardhat";

describe("AccessAndAudit", function () {
    let ethers: any;
  async function deployContract() {
    const connection = await network.getOrCreate();
    ethers = connection.ethers;

    const [
      admin,
      staff,
      auditor,
      customer,
      attacker,
    ] = await ethers.getSigners();

    const AccessAndAudit =
      await ethers.getContractFactory("AccessAndAudit");

    const contract =
      await AccessAndAudit.deploy();

    await contract.waitForDeployment();

    return {
      contract,
      admin,
      staff,
      auditor,
      customer,
      attacker,
    };
  }

  describe("Deployment", function () {
    it("Deployer should become ADMIN", async function () {
      const { contract, admin } = await deployContract();

      const ADMIN = 1;

      expect(
        await contract.getRole(admin.address)
      ).to.equal(ADMIN);
    });
  });

  describe("Role Management", function () {
    it("ADMIN can grant STAFF role", async function () {
      const { contract, admin, staff } =
        await deployContract();

      const STAFF = 2;

      await contract
        .connect(admin)
        .grantRole(
          staff.address,
          STAFF,
          ethers.ZeroHash
        );

      expect(
        await contract.getRole(staff.address)
      ).to.equal(STAFF);
    });

    it("ADMIN can grant AUDITOR role", async function () {
      const { contract, admin, auditor } =
        await deployContract();

      const AUDITOR = 3;

      await contract
        .connect(admin)
        .grantRole(
          auditor.address,
          AUDITOR,
          ethers.ZeroHash
        );

      expect(
        await contract.getRole(auditor.address)
      ).to.equal(AUDITOR);
    });

    it("ADMIN can grant CUSTOMER role", async function () {
      const { contract, admin, customer } =
        await deployContract();

      const CUSTOMER = 4;

      const userIdHash =
        ethers.keccak256(
          ethers.toUtf8Bytes("user001")
        );

      await contract
        .connect(admin)
        .grantRole(
          customer.address,
          CUSTOMER,
          userIdHash
        );

      expect(
        await contract.getRole(customer.address)
      ).to.equal(CUSTOMER);

      expect(
        await contract.getCustomerUserIdHash(
          customer.address
        )
      ).to.equal(userIdHash);
    });

    it("Non-ADMIN cannot grant a role", async function () {
      const { contract, staff, attacker } =
        await deployContract();

      const STAFF = 2;

      await expect(
        contract
          .connect(staff)
          .grantRole(
            attacker.address,
            STAFF,
            ethers.ZeroHash
          )
      ).to.be.revertedWith(
        "Access denied: ADMIN only"
      );
    });

    it("ADMIN can revoke a role", async function () {
      const { contract, admin, staff } =
        await deployContract();

      const STAFF = 2;

      await contract
        .connect(admin)
        .grantRole(
          staff.address,
          STAFF,
          ethers.ZeroHash
        );

      await contract
        .connect(admin)
        .revokeRole(staff.address);

      expect(
        await contract.getRole(staff.address)
      ).to.equal(0);
    });
  });

  describe("Audit Recording", function () {
    it("STAFF can record an audit event", async function () {
      const { contract, admin, staff } =
        await deployContract();

      const STAFF = 2;

      await contract
        .connect(admin)
        .grantRole(
          staff.address,
          STAFF,
          ethers.ZeroHash
        );

      const eventId = 1001;

      const userIdHash =
        ethers.keccak256(
          ethers.toUtf8Bytes("user001")
        );

      const dataHash =
        ethers.keccak256(
          ethers.toUtf8Bytes(
            "TRANSFER:1000000:SUCCESS"
          )
        );

      await expect(
        contract
          .connect(staff)
          .recordAudit(
            eventId,
            userIdHash,
            "TRANSFER",
            "ACCOUNT_001",
            1750000000,
            "SUCCESS",
            dataHash
          )
      ).to.emit(
        contract,
        "AuditRecorded"
      );
    });

    it("AUDITOR cannot record an audit event", async function () {
      const {
        contract,
        admin,
        auditor,
      } = await deployContract();

      const AUDITOR = 3;

      await contract
        .connect(admin)
        .grantRole(
          auditor.address,
          AUDITOR,
          ethers.ZeroHash
        );

      await expect(
        contract
          .connect(auditor)
          .recordAudit(
            1001,
            ethers.ZeroHash,
            "LOGIN",
            "SYSTEM",
            1750000000,
            "SUCCESS",
            ethers.keccak256(
              ethers.toUtf8Bytes("test")
            )
          )
      ).to.be.revertedWith(
        "Access denied: cannot record audit"
      );
    });

    it("CUSTOMER cannot record an audit event", async function () {
      const {
        contract,
        admin,
        customer,
      } = await deployContract();

      const CUSTOMER = 4;

      await contract
        .connect(admin)
        .grantRole(
          customer.address,
          CUSTOMER,
          ethers.keccak256(
            ethers.toUtf8Bytes("user001")
          )
        );

      await expect(
        contract
          .connect(customer)
          .recordAudit(
            1001,
            ethers.ZeroHash,
            "TRANSFER",
            "ACCOUNT_001",
            1750000000,
            "SUCCESS",
            ethers.keccak256(
              ethers.toUtf8Bytes("test")
            )
          )
      ).to.be.revertedWith(
        "Access denied: cannot record audit"
      );
    });

    it("Cannot record duplicate event ID", async function () {
      const { contract, admin, staff } =
        await deployContract();

      const STAFF = 2;

      await contract
        .connect(admin)
        .grantRole(
          staff.address,
          STAFF,
          ethers.ZeroHash
        );

      const dataHash =
        ethers.keccak256(
          ethers.toUtf8Bytes("test")
        );

      await contract
        .connect(staff)
        .recordAudit(
          1001,
          ethers.ZeroHash,
          "LOGIN",
          "SYSTEM",
          1750000000,
          "SUCCESS",
          dataHash
        );

      await expect(
        contract
          .connect(staff)
          .recordAudit(
            1001,
            ethers.ZeroHash,
            "LOGIN",
            "SYSTEM",
            1750000001,
            "SUCCESS",
            dataHash
          )
      ).to.be.revertedWith(
        "Audit event already exists"
      );
    });
  });

  describe("Audit Reading", function () {
    it("AUDITOR can read audit events", async function () {
      const {
        contract,
        admin,
        staff,
        auditor,
      } = await deployContract();

      const STAFF = 2;
      const AUDITOR = 3;

      await contract
        .connect(admin)
        .grantRole(
          staff.address,
          STAFF,
          ethers.ZeroHash
        );

      await contract
        .connect(admin)
        .grantRole(
          auditor.address,
          AUDITOR,
          ethers.ZeroHash
        );

      const dataHash =
        ethers.keccak256(
          ethers.toUtf8Bytes("LOGIN:test")
        );

      await contract
        .connect(staff)
        .recordAudit(
          1001,
          ethers.ZeroHash,
          "LOGIN",
          "SYSTEM",
          1750000000,
          "SUCCESS",
          dataHash
        );

      const audit =
        await contract
          .connect(auditor)
          .getAudit(1001);

      expect(audit[0]).to.equal(1001);
      expect(audit[2]).to.equal("LOGIN");
      expect(audit[5]).to.equal("SUCCESS");
      expect(audit[6]).to.equal(dataHash);
      expect(audit[7]).to.equal(staff.address);
    });

    it("CUSTOMER cannot read arbitrary audit events", async function () {
      const {
        contract,
        admin,
        customer,
      } = await deployContract();

      const CUSTOMER = 4;

      await contract
        .connect(admin)
        .grantRole(
          customer.address,
          CUSTOMER,
          ethers.keccak256(
            ethers.toUtf8Bytes("user001")
          )
        );

      await expect(
        contract
          .connect(customer)
          .getAudit(1001)
      ).to.be.revertedWith(
        "Access denied: cannot read audit"
      );
    });
    it("CUSTOMER can read only their own audit events", async function () {
  const {
    contract,
    admin,
    staff,
    customer,
  } = await deployContract();

  const STAFF = 2;
  const CUSTOMER = 4;

  const customerUserIdHash =
    ethers.keccak256(
      ethers.toUtf8Bytes("user001")
    );

  const otherUserIdHash =
    ethers.keccak256(
      ethers.toUtf8Bytes("user002")
    );

    // Grant STAFF role
    await contract
        .connect(admin)
        .grantRole(
        staff.address,
        STAFF,
        ethers.ZeroHash
        );

    // Grant CUSTOMER role to customer
    await contract
        .connect(admin)
        .grantRole(
        customer.address,
        CUSTOMER,
        customerUserIdHash
        );

    // Create audit event belonging to customer
    const customerDataHash =
        ethers.keccak256(
        ethers.toUtf8Bytes("CUSTOMER_TRANSFER")
        );

    await contract
        .connect(staff)
        .recordAudit(
        1001,
        customerUserIdHash,
        "TRANSFER",
        "ACCOUNT_001",
        1750000000,
        "SUCCESS",
        customerDataHash
        );

    // Customer can read their own audit
    const ownAudit =
        await contract
        .connect(customer)
        .getMyAudit(1001);

    expect(ownAudit[0]).to.equal(1001);
    expect(ownAudit[1]).to.equal(
        customerUserIdHash
    );

    // Create another audit belonging to another user
    const otherDataHash =
        ethers.keccak256(
        ethers.toUtf8Bytes("OTHER_TRANSFER")
        );

    await contract
        .connect(staff)
        .recordAudit(
        1002,
        otherUserIdHash,
        "TRANSFER",
        "ACCOUNT_002",
        1750000001,
        "SUCCESS",
        otherDataHash
        );

    // Customer must NOT be able to read another user's audit
    await expect(
        contract
        .connect(customer)
        .getMyAudit(1002)
    ).to.be.revertedWith(
        "Access denied: not your audit"
    );
    });
  });

  describe("Audit Integrity Verification", function () {
    it("Correct hash should verify successfully", async function () {
      const { contract, admin, staff } =
        await deployContract();

      const STAFF = 2;

      await contract
        .connect(admin)
        .grantRole(
          staff.address,
          STAFF,
          ethers.ZeroHash
        );

      const dataHash =
        ethers.keccak256(
          ethers.toUtf8Bytes(
            "TRANSFER:1000000:SUCCESS"
          )
        );

      await contract
        .connect(staff)
        .recordAudit(
          1001,
          ethers.ZeroHash,
          "TRANSFER",
          "ACCOUNT_001",
          1750000000,
          "SUCCESS",
          dataHash
        );

      const result =
        await contract
          .connect(staff)
          .verifyAudit(
            1001,
            dataHash
          );

      expect(result).to.equal(true);
    });

    it("Modified hash should fail verification", async function () {
      const { contract, admin, staff } =
        await deployContract();

      const STAFF = 2;

      await contract
        .connect(admin)
        .grantRole(
          staff.address,
          STAFF,
          ethers.ZeroHash
        );

      const originalHash =
        ethers.keccak256(
          ethers.toUtf8Bytes(
            "TRANSFER:1000000:SUCCESS"
          )
        );

      const modifiedHash =
        ethers.keccak256(
          ethers.toUtf8Bytes(
            "TRANSFER:9000000:SUCCESS"
          )
        );

      await contract
        .connect(staff)
        .recordAudit(
          1001,
          ethers.ZeroHash,
          "TRANSFER",
          "ACCOUNT_001",
          1750000000,
          "SUCCESS",
          originalHash
        );

      const result =
        await contract
          .connect(staff)
          .verifyAudit(
            1001,
            modifiedHash
          );

      expect(result).to.equal(false);
    });
  });
});