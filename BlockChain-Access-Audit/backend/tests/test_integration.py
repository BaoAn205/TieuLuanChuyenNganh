import json
import hashlib
import os
import socket
import subprocess
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from web3 import Account, Web3

from app import main


PROJECT_DIR = Path(__file__).resolve().parents[2]
BLOCKCHAIN_DIR = PROJECT_DIR / "blockchain"
ARTIFACT_PATH = BLOCKCHAIN_DIR / "artifacts" / "contracts" / "AccessAndAudit.sol" / "AccessAndAudit.json"
TEST_PRIVATE_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
DEMO_WALLETS = {
    "admin-001": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
    "staff-001": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
    "auditor-001": "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
    "customer-001": "0x90F79bf6EB2c4f870365E785982E1f101E93b906",
}
DEMO_ROLE_IDS = {"admin-001": 1, "staff-001": 2, "auditor-001": 3, "customer-001": 4}


@pytest.fixture(scope="session")
def local_chain():
    with socket.socket() as port_socket:
        port_socket.bind(("127.0.0.1", 0))
        port = port_socket.getsockname()[1]
    command = (
        f'npx ganache --server.host 127.0.0.1 --server.port {port} '
        '--chain.chainId 31337 '
        '--wallet.mnemonic "test test test test test test test test test test test junk"'
    )
    process = subprocess.Popen(
        command,
        cwd=BLOCKCHAIN_DIR,
        shell=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
    )
    rpc_url = f"http://127.0.0.1:{port}"
    web3 = Web3(Web3.HTTPProvider(rpc_url))
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline and not web3.is_connected():
        if process.poll() is not None:
            pytest.fail("Hardhat node exited before becoming ready")
        time.sleep(0.25)
    if not web3.is_connected():
        process.terminate()
        pytest.fail("Hardhat node did not become ready within 45 seconds")
    yield web3, rpc_url
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            check=False,
            capture_output=True,
        )
    else:
        process.terminate()
        process.wait(timeout=10)


@pytest.fixture
def deployed_contract(local_chain):
    web3, _ = local_chain
    subprocess.run("npx hardhat compile", cwd=BLOCKCHAIN_DIR, shell=True, check=True)
    artifact = json.loads(ARTIFACT_PATH.read_text(encoding="utf-8"))
    signer = Account.from_key(TEST_PRIVATE_KEY)
    factory = web3.eth.contract(abi=artifact["abi"], bytecode=artifact["bytecode"])
    deployment = factory.constructor().build_transaction(
        {
            "from": signer.address,
            "nonce": web3.eth.get_transaction_count(signer.address),
            "chainId": web3.eth.chain_id,
            "gas": 4_000_000,
            "gasPrice": web3.eth.gas_price,
        }
    )
    signed = signer.sign_transaction(deployment)
    tx_hash = web3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
    contract = web3.eth.contract(address=receipt.contractAddress, abi=artifact["abi"])
    for user_id in ("staff-001", "auditor-001", "customer-001"):
        user_hash = hashlib.sha256(user_id.encode("utf-8")).digest()
        grant = contract.functions.grantRole(
            Web3.to_checksum_address(DEMO_WALLETS[user_id]),
            DEMO_ROLE_IDS[user_id],
            user_hash,
        ).transact({"from": signer.address})
        web3.eth.wait_for_transaction_receipt(grant)
    return receipt.contractAddress


@pytest.fixture
def client(tmp_path, monkeypatch, local_chain, deployed_contract):
    _, rpc_url = local_chain
    test_database_url = os.getenv("POSTGRES_TEST_DATABASE_URL")
    if not test_database_url:
        pytest.skip("Set POSTGRES_TEST_DATABASE_URL to a dedicated PostgreSQL test database")
    monkeypatch.setattr(main, "DATABASE_URL", test_database_url)
    monkeypatch.setattr(main, "BLOCKCHAIN_ENABLED", True)
    monkeypatch.setattr(main, "BLOCKCHAIN_RPC_URL", rpc_url)
    monkeypatch.setattr(main, "BLOCKCHAIN_CONTRACT_ADDRESS", deployed_contract)
    monkeypatch.setattr(main, "BLOCKCHAIN_PRIVATE_KEY", TEST_PRIVATE_KEY)
    with TestClient(main.app) as test_client:
        connection = main.connect()
        connection.execute("TRUNCATE audit_events, transactions, sessions, accounts, users RESTART IDENTITY CASCADE")
        connection.executemany(
            "INSERT INTO users (user_id, full_name, role, password, wallet_address) VALUES (?, ?, ?, ?, ?)",
            [
                ("admin-001", "System Administrator", "ADMIN", "admin123", DEMO_WALLETS["admin-001"]),
                ("staff-001", "Bank Staff", "STAFF", "staff123", DEMO_WALLETS["staff-001"]),
                ("auditor-001", "Audit Officer", "AUDITOR", "audit123", DEMO_WALLETS["auditor-001"]),
                ("customer-001", "Demo Customer", "CUSTOMER", "customer123", DEMO_WALLETS["customer-001"]),
            ],
        )
        connection.executemany(
            "INSERT INTO accounts (account_id, user_id, balance) VALUES (?, ?, ?)",
            [("ACC-1001", "customer-001", 10000), ("ACC-2002", "staff-001", 0)],
        )
        connection.commit()
        connection.close()
        yield test_client


def login(client, user_id, password):
    response = client.post(
        "/api/login",
        json={
            "userId": user_id,
            "password": password,
            "walletAddress": DEMO_WALLETS[user_id],
        },
    )
    assert response.status_code == 200
    return response.json()


def test_login_view_transfer_and_audit_log_e2e(client, local_chain, deployed_contract):
    customer = login(client, "customer-001", "customer123")
    customer_headers = {"Authorization": f"Bearer {customer['sessionToken']}"}
    assert len(customer["sessionToken"]) >= 40
    restored_session = client.get("/api/me", headers=customer_headers)
    assert restored_session.status_code == 200
    assert restored_session.json()["user"]["role"] == "CUSTOMER"

    account_response = client.get("/api/accounts/customer-001", headers=customer_headers)
    assert account_response.status_code == 200
    assert account_response.json()["accounts"][0]["account_id"] == "ACC-1001"

    beneficiary_response = client.get(
        "/api/beneficiaries/ACC-2002", headers=customer_headers
    )
    assert beneficiary_response.status_code == 200
    assert beneficiary_response.json()["accountName"] == "Bank Staff"

    self_transfer = client.post(
        "/api/transactions/transfer",
        headers=customer_headers,
        json={"userId": "customer-001", "toAccount": "ACC-1001", "amount": 1000},
    )
    assert self_transfer.status_code == 400

    with main.connect() as connection:
        connection.execute(
            "INSERT OR IGNORE INTO accounts (account_id, user_id, balance) VALUES (?, ?, ?)",
            ("ACC-2002", "staff-001", 0),
        )
        connection.commit()

    transfer_response = client.post(
        "/api/transactions/transfer",
        headers=customer_headers,
        json={"userId": "customer-001", "toAccount": "ACC-2002", "amount": 125},
    )
    assert transfer_response.status_code == 200
    transfer_event = transfer_response.json()["audit"]
    assert transfer_event["blockchainTxHash"]
    assert isinstance(transfer_event["blockchainBlockNumber"], int)
    assert isinstance(transfer_event["blockchainLogIndex"], int)

    canonical = json.dumps(
        {
            field: transfer_event[field]
            for field in (
                "eventId", "userId", "role", "action", "resource", "timestamp",
                "sourceIp", "result", "riskLevel", "details",
            )
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    expected_hash = __import__("hashlib").sha256(canonical.encode("utf-8")).hexdigest()
    assert transfer_event["dataHash"] == expected_hash

    web3, _ = local_chain
    artifact = json.loads(ARTIFACT_PATH.read_text(encoding="utf-8"))
    contract = web3.eth.contract(
        address=Web3.to_checksum_address(deployed_contract), abi=artifact["abi"]
    )
    chain_event = contract.functions.getAudit(transfer_event["eventId"]).call(
        {"from": Account.from_key(TEST_PRIVATE_KEY).address}
    )
    assert chain_event[6].hex().removeprefix("0x") == expected_hash
    receipt = web3.eth.get_transaction_receipt(transfer_event["blockchainTxHash"])
    assert receipt.blockNumber == transfer_event["blockchainBlockNumber"]
    matching_events = contract.events.AuditRecorded().process_receipt(receipt)
    assert len(matching_events) == 1
    assert matching_events[0]["logIndex"] == transfer_event["blockchainLogIndex"]
    assert matching_events[0]["args"]["eventId"] == transfer_event["eventId"]

    with main.connect() as connection:
        mapped_row = connection.execute(
            "SELECT * FROM audit_events WHERE event_id = ?",
            (transfer_event["eventId"],),
        ).fetchone()
    assert mapped_row["blockchain_tx_hash"] == transfer_event["blockchainTxHash"]
    assert mapped_row["blockchain_block_number"] == transfer_event["blockchainBlockNumber"]
    assert mapped_row["blockchain_log_index"] == transfer_event["blockchainLogIndex"]

    auditor = login(client, "auditor-001", "audit123")
    auditor_headers = {"Authorization": f"Bearer {auditor['sessionToken']}"}
    logs_response = client.get("/api/audit/logs", headers=auditor_headers)
    assert logs_response.status_code == 200
    logs = logs_response.json()["logs"]
    logged_transfer = next(row for row in logs if row["eventId"] == transfer_event["eventId"])
    assert {
        "eventId", "userId", "role", "action", "resource", "timestamp", "sourceIp",
        "result", "riskLevel", "dataHash", "blockchainTxHash", "details",
        "blockchainBlockNumber", "blockchainLogIndex",
    } <= logged_transfer.keys()
    assert logged_transfer["blockchainTxHash"] == transfer_event["blockchainTxHash"]

    encoded_time = transfer_event["timestamp"].replace("+", "%2B")
    filtered_logs = client.get(
        "/api/audit/logs?userId=customer-001&role=CUSTOMER&action=TRANSFER&blockchainStatus=recorded"
        f"&from={encoded_time}&to={encoded_time}",
        headers=auditor_headers,
    )
    assert filtered_logs.status_code == 200
    assert [row["eventId"] for row in filtered_logs.json()["logs"]] == [transfer_event["eventId"]]
    detail = client.get(
        f"/api/audit/logs/{transfer_event['eventId']}", headers=auditor_headers
    )
    assert detail.status_code == 200
    assert detail.json()["event"]["blockchainLogIndex"] == transfer_event["blockchainLogIndex"]

    customer_logs = client.get("/api/audit/logs", headers=customer_headers)
    assert customer_logs.status_code == 403
    own_logs = client.get("/api/audit/my-logs", headers=customer_headers)
    assert own_logs.status_code == 200
    assert all(row["userId"] == "customer-001" for row in own_logs.json()["events"])
    own_detail = client.get(
        f"/api/audit/logs/{transfer_event['eventId']}", headers=customer_headers
    )
    assert own_detail.status_code == 200
    auditor_event = next(row for row in logs if row["userId"] == "auditor-001")
    foreign_detail = client.get(
        f"/api/audit/logs/{auditor_event['eventId']}", headers=customer_headers
    )
    assert foreign_detail.status_code == 403

    administrator = login(client, "admin-001", "admin123")
    admin_headers = {"Authorization": f"Bearer {administrator['sessionToken']}"}
    admin_access_response = client.post("/api/admin/access", headers=admin_headers)
    assert admin_access_response.status_code == 200
    assert admin_access_response.json()["audit"]["action"] == "ADMIN_ACCESS"
    admin_logs = client.get("/api/audit/logs", headers=admin_headers)
    assert admin_logs.status_code == 200
    assert admin_logs.json()["logs"]

    verified = client.post(
        "/api/verify-integrity",
        headers=auditor_headers,
        json={"eventId": transfer_event["eventId"]},
    )
    assert verified.status_code == 200
    assert verified.json()["verified"] is True
    assert verified.json()["onChainVerified"] is True


def test_password_hashing_profile_logout_and_session_revocation(client):
    customer = login(client, "customer-001", "customer123")
    headers = {"Authorization": f"Bearer {customer['sessionToken']}"}
    with main.connect() as connection:
        password = connection.execute(
            "SELECT password FROM users WHERE user_id = ?", ("customer-001",)
        ).fetchone()["password"]
    assert password.startswith("pbkdf2_sha256$")

    profile = client.patch(
        "/api/profile", headers=headers, json={"fullName": "Demo Customer Updated"}
    )
    assert profile.status_code == 200
    assert profile.json()["audit"]["action"] == "CHANGE_PROFILE"

    logout = client.post("/api/logout", headers=headers)
    assert logout.status_code == 200
    assert logout.json()["status"] == "logged_out"
    assert client.get("/api/accounts/customer-001", headers=headers).status_code == 401


def test_wrong_password_does_not_create_a_session(client):
    with main.connect() as connection:
        before = connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
    response = client.post(
        "/api/login",
        json={
            "userId": "customer-001",
            "password": "incorrect",
            "walletAddress": DEMO_WALLETS["customer-001"],
        },
    )
    with main.connect() as connection:
        after = connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
    assert response.status_code == 401
    assert after == before


def test_login_rejects_wallet_assigned_to_another_role(client):
    response = client.post(
        "/api/login",
        json={
            "userId": "customer-001",
            "password": "customer123",
            "walletAddress": DEMO_WALLETS["admin-001"],
        },
    )
    assert response.status_code == 403
    assert "not assigned" in response.json()["detail"]


def test_login_rejects_wallet_without_required_contract_role(client, local_chain, deployed_contract):
    web3, _ = local_chain
    artifact = json.loads(ARTIFACT_PATH.read_text(encoding="utf-8"))
    contract = web3.eth.contract(
        address=Web3.to_checksum_address(deployed_contract), abi=artifact["abi"]
    )
    admin = Account.from_key(TEST_PRIVATE_KEY)
    revoke = contract.functions.revokeRole(
        Web3.to_checksum_address(DEMO_WALLETS["customer-001"])
    ).transact({"from": admin.address})
    web3.eth.wait_for_transaction_receipt(revoke)

    response = client.post(
        "/api/login",
        json={
            "userId": "customer-001",
            "password": "customer123",
            "walletAddress": DEMO_WALLETS["customer-001"],
        },
    )
    assert response.status_code == 403
    assert "Wallet role" in response.json()["detail"]


def test_postgresql_tampering_is_detected_against_chain(client):
    customer = login(client, "customer-001", "customer123")
    headers = {"Authorization": f"Bearer {customer['sessionToken']}"}
    client.get("/api/accounts/customer-001", headers=headers)
    event_id = customer["audit"]["eventId"]

    before = client.post(
        "/api/verify-integrity", headers=headers, json={"eventId": event_id}
    )
    assert before.status_code == 200
    assert before.json()["verified"] is True

    fields_to_tamper = {
        "user_id": "admin-001",
        "role": "ADMIN",
        "action": "ADMIN_ACCESS",
        "resource": "/admin/secrets",
        "timestamp": "2000-01-01T00:00:00+00:00",
        "source_ip": "203.0.113.99",
        "result": "FAILED",
        "risk_level": "CRITICAL",
        "details": json.dumps({"amount": 999999}),
    }
    with main.connect() as connection:
        original = connection.execute(
            "SELECT * FROM audit_events WHERE event_id = ?", (event_id,)
        ).fetchone()

    for field, replacement in fields_to_tamper.items():
        with main.connect() as connection:
            connection.execute(
                f"UPDATE audit_events SET {field} = ? WHERE event_id = ?",
                (replacement, event_id),
            )
            connection.commit()

        after = client.post(
            "/api/verify-integrity", headers=headers, json={"eventId": event_id}
        )
        assert after.status_code == 200, field
        assert after.json()["verified"] is False, field
        assert after.json()["onChainVerified"] is False, field
        assert "can thiệp" in after.json()["message"]

        with main.connect() as connection:
            connection.execute(
                f"UPDATE audit_events SET {field} = ? WHERE event_id = ?",
                (original[field], event_id),
            )
            connection.commit()


def test_legacy_plaintext_password_is_upgraded_on_successful_login(client):
    with main.connect() as connection:
        connection.execute(
            "UPDATE users SET password = ? WHERE user_id = ?",
            ("customer123", "customer-001"),
        )
        connection.commit()

    assert login(client, "customer-001", "customer123")["sessionToken"]
    with main.connect() as connection:
        password = connection.execute(
            "SELECT password FROM users WHERE user_id = ?", ("customer-001",)
        ).fetchone()["password"]
    assert password.startswith("pbkdf2_sha256$")


def test_expired_session_is_rejected_and_removed(client):
    customer = login(client, "customer-001", "customer123")
    headers = {"Authorization": f"Bearer {customer['sessionToken']}"}
    with main.connect() as connection:
        connection.execute(
            "UPDATE sessions SET expires_at = ? WHERE token = ?",
            ("2000-01-01T00:00:00+00:00", customer["sessionToken"]),
        )
        connection.commit()

    response = client.get("/api/accounts/customer-001", headers=headers)
    assert response.status_code == 401
    assert "expired" in response.json()["detail"]
    with main.connect() as connection:
        assert connection.execute(
            "SELECT 1 FROM sessions WHERE token = ?", (customer["sessionToken"],)
        ).fetchone() is None


def test_legacy_event_without_chain_transaction_is_reported_offchain_only(client):
    customer = login(client, "customer-001", "customer123")
    event_id = customer["audit"]["eventId"]
    headers = {"Authorization": f"Bearer {customer['sessionToken']}"}

    with main.connect() as connection:
        connection.execute(
            "UPDATE audit_events SET blockchain_tx_hash = NULL WHERE event_id = ?",
            (event_id,),
        )
        connection.commit()

    response = client.post(
        "/api/verify-integrity", headers=headers, json={"eventId": event_id}
    )
    assert response.status_code == 200
    assert response.json()["verified"] is True
    assert response.json()["onChainVerified"] is None
    assert "off-chain" in response.json()["message"]
