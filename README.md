# TieuLuanChuyenNganh
 
```
blockchain-access-audit/          <-- Đây là 1 Git Repo duy nhất (git init ở đây)
├── .gitignore
├── README.md
│
├── blockchain/                   <-- Module 1: Solidity Smart Contract
│   ├── contracts/
│   │   └── AccessAndAudit.sol    <-- Mã nguồn Solidity
│   ├── scripts/
│   │   └── deploy.js             <-- Script deploy lên Ganache
│   ├── package.json              <-- Quản lý Hardhat, Ethers.js
│   └── hardhat.config.js
│
├── backend/                      <-- Module 2: Web API & AI Agent
│   ├── app/
│   │   ├── main.py               <-- FastAPI Backend
│   │   ├── ai_agent.py           <-- Python AI Agent giám sát real-time
│   │   └── crypto_utils.py       <-- Hàm mã hóa AES & tính SHA-256
│   ├── requirements.txt          <-- Cài web3.py, fastapi, uvicorn
│   └── database.db               <-- SQLite database local
│
└── frontend/                     <-- Module 3: Web UI Ngân hàng / Audit Dashboard
    ├── index.html                <-- Giao diện người dùng
    ├── audit.html                <-- Giao diện Verify Integrity
    └── js/
        └── app.js                <-- Tương tác Web3 & MetaMask
```