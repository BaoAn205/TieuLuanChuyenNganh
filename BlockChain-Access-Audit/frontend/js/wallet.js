(() => {
  let connectedAddress = '';
  const chainId = window.APP_CONFIG?.CHAIN_ID || '0x7a69';
  const chainName = window.APP_CONFIG?.CHAIN_NAME || 'Hardhat Local';
  const chainRpcUrl = window.APP_CONFIG?.CHAIN_RPC_URL || 'http://127.0.0.1:8546';

  async function connect() {
    if (!window.ethereum) {
      throw new Error('MetaMask extension was not detected.');
    }

    try {
      await window.ethereum.request({
        method: 'wallet_switchEthereumChain',
        params: [{ chainId }],
      });
    } catch (error) {
      if (error.code !== 4902) throw error;
      await window.ethereum.request({
        method: 'wallet_addEthereumChain',
        params: [{
          chainId,
          chainName,
          nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 },
          rpcUrls: [chainRpcUrl],
        }],
      });
    }

    const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
    if (!accounts.length) throw new Error('No MetaMask account was selected.');
    connectedAddress = accounts[0];
    return connectedAddress;
  }

  if (window.ethereum?.on) {
    window.ethereum.on('accountsChanged', (accounts) => {
      connectedAddress = accounts[0] || '';
      window.dispatchEvent(new CustomEvent('walletchange', { detail: { address: connectedAddress } }));
    });
    window.ethereum.on('chainChanged', () => {
      connectedAddress = '';
      window.dispatchEvent(new CustomEvent('walletchange', { detail: { address: '' } }));
    });
  }

  window.BancollectWallet = {
    connect,
    get address() { return connectedAddress; },
  };
})();
