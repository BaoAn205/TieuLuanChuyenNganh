(() => {
  let connectedAddress = '';
  const localChainId = '0x7a69';

  async function connect() {
    if (!window.ethereum) {
      throw new Error('MetaMask extension was not detected.');
    }

    try {
      await window.ethereum.request({
        method: 'wallet_switchEthereumChain',
        params: [{ chainId: localChainId }],
      });
    } catch (error) {
      if (error.code !== 4902) throw error;
      await window.ethereum.request({
        method: 'wallet_addEthereumChain',
        params: [{
          chainId: localChainId,
          chainName: 'Hardhat Local',
          nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 },
          rpcUrls: ['http://127.0.0.1:8546'],
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