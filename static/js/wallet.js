console.log("Wallet.js execution started");

let peraWallet;

document.addEventListener("DOMContentLoaded", () => {
    console.log("DOM Loaded - Initializing Wallet Logic");

    // Initialize PeraWallet instance
    // Check if global exists
    if (typeof PeraWalletConnect === 'undefined') {
        console.error("PeraWalletConnect library not loaded!");
        alert("Error: PeraWallet Library not loaded. Check internet connection.");
        return;
    }

    try {
        // Our webpack bundle exposes window.PeraWalletConnect = { PeraWalletConnect: class }
        // So we need to access window.PeraWalletConnect.PeraWalletConnect

        let PeraClass;
        if (typeof PeraWalletConnect.PeraWalletConnect === 'function') {
            PeraClass = PeraWalletConnect.PeraWalletConnect;
        } else if (typeof PeraWalletConnect === 'function') {
            PeraClass = PeraWalletConnect;
        } else {
            throw new Error("PeraWalletConnect class not found in global object. Keys: " + Object.keys(PeraWalletConnect));
        }

        peraWallet = new PeraClass({ chainId: 416002 });
        console.log("PeraWallet initialized with ChainID 416002 (TestNet)");
    } catch (e) {
        console.error("Failed to initialize PeraWallet:", e);
        return;
    }

    // Reconnect on reload
    peraWallet.reconnectSession().then((accounts) => {
        if (accounts.length) {
            console.log("Session reconnected:", accounts[0]);
            updateWalletUI(accounts[0]);
        }
    }).catch((e) => console.log("Reconnect failed:", e));

    const connectBtn = document.getElementById("connect-wallet-btn");
    if (connectBtn) {
        console.log("Connect button found, attaching listener");
        connectBtn.addEventListener("click", handleConnectWallet);
    } else {
        console.error("Connect button NOT found in DOM");
    }
});

function handleConnectWallet(e) {
    if (e) e.preventDefault();
    console.log("Connect button clicked");

    if (!peraWallet) {
        console.error("PeraWallet not initialized");
        return;
    }

    peraWallet.connect()
        .then((newAccounts) => {
            console.log("Connected:", newAccounts);
            peraWallet.connector.on("disconnect", handleDisconnectWallet);
            updateWalletUI(newAccounts[0]);
        })
        .catch((error) => {
            console.error("Connection error:", error);
            if (error?.data?.type !== "CONNECT_MODAL_CLOSED") {
                alert("Connection failed: " + error.message);
            }
        });
}

function handleDisconnectWallet() {
    console.log("Disconnecting...");
    peraWallet.disconnect().catch((e) => console.log(e));
    updateWalletUI(null);
}

function updateWalletUI(accountAddress) {
    const connectBtn = document.getElementById("connect-wallet-btn");
    if (!connectBtn) return;

    if (accountAddress) {
        // Connected
        connectBtn.innerHTML = `<img src="https://explorer.perawallet.app/favicon.ico" alt="Pera" style="width: 20px; height: 20px; margin-right: 8px;"> ${accountAddress.slice(0, 6)}...${accountAddress.slice(-4)}`;
        connectBtn.removeEventListener("click", handleConnectWallet);
        connectBtn.addEventListener("click", handleDisconnectWallet);

        // Apply Premium Connected Style
        connectBtn.classList.remove("btn-pera", "btn-success");
        connectBtn.classList.add("btn-pera-connected");

        connectBtn.title = "Click to disconnect";
    } else {
        // Disconnected
        connectBtn.innerHTML = `<img src="https://explorer.perawallet.app/favicon.ico" alt="Pera" style="width: 20px; height: 20px; margin-right: 8px;"> Connect Wallet`;
        connectBtn.removeEventListener("click", handleDisconnectWallet);
        connectBtn.addEventListener("click", handleConnectWallet);

        // Apply Premium Default Style
        connectBtn.classList.remove("btn-pera-connected", "btn-success", "text-primary"); // Cleanup old classes
        connectBtn.classList.add("btn-pera");

        connectBtn.title = "Connect Pera Wallet";
    }
}
