#!/usr/bin/env bash
set -e

echo "Installing SecureNet VPN Client..."

if [ ! -f "target/release/sn" ]; then
    echo "⚠️  Client binary not found!"
    echo "Please build the client first by running:"
    echo "   cargo build --release --bin sn"
    exit 1
fi


# Copy the binary
echo "Installing binary to /usr/local/bin/sn"
sudo cp target/release/sn /usr/local/bin/sn
sudo chmod +x /usr/local/bin/sn

# Setup configuration directory
echo "Creating /etc/securenet configuration directory"
sudo mkdir -p /etc/securenet
if [ -f config/client.toml.example ] && [ ! -f /etc/securenet/client.toml ]; then
    echo "Copying default config to /etc/securenet/client.toml"
    sudo cp config/client.toml.example /etc/securenet/client.toml
    sudo chmod 600 /etc/securenet/client.toml
fi

# Copy the systemd service if provided
if [ -f scripts/securenet.service ]; then
    echo "Installing systemd service securenet.service"
    sudo cp scripts/securenet.service /etc/systemd/system/securenet.service
    sudo systemctl daemon-reload
    # sudo systemctl enable securenet
fi

echo "Installation complete!"
echo "To start the client:"
echo "   sudo systemctl start securenet"
echo "To view status:"
echo "   sudo systemctl status securenet"
