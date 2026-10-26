# Add Node.js to apt using the new method
sudo apt update
sudo apt install -y ca-certificates curl gnupg netcat
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | sudo gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg

# Set the Node.js version to install
NODE_MAJOR=18

# Add the NodeSource repository for the desired Node.js version
echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_$NODE_MAJOR.x focal main" | sudo tee /etc/apt/sources.list.d/nodesource.list

# Update apt and install Node.js
sudo apt update
sudo apt install -y nodejs

# Install pm2 globally
sudo npm install -g pm2

# #####Update pm2 (if needed)
pm2 update


