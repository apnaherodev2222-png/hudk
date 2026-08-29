#!/usr/bin/env bash
set -euo pipefail

# Debian/Ubuntu VPS: install Docker Engine + CLI and enable the service.
if ! command -v docker >/dev/null 2>&1; then
  sudo apt-get update
  sudo apt-get install -y ca-certificates curl
  sudo install -m 0755 -d /etc/apt/keyrings
  sudo curl -fsSL https://download.docker.com/linux/$(. /etc/os-release && echo "$ID")/gpg -o /etc/apt/keyrings/docker.asc
  sudo chmod a+r /etc/apt/keyrings/docker.asc
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/$(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
  sudo apt-get update
  sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi
sudo systemctl enable --now docker
sudo docker pull python:3.11-slim
sudo docker pull node:20-bookworm-slim
sudo docker info >/dev/null

echo "Docker sandbox is ready."
echo "Set BOT_TOKEN in your environment before starting the bot."
echo "Example: export BOT_TOKEN='YOUR_NEW_TOKEN'"
