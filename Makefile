.PHONY: build.release
build.release:
	cargo build --release

.PHONY: install
install: build.release
	# 1. Authorized group + add yourself (macOS)
	sudo dseditgroup -o create tunmux
	sudo dseditgroup -o edit -a $$(id -F) -t user tunmux

	# 2. Binary + log dir
	sudo install -m 0755 target/release/tunmux /usr/local/bin/tunmux
	sudo mkdir -p /var/log/tunmux && sudo chmod 755 /var/log/tunmux

	# 3. Install + load the daemon (root-owned plist => system daemon)
	sudo cp etc/me.pansen.tunmux.privileged.plist /Library/LaunchDaemons/
	sudo chown root:wheel /Library/LaunchDaemons/me.pansen.tunmux.privileged.plist
	sudo chmod 644 /Library/LaunchDaemons/me.pansen.tunmux.privileged.plist
	sudo launchctl bootstrap system /Library/LaunchDaemons/me.pansen.tunmux.privileged.plist

	# 4. Now connect as your normal user — no sudo prompt:
	# tunmux --debug wgconf connect --file ~/private/.wireguard/static.22.101.88.23.clients.your-server.de/andi_split.conf
