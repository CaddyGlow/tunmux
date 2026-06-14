.PHONY: build.release
build.release:
	cargo build --release

.PHONY: install/privileged
install/privileged:
	sudo dseditgroup -o read tunmux >/dev/null 2>&1 || sudo dseditgroup -o create tunmux
	sudo dseditgroup -o edit -a $$(id -F) -t user tunmux

	sudo install -m 0755 target/release/tunmux /usr/local/bin/tunmux
	sudo mkdir -p /var/log/tunmux && sudo chmod 755 /var/log/tunmux

	sudo cp etc/me.pansen.tunmux.privileged.plist /Library/LaunchDaemons/
	sudo chown root:wheel /Library/LaunchDaemons/me.pansen.tunmux.privileged.plist
	sudo chmod 644 /Library/LaunchDaemons/me.pansen.tunmux.privileged.plist
	sudo launchctl bootout system/me.pansen.tunmux.privileged 2>/dev/null || true
	sudo launchctl bootstrap system /Library/LaunchDaemons/me.pansen.tunmux.privileged.plist


.PHONY: install/wrapper
install/wrapper:
	mkdir -p $$HOME/.local/bin
	cp scripts/tunmux-autoconnect.sh $$HOME/.local/bin/tunmux-autoconnect.sh
	chmod 0755 $$HOME/.local/bin/tunmux-autoconnect.sh

.PHONY: install/autostart
install/autostart:
	mkdir -p $$HOME/Library/LaunchAgents
	sed "s|__HOME__|$$HOME|g" etc/me.pansen.tunmux.autoconnect.plist > $$HOME/Library/LaunchAgents/me.pansen.tunmux.autoconnect.plist
	launchctl bootstrap gui/$$(id -u) $$HOME/Library/LaunchAgents/me.pansen.tunmux.autoconnect.plist
	@# test now
	launchctl kickstart -k gui/$$(id -u)/me.pansen.tunmux.autoconnect
	@# inspect
	launchctl print gui/$$(id -u)/me.pansen.tunmux.autoconnect


.PHONY: install
install: build.release install/privileged install/wrapper install/autostart
