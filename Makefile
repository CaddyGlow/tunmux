.PHONY: submodule
submodule:
	git submodule update --init --recursive

.PHONY: build.release
build.release: submodule
	cargo build --release

.PHONY: install/privileged
install/privileged:
	sudo dseditgroup -o read tunmux >/dev/null 2>&1 || sudo dseditgroup -o create tunmux
	sudo dseditgroup -o edit -a $$(id -F) -t user tunmux

	sudo install -m 0755 target/release/tunmux /usr/local/bin/tunmux
	sudo mkdir -p /var/log/tunmux && sudo chmod 755 /var/log/tunmux
	sudo mkdir -p "/Library/Application Support/tunmux/run"
	sudo chgrp tunmux "/Library/Application Support/tunmux/run"
	sudo chmod 0750 "/Library/Application Support/tunmux/run"

	sudo cp etc/me.pansen.tunmux.privileged.plist /Library/LaunchDaemons/
	sudo chown root:wheel /Library/LaunchDaemons/me.pansen.tunmux.privileged.plist
	sudo chmod 644 /Library/LaunchDaemons/me.pansen.tunmux.privileged.plist
	GID=$$(dscl . -read /Groups/tunmux PrimaryGroupID | awk '{print $$2}'); \
	sudo /usr/libexec/PlistBuddy -c "Add :Sockets:Listeners:SockPathGroup integer $$GID" \
		/Library/LaunchDaemons/me.pansen.tunmux.privileged.plist
	sudo launchctl bootout system/me.pansen.tunmux.privileged 2>/dev/null || true
	@# Clear any stale "disabled" override — bootstrap of a disabled label fails with EIO (5).
	sudo launchctl enable system/me.pansen.tunmux.privileged
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
	launchctl bootout gui/$$(id -u)/me.pansen.tunmux.autoconnect 2>/dev/null || true
	launchctl bootstrap gui/$$(id -u) $$HOME/Library/LaunchAgents/me.pansen.tunmux.autoconnect.plist
	@# test now
	launchctl kickstart -k gui/$$(id -u)/me.pansen.tunmux.autoconnect
	@# inspect
	launchctl print gui/$$(id -u)/me.pansen.tunmux.autoconnect


.PHONY: install
install: build.release install/privileged install/wrapper install/autostart


.PHONY: uninstall/autostart
uninstall/autostart:
	launchctl bootout gui/$$(id -u)/me.pansen.tunmux.autoconnect 2>/dev/null || true
	rm -f $$HOME/Library/LaunchAgents/me.pansen.tunmux.autoconnect.plist

.PHONY: uninstall/wrapper
uninstall/wrapper:
	rm -f $$HOME/.local/bin/tunmux-autoconnect.sh

.PHONY: uninstall/privileged
uninstall/privileged:
	sudo launchctl bootout system/me.pansen.tunmux.privileged 2>/dev/null || true
	sudo launchctl disable system/me.pansen.tunmux.privileged 2>/dev/null || true
	sudo pkill -f '/usr/local/bin/tunmux wgconf' 2>/dev/null || true
	sudo rm -f /Library/LaunchDaemons/me.pansen.tunmux.privileged.plist
	sudo rm -f /usr/local/bin/tunmux
	sudo rm -rf "/Library/Application Support/tunmux"
	sudo rm -rf /var/log/tunmux
	sudo dseditgroup -o delete tunmux 2>/dev/null || true

.PHONY: uninstall
uninstall: uninstall/autostart uninstall/wrapper uninstall/privileged


.PHONY: check/privileged
check/privileged:
	@echo "==> daemon (expect: state = not running, sockets registered)"
	sudo launchctl print system/me.pansen.tunmux.privileged | grep -E 'state =|Listeners'
	@echo "==> socket (expect: srw-rw---- root:tunmux)"
	stat -f '  %Sp  %Su:%Sg  %N' "/Library/Application Support/tunmux/run/ctl.sock"
	@echo "==> socket dir (expect: drwxr-x--- root:tunmux)"
	stat -f '  %Sp  %Su:%Sg  %N' "/Library/Application Support/tunmux/run"
	@echo "==> group membership (expect: tunmux listed)"
	id | tr ',' '\n' | grep tunmux || echo "  not in tunmux group — re-login required"
	sudo log show --predicate 'sender == "launchd"' --last 10m --info | grep tunmux | tail -n30
	sudo tail -n20  /var/log/tunmux/*
	ps axu | grep tunmux
	ping -c2 55.56.57.2

.PHONY: check
check: check/privileged
