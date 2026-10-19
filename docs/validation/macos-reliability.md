# Native macOS reliability validation

Run as the login user on the test Mac. Select a disposable test tunnel and finish
existing connections first. Evidence lives under `target/native-validation/evidence`
with private permissions; it contains network addresses, never the profile or keys.

Build and prepare a WireGuard profile from the configured AirVPN login:

```sh
cargo build --locked
cargo run --locked --example prepare_airvpn_profile -- target/native-validation/airvpn.conf
```

The example reads the existing credential store and cached manifest, uses the
configured country and device (otherwise the first device and alphabetically first
server), and creates a new private file without overwriting an existing profile.
It does not refresh credentials or contact the provider.

Install the privileged service, using sudo in a terminal or the macOS administrator
dialog. Dialog callers should pass `--user <login-uid>` explicitly. The binary and
all its parent directories must be root-owned and not writable by other users.

```sh
sudo target/debug/tunmux service install --user "$(id -u)"
target/debug/tunmux service diagnose
```

For administrator operations in one Terminal sudo session, install the supplied build
and run the automated native suite as root while keeping tunmux itself under the
login UID:

```sh
sudo /usr/bin/python3 scripts/macos_native_validation.py --login-user "$(id -u)" --binary target/debug/tunmux --install --profile-file target/native-validation/airvpn.conf --scenario suite --dns-service 'Wi-Fi' --conflict-dns 1.1.1.1
```

Choose the actual active network service name for `--dns-service`. Add
`--with-transitions` only with an operator present; the suite then pauses for
network switching and sleep/resume. It installs once and executes disconnect,
SIGTERM, crash recovery, LAN, and optional DNS-conflict scenarios, stopping on the
first failure. With `--install`, it also exercises live reload and uninstall, then
reinstalls the service from the retained source build. Root-created evidence is
returned to the login user.

Alternatively, capture a baseline and run each scenario separately:

```sh
python3 scripts/macos_native_validation.py --scenario snapshot
python3 scripts/macos_native_validation.py --profile-file target/native-validation/airvpn.conf --scenario disconnect --admin-dialog
python3 scripts/macos_native_validation.py --profile-file target/native-validation/airvpn.conf --scenario sigterm --admin-dialog
python3 scripts/macos_native_validation.py --profile-file target/native-validation/airvpn.conf --scenario crash --admin-dialog
python3 scripts/macos_native_validation.py --profile-file target/native-validation/airvpn.conf --scenario lan --admin-dialog
python3 scripts/macos_native_validation.py --profile-file target/native-validation/airvpn.conf --scenario local-proxy
```

For a DNS conflict, explicitly select an active service and a working external DNS
address using `--dns-service` and `--conflict-dns`. The runner verifies that disconnect
reports the conflict and preserves the external setting, then restores the
helper-owned value to retry journal cleanup before restoring the baseline.
Do not delete the journal to make a failed scenario pass.

`network-switch` and `sleep-resume` pause after connecting. An operator changes the
physical network or sleeps and resumes the Mac, then presses Enter after the
primary network settles. The runner then waits up to 60 seconds for a stable IPv4
default route and three consecutive successful tunnel pings as the login user
before running the full connectivity hook. It records each wait attempt in
`transition-wait.json`, the hook output in `connectivity.log`, and independent
ping/HTTPS diagnostics in `connectivity-failure.json` if the hook fails. Inspect before/after
routes and connectivity results. Record Wi-Fi off/on as an outage test rather than
as coverage of switching to a different physical interface or gateway.
An unavailable second physical network must be recorded as untested.

After the administrator suite passes, run these separately in Terminal. Each
command connects before asking for its transition; wait for that prompt before
changing networks or putting the Mac to sleep.

```sh
sudo /usr/bin/python3 scripts/macos_native_validation.py --login-user "$(id -u)" --binary /usr/local/libexec/tunmux --profile-file target/native-validation/airvpn.conf --scenario network-switch
sudo /usr/bin/python3 scripts/macos_native_validation.py --login-user "$(id -u)" --binary /usr/local/libexec/tunmux --profile-file target/native-validation/airvpn.conf --scenario sleep-resume
```

## Acceptance criteria

- `--if-missing` preserves the active session identity and does not rerun hooks.
- Disconnect acknowledges restoration before success and completes within 70 seconds.
- SIGTERM restores network settings; SIGKILL retains recoverable intent. The next
  connect recovers the identified inactive session before establishing a fresh one.
- Routes, DNS, and search domains return to the recorded baseline when the physical
  network has not changed. Transient neighbor/cache route differences are acceptable;
  remaining VPN routes and unfinished journal actions are failures.
- A conflicting external DNS setting survives cleanup. The journal retains only
  unresolved work and succeeds once ownership is independently resolved.
- The live interface MTU matches the selected override/profile value. LAN opt-in
  preserves physical LAN routes and omits VPN routes that would override them,
  while retaining VPN DNS host routes. Default AllowedIPs behavior remains unchanged.
- Network changes coalesce, gateway replacement uses gateway plus interface identity,
  and no changes are applied without a settled primary network. Resume does not
  create competing helpers or overwrite another owner's DNS.

For a live, isolated local-proxy reconnect and suppression test without a login agent:

```sh
python3 scripts/macos_autoconnect_validation.py --profile-file target/native-validation/airvpn.conf
```

It restarts the controller after a manual disconnect, verifies persistent suspension,
resumes explicitly, kills the newly created proxy process, and checks automatic
reconnect with stable ports. Its desired state and logs stay under the evidence
directory, and it disconnects test sessions before exiting.

## launchd and autoconnect campaign

1. Verify `service diagnose` and an authorized operation activate the socket job.
   Confirm an unauthorized user cannot traverse/connect to the control socket.
2. Enable one direct and at least two distinct local-proxy desired connections.
   Confirm the login agent runs as the user, starts without prompting, and does not
   start extra sessions after a second controller invocation.
3. Disconnect an entry manually, then restart the agent and log out/in. The entry
   must remain suspended until explicit `autoconnect resume <name>`.
4. Race manual connects, controller starts, and disconnects. Verify serialization,
   session identity, stable proxy ports, and absence of duplicate instances.
5. Exercise transient connection failure and observe bounded retries. Restart the
   controller during backoff: failure counts must persist. Missing credentials,
   unknown identity, corrupt metadata, and ownership conflicts require intervention.
6. Reload with live managed sessions; verify acknowledged teardown and restoration
   before service replacement. Only previously enabled entries resume. Uninstall
   must suspend entries, stop the agent, complete cleanup, and preserve profiles.
   A pending recovery conflict must leave the service and recovery artifacts installed.

Record host/OS, binary revision, scenario, elapsed times, evidence paths, and any
untested transitions in the validation report. Unit tests and compilation do not
substitute for this campaign.
