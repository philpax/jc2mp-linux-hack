# JC2-MP Linux launch workaround

A standalone Python script that works around JC2-MP startup failures under Proton. Patches apply in memory only. Installed game files and registry keys remain unchanged.

## Usage

Requires Linux x86-64, 64-bit Python 3.10+, and Steam installations of Just Cause 2 and JC2-MP. No Python dependencies are required.

Set JC2-MP's Steam launch options to:

```text
python3 "/absolute/path/to/jc2mp_launch.py" -- %command%
```

Replace the path with the script's location. Stop any existing JC2-MP processes before launching. Remove the launch option to disable the workaround.

## Compatibility

Tested with JC2-MP Steam build 1867542 and Proton Experimental 11.0 (20261014). The main menu, Settings dialog, and online play are verified.

The script checks binary hashes and instruction bytes before patching. Unsupported builds are rejected. System ptrace restrictions can prevent it from working; root is not required.

The script's header describes the startup failures and workarounds. It covers all three COM-registration checks used during GUI initialization. Patching only one check can trigger a process-exit request followed by a hang in DLL cleanup, leaving the last rendered frame visible.

Regression tests run with `python3 -m unittest -v`. Three consecutive Steam launches reached the multiplayer menu after applying all three checks. Window-close requests can still take more than 25 seconds; clean exit is not verified.

## Steam exits before launching the game

A system D-Bus resource-quota failure can disconnect Steam. GLib then sends SIGTERM to Steam, which logs off and exits. The system journal identifies this failure with `dbus-broker` messages about insufficient resources to receive a reply. This is separate from the game startup patches.

For this specific failure, stop Steam and start it with system-bus access disabled for that process:

```sh
STEAM_RUNTIME_LOGGER=0 DBUS_SYSTEM_BUS_ADDRESS=unix:path=/dev/null steam
```

The session bus remains available. System-bus integrations are unavailable until Steam restarts without the override. The path must exist because Steam's webhelper container mounts it; a nonexistent path prevents the webhelper from starting. This is a temporary diagnostic workaround, not a repair for the broker's resource exhaustion. Do not add these variables to the game's launch options as a general startup fix.
