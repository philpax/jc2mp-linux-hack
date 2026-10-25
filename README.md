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

The script's header describes the startup failures and workarounds.
