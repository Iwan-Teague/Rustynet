# Rustynet

## Quick Start Wizard

Run the interactive setup/menu wizard:

```bash
./start.sh
```

The wizard handles:
- first-run bootstrap (dependencies, keys, trust material, systemd wiring)
- daemon/service lifecycle
- peer connection helpers
- encrypted key custody at rest + runtime key management
- local key rotation/revocation and peer rotation-bundle apply flow
- exit-node and LAN-access toggles
- route advertisement and status checks

After first setup, run `./start.sh` again anytime to open the terminal control menu.
