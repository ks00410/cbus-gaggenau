# Gaggenau Home Connect integration

This integration reads a Gaggenau oven and cooktop through the BSH Home Connect local WebSocket protocol and writes the state to C-Bus UserParams on a Clipsal C-Bus 5500AC LogicMachine.

## Files

- `user_library_gaggenau.lua` — library, WebSocket protocol, parser, and C-Bus writes.
- `script_resident_poll.lua` — thin resident-script entry point.
- `script_event_control.lua` — handles `Oven_Command` control requests.

Install the library where LogicMachine can load user libraries, and install the two scripts in the corresponding resident and event script locations. Run the resident script approximately every 30 seconds initially.

## One-time profile setup

1. Connect each appliance to the Home Connect mobile application and confirm that it is reachable locally.
2. Run the Home Connect Profile Downloader on a workstation using the Home Connect account.
3. Locate each appliance profile and record its `connectionType`, host credentials, PSK/AES key, and AES IV where present.
4. Use the profile's entity descriptions to identify the actual numeric UID for each entity. Entity UIDs vary between appliance models.
5. Give each appliance a DHCP reservation or otherwise configure a static IP address. The integration uses direct IP connections and does not perform discovery.

## Determining `connectionType`

Use the `connectionType` value in the downloaded appliance profile:

- `TLS` uses `wss://<host>:443/homeconnect` and the profile PSK. The WebSocket JSON protocol is implemented and works when the LogicMachine LuaSec/OpenSSL build supports the required PSK cipher suite.
- `AES` uses `ws://<host>/homeconnect` and encrypts each payload over the plain WebSocket.

The AES encryption layer in this integration is deliberately a documented stub. `aesEncrypt` and `aesDecrypt` currently pass plaintext through, so TLS mode and unencrypted protocol testing work. AES-mode appliances will not work until the Home Connect AES-CBC framing, HMAC chaining, padding, and stateful IV handling are adapted from the Unisenza `user.aes` implementation. See `cbus-smart-home/docs/08-gaggenau-home-connect.md` for the exact specification.

## `user.secrets`

Keep credentials outside the integration files. Add the following structure to `user.secrets` and replace every example value:

```lua
secrets.gaggenau = {
  oven_host = "192.168.1.xx",
  oven_key = "base64-psk-or-aes-key",
  oven_iv = "base64-iv", -- AES mode only
  oven_mode = "AES", -- "AES" or "TLS"

  cooktop_host = "192.168.1.xy",
  cooktop_key = "base64-psk-or-aes-key",
  cooktop_iv = "base64-iv",
  cooktop_mode = "AES",
}
```

Keys and IVs are retained for the AES/TLS adaptation and must never be placed in a public script or committed to source control.

## UserParams

Create these UserParams on network index `0` before enabling the scripts:

### Oven

- `Oven_OperationState` — string
- `Oven_DoorState` — string
- `Oven_CurrentTemp` — float in °C
- `Oven_Program` — string
- `Oven_TimeRemaining` — number of seconds
- `Oven_PreheatDone` — `0` or `1`
- `Oven_RemoteAllowed` — `0` or `1`
- `Oven_LastUpdated` — date/time string
- `Oven_Command` — command string used by the event script

Supported `Oven_Command` values are `light_on`, `light_off`, `child_lock_on`, and `child_lock_off`. The command is cleared after a successful POST.

### Cooktop

- `Cooktop_OperationState` — string
- `Cooktop_InUse` — `0` or `1`
- `Cooktop_LastUpdated` — date/time string

Also create `Debug Logging` if verbose logging is required. Missing parameters are skipped safely and warned only once per session.

## Operation and safety

The resident script opens a WebSocket, performs the Home Connect handshake, requests descriptions and mandatory values, writes state, sends `deviceReady`, and closes the connection on every cycle. Remote oven commands are subject to the appliance's own remote-control safety gate; the oven may require Remote Start to be enabled locally first.

The static UID table in the library contains only typical fallback examples. The description response is used to build the runtime UID map, and model-specific descriptions should be retained when validating command UIDs.

Australian English is used in labels and documentation. Local LAN operation requires no cloud connection after profile credentials have been obtained.
