# `ring` (companion radio, fork)

Sounds the buzzer to find the radio. It plays the ring tune on repeat, even
when the buzzer is muted, until the time runs out or someone presses any key.

```
ring           ring for 30 s
ring <1-300>   ring for that many seconds
ring stop      stop (also: ring 0)
```

Replies: `OK - ringing 30 s`, `OK - ring stopped`, `Error: ring [1-300|stop]`,
or `Error: no buzzer` on boards built without `PIN_BUZZER`.

## Who can send it

- **Over Bluetooth/USB:** the companion's local CLI (`CMD_RUN_CLI_COMMAND`),
  e.g. `meshcore-cli -a <ble-addr> cli "ring 60"`.
- **Over LoRa, from an admin:** a contact that has the remote-CLI permission
  (contact flag `0x10`) on the radio being rung. Send it as a CLI command:
  `meshcore-cli -a <your-radio> cmd <radio-name> "ring 60"`. The reply comes
  back as CLI data (`sync_msgs` shows it; `wait_msg` does not). From any
  other contact the text arrives as an ordinary chat message and nothing rings.

## Implementation

- `MyMesh::handleCommand` parses the command and calls
  `Listener::onRingRequest(seconds)`. The default returns false, which gives
  the "no buzzer" reply.
- `genericBuzzer::ring()` owns the timer and replays the tune from `loop()`.
  ui-new, ui-orig and ui-tiny forward the request and stop the ring on a key
  press. ui-orig does it in its any-press handler, so that press still does
  its normal action as well.
- Tested on Rover (Wio Tracker L1, `WioTrackerL1_companion_radio_ble_findhub`),
  2026-10-25: all four command forms over BLE; over LoRa from Scout with the
  admin flag (reply `OK - ringing 5 s`) and without it (delivered as a chat
  message, not run). Builds: L1 plain and Find Hub, T1000-E (ui-orig),
  T-Echo Card (ui-tiny), RAK4631 (no buzzer).
