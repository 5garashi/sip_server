Sure, here's a markdown-formatted README file for your SIP proxy server program:

---

```markdown
# 🧭 Minimal SIP Proxy Server

This project implements a minimal UDP-based SIP proxy server written in Python 3.  
It receives, interprets, and relays SIP messages between clients, enabling basic call routing, registration tracking, and ACK/BYE handling.

---

## 🚀 Features

- UDP server listening on port `5060`
- Parses SIP messages and handles:
  - `REGISTER` requests and stores user addresses
  - `INVITE` routing between registered users
  - `ACK` and `BYE` forwarding based on session history
  - Generic SIP `RESPONSE` handling (e.g., `180 Ringing`, `200 OK`)
  - Fallback logic for unknown messages
- Structured logging with `brief` and `debug` modes
- Hexdump utility for non-SIP or malformed messages
- NAT-safe message forwarding logic with session tracking (`call_sessions`)
- Drop mechanism for undesired IPs (e.g., filters out `77.110.114.15`)

---

## 🧰 Requirements

- Python 3.6+
- No external dependencies

---

## ▶️ Usage

Run the proxy server:

```bash
python3 sip_proxy.py
```

To enable detailed logs (debug mode):

```bash
python3 sip_proxy.py debug
```

---

## 🧪 Message Handling Overview

| Method        | Function             | Behavior                              |
|---------------|----------------------|----------------------------------------|
| `REGISTER`    | `handle_register()`   | Stores sender address in `registered_users` |
| `INVITE`      | `handle_invite()`     | Relays request to registered callee    |
| `ACK` / `BYE` | `handle_ack_or_bye()` | Routes to peer and updates session     |
| `RESPONSE`    | `handle_response()`   | Forwards SIP response to the initiator |
| `UNKNOWN`     | `handle_unknown()`    | Attempts forwarding based on `Call-ID` |

---

## 📦 Message Parsing Logic

- SIP method is derived from the first line of the message via `get_sip_method()`
- `To:`, `From:`, `Call-ID:`, and `CSeq:` headers are used for user and session identification
- `Contact:` is used for ACK destination
- IP filtering applied to skip known bad IPs (e.g. `77.110.114.15`)

---

## 🛡️ Notes

- `registered_users` maps usernames to `(IP, port)` tuples for routing
- `call_sessions` maps `Call-ID` to `{from, to}` tuples for reverse path determination
- ACK messages are explicitly constructed and sent using `send_ack()`
- All UDP socket activity is managed through a single `send_to()` wrapper

---

## 🐞 Logging

| Mode   | Behavior                    |
|--------|-----------------------------|
| `brief`| Minimal, essential messages |
| `debug`| Full message dumps, routing details, hexdumps |

Enable `debug` via CLI argument to observe full SIP traffic and session routing.

---

## 📁 Files

All functionality is self-contained in a single Python script. No external modules or configs are required.

---

## 📌 License

This project is provided as-is for educational or experimental SIP proxy usage.

```

---

Would you like me to generate sample SIP test packets or a configuration guide for compatible clients like Linphone or Grandstream?
