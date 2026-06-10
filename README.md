# Signal-IRC Bridge Bot
Bridge messages between multiple Signal contacts/groups and one or more IRC channels.

This project uses the [signal-cli-rest-api](https://github.com/bbernhard/signal-cli-rest-api). 
The REST API can be hosted on an external system. Default configuration assumes it's on localhost.

# Multiple targets and channels
Every Signal target (contact or group) can be bound to one or more IRC channels
via the `channels:` token in the `[targets]` section. This enables:

- **Merge**: point several Signal targets at the same channel to combine chats.
- **Mirror**: give one target several channels to mirror a Signal chat across them.
- **Isolate**: point targets at distinct channels for independent bridges.

Targets with no `channels:` set fall back to the default channel in `[irc]`.

```ini
[targets]
# Relays to the default [irc] channel
+15551234567 =
# Bridged to one specific channel
+19998675309 = Jenny, channels:#jenny
# Group mirrored across two channels (needs Group ID + Internal ID)
group.AAAA== = internal:BBBB==, group, channels:#bridge-a #bridge-b
```

Bridge behavior is controlled in `[bridge]`:
- `forward_all_messages` — forward every IRC message to Signal, not just those
  prefixed with the bot's nick (`botname: ...`).
- `mirror_channels` — echo IRC messages between the channels of a multi-channel
  target (IRC↔IRC). Off keeps channels independent.

# Signal Group ID & Internal ID 
After setting up the account for the bot, then joining it to a Signal Group, you can obtain the
Group ID and Internal ID for the config by performing the following;

curl http://localhost:8080/v1/groups/$telephonenumber | jq




This program is provided as-is, without warranty of any kind. Use at your own risk.
