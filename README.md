# Signal-IRC Bridge Bot
Bridge messages between multiple Signal contacts/groups and an IRC channel

This project uses the [signal-cli-rest-api](https://github.com/bbernhard/signal-cli-rest-api). 
The REST API can be hosted on an external system. Default configuration assumes it's on localhost.

# Signal Group ID & Internal ID 
After setting up the account for the bot, then joining it to a Signal Group, you can obtain the
Group ID and Internal ID for the config by performing the following;

curl http://localhost:8080/v1/groups/$telephonenumber | jq




This program is provided as-is, without warranty of any kind. Use at your own risk.
