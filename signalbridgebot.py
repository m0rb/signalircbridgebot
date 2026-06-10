#!/usr/bin/env python3
"""
Signal-IRC Bridge Bot

Bridges messages between multiple Signal contacts/groups and one or more IRC
channels over SSL.

Each Signal target (contact or group) is bound to one or more IRC channels:
- Bind several targets to the same channel to merge chats into one channel.
- Bind one target to several channels to mirror a Signal chat across channels.
- Bind targets to distinct channels for independent, isolated bridges.
Targets with no channel set fall back to the default [irc] channel.

Requirements:
- signal-cli-rest-api running in json-rpc mode
  (https://github.com/bbernhard/signal-cli-rest-api)
- Python 3.10+

Signal -> IRC: Messages relayed as "<sender> message" or "[TargetName] <sender> message"
IRC -> Signal: Relayed to the Signal target(s) bound to the originating channel.
    By default only messages prefixed with "botname:" are forwarded; set
    forward_all_messages = true to forward every channel message.

Admin commands (via IRC private message to the bot):
    help                       - Show available commands
    list                       - List active targets and their channels
    add <id> [name] [#chan...] - Add a target (phone number or group ID)
    remove <id>                - Remove a target
    channels <id> [#chan...]   - Set/clear a target's IRC channels
    status                     - Show bridge status

Usage:
    python signalbridgebot.py --config config.ini
"""

import argparse
import asyncio
import configparser
import fnmatch
import json
import logging
import os
import re
import signal
import ssl
import sys
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

import aiohttp
import irc.client_aio
import irc.connection

@dataclass
class Target:
    """A Signal target (contact or group)"""
    id: str  # Phone number or group ID (for sending - use the group.XXX= format)
    internal_id: str = ""  # For groups: the internal_id used in incoming messages
    name: str = ""  # Optional friendly name - if set, shown as prefix on IRC
    is_group: bool = False
    enabled: bool = True
    # IRC channels this target bridges to. Empty -> falls back to the default
    # channel (config.irc_channel). List multiple channels to mirror one Signal
    # chat to several IRC channels.
    channels: list[str] = field(default_factory=list)
    message_count: int = 0
    last_message: Optional[datetime] = None

    def __post_init__(self):
        # Auto-detect group by ID format
        if not self.is_group and (self.id.startswith("group.") or self.internal_id):
            self.is_group = True

    def to_dict(self) -> dict:
        d = {
            "id": self.id,
            "is_group": self.is_group,
            "enabled": self.enabled,
        }
        if self.name:
            d["name"] = self.name
        if self.internal_id:
            d["internal_id"] = self.internal_id
        if self.channels:
            d["channels"] = self.channels
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "Target":
        return cls(
            id=data["id"],
            internal_id=data.get("internal_id", ""),
            name=data.get("name", ""),
            is_group=data.get("is_group", False),
            enabled=data.get("enabled", True),
            channels=list(data.get("channels", [])),
        )


@dataclass
class Config:
    """Bridge configuration"""
    # Signal settings (signal-cli-rest-api)
    signal_api_url: str = "http://localhost:8080"
    signal_phone_number: str = ""
    
    # Multiple targets
    targets: dict[str, Target] = field(default_factory=dict)
    
    # IRC settings
    irc_server: str = "irc.libera.chat"
    irc_port: int = 6697
    irc_use_ssl: bool = True
    irc_verify_ssl: bool = True
    irc_nick: str = "SignalBridge"
    irc_channel: str = "#signal-bridge"
    irc_password: str = ""
    irc_nickserv_password: str = ""

    # Admin settings
    admin_masks: list[str] = field(default_factory=list)

    # Bridge settings
    rate_limit_ms: int = 500
    # Prefix prepended to every Signal -> IRC message (e.g. a leading marker)
    signal_prefix: str = ""
    # Forward every IRC channel message to Signal, not just "<nick>:"-prefixed ones
    forward_all_messages: bool = False
    # Echo IRC messages between the channels of a target that maps to several
    # channels (IRC<->IRC mirroring). Off -> channels are independent.
    mirror_channels: bool = False

    # State file for dynamic targets
    state_file: str = ""

    def add_target(self, target: Target):
        """Add a target"""
        self.targets[target.id] = target
    
    def remove_target(self, target_id: str) -> bool:
        """Remove a target by ID"""
        if target_id in self.targets:
            del self.targets[target_id]
            return True
        return False
    
    @staticmethod
    def _normalize_group_id(gid: str) -> str:
        """Strip 'group.' prefix for consistent comparison."""
        return gid[6:] if gid.startswith("group.") else gid

    def get_target_by_source(self, source: str, group_id: str = "") -> Optional[Target]:
        """Find a target matching the source or group"""
        if group_id:
            normalized = self._normalize_group_id(group_id)
            for target in self.targets.values():
                if not target.is_group:
                    continue
                if target.internal_id and target.internal_id == group_id:
                    return target
                if self._normalize_group_id(target.id) == normalized:
                    return target
        if source in self.targets:
            return self.targets[source]
        return None

    def channels_for_target(self, target: Target) -> list[str]:
        """IRC channels a Signal target relays to (its own, or the default)."""
        return target.channels if target.channels else [self.irc_channel]

    def all_channels(self) -> list[str]:
        """Every IRC channel the bot must join: the default plus all targets'."""
        ordered: list[str] = []
        for chan in [self.irc_channel, *(c for t in self.targets.values() for c in t.channels)]:
            if chan and chan not in ordered:
                ordered.append(chan)
        return ordered

    def targets_for_channel(self, channel: str) -> list[Target]:
        """Enabled Signal targets that bridge the given IRC channel."""
        return [
            t for t in self.targets.values()
            if t.enabled and channel in self.channels_for_target(t)
        ]

    def mirror_channels_for(self, channel: str) -> list[str]:
        """Other IRC channels that should mirror a message seen in `channel`.

        The union of all channels of every target bridging `channel`, minus
        `channel` itself. Empty unless mirror_channels is enabled.
        """
        if not self.mirror_channels:
            return []
        dests: list[str] = []
        for target in self.targets_for_channel(channel):
            for chan in self.channels_for_target(target):
                if chan != channel and chan not in dests:
                    dests.append(chan)
        return dests

    def save_state(self):
        """Save dynamic state to file"""
        if not self.state_file:
            return
        state = {
            "targets": {tid: t.to_dict() for tid, t in self.targets.items()}
        }
        try:
            with open(self.state_file, "w") as f:
                json.dump(state, f, indent=2)
        except Exception as e:
            logging.error(f"Failed to save state: {e}")
    
    def load_state(self):
        """Load dynamic state from file"""
        if not self.state_file or not os.path.exists(self.state_file):
            return
        try:
            with open(self.state_file, "r") as f:
                state = json.load(f)
            for tid, tdata in state.get("targets", {}).items():
                self.targets[tid] = Target.from_dict(tdata)
        except Exception as e:
            logging.error(f"Failed to load state: {e}")

    @classmethod
    def from_env(cls) -> "Config":
        """Load configuration from environment variables"""
        cfg = cls(
            signal_api_url=os.getenv("SIGNAL_API_URL", "http://localhost:8080"),
            signal_phone_number=os.getenv("SIGNAL_PHONE_NUMBER", ""),
            irc_server=os.getenv("IRC_SERVER", "irc.libera.chat"),
            irc_port=int(os.getenv("IRC_PORT", "6697")),
            irc_use_ssl=os.getenv("IRC_USE_SSL", "true").lower() == "true",
            irc_verify_ssl=os.getenv("IRC_VERIFY_SSL", "true").lower() == "true",
            irc_nick=os.getenv("IRC_NICK", "SignalBridge"),
            irc_channel=os.getenv("IRC_CHANNEL", "#signal-bridge"),
            irc_password=os.getenv("IRC_PASSWORD", ""),
            irc_nickserv_password=os.getenv("IRC_NICKSERV_PASSWORD", ""),
            rate_limit_ms=int(os.getenv("RATE_LIMIT_MS", "500")),
            signal_prefix=os.getenv("SIGNAL_PREFIX", ""),
            forward_all_messages=os.getenv("FORWARD_ALL_MESSAGES", "false").lower() == "true",
            mirror_channels=os.getenv("MIRROR_CHANNELS", "false").lower() == "true",
            state_file=os.getenv("STATE_FILE", ""),
        )
        
        admin_masks = os.getenv("ADMIN_MASKS", "")
        if admin_masks:
            cfg.admin_masks = [m.strip() for m in admin_masks.split(",")]
        
        # SIGNAL_TARGETS: comma-separated targets. Append "@#chan1+#chan2" to a
        # target to bind it to specific IRC channels, e.g. "+15551234567@#room".
        targets_str = os.getenv("SIGNAL_TARGETS", "")
        if targets_str:
            for t in targets_str.split(","):
                t = t.strip()
                if not t:
                    continue
                channels: list[str] = []
                if "@" in t:
                    t, _, chans = t.partition("@")
                    t = t.strip()
                    channels = [c.strip() for c in chans.split("+") if c.strip()]
                cfg.add_target(Target(id=t, channels=channels))
        
        cfg.load_state()
        return cfg

    @classmethod
    def from_file(cls, path: str) -> "Config":
        """Load configuration from INI file"""
        parser = configparser.ConfigParser()
        # Preserve case for option names (important for base64 group IDs)
        parser.optionxform = str
        parser.read(path)
        
        cfg = cls()

        # Blank-tolerant readers: a present-but-empty value (common in template
        # configs, e.g. "port =") falls back to the default instead of erroring.
        def _str(section, key, fallback):
            return section.get(key, "").strip() or fallback

        def _int(section, key, fallback):
            val = section.get(key, "").strip()
            return int(val) if val else fallback

        def _bool(section, key, fallback):
            val = section.get(key, "").strip().lower()
            if not val:
                return fallback
            return val in ("1", "true", "yes", "on")

        if "signal" in parser:
            s = parser["signal"]
            cfg.signal_api_url = _str(s, "api_url", cfg.signal_api_url)
            cfg.signal_phone_number = _str(s, "phone_number", "")

        if "irc" in parser:
            i = parser["irc"]
            cfg.irc_server = _str(i, "server", cfg.irc_server)
            cfg.irc_port = _int(i, "port", cfg.irc_port)
            cfg.irc_use_ssl = _bool(i, "use_ssl", cfg.irc_use_ssl)
            cfg.irc_verify_ssl = _bool(i, "verify_ssl", cfg.irc_verify_ssl)
            cfg.irc_nick = _str(i, "nick", cfg.irc_nick)
            cfg.irc_channel = _str(i, "channel", cfg.irc_channel)
            cfg.irc_password = _str(i, "password", cfg.irc_password)
            cfg.irc_nickserv_password = _str(i, "nickserv_password", cfg.irc_nickserv_password)

        if "bridge" in parser:
            b = parser["bridge"]
            cfg.rate_limit_ms = _int(b, "rate_limit_ms", cfg.rate_limit_ms)
            cfg.signal_prefix = b.get("signal_prefix", cfg.signal_prefix)
            cfg.forward_all_messages = _bool(b, "forward_all_messages", cfg.forward_all_messages)
            cfg.mirror_channels = _bool(b, "mirror_channels", cfg.mirror_channels)
            cfg.state_file = _str(b, "state_file", cfg.state_file)
        
        if "admin" in parser:
            a = parser["admin"]
            masks = a.get("masks", "")
            if masks:
                cfg.admin_masks = [m.strip() for m in masks.split(",")]
        
        # Load targets - format: id = [internal:X] [group] [channels:#a #b] [name]
        # The id should be the group.XXX= format for sending.
        # internal_id is the base64 ID used in incoming messages (optional, for groups).
        # channels: binds this target to specific IRC channel(s), space-separated.
        #   Omit to use the default [irc] channel. List several to mirror one
        #   Signal chat across multiple IRC channels.
        if "targets" in parser:
            for line in parser["targets"]:
                raw_value = parser["targets"][line]
                target_id = line
                value = raw_value

                # Handle base64 IDs with = padding that got split
                while value.startswith("="):
                    target_id += "="
                    value = value[1:].lstrip()

                is_group = False
                name = ""
                internal_id = ""
                channels: list[str] = []

                if value:
                    parts = [p.strip() for p in value.split(",")]
                    for part in parts:
                        if part.lower() == "group":
                            is_group = True
                        elif part.startswith("internal:"):
                            internal_id = part[9:].strip()
                        elif part.startswith("channels:"):
                            channels = [c.strip() for c in part[9:].split() if c.strip()]
                        elif part:
                            name = part

                if target_id:
                    cfg.add_target(Target(
                        id=target_id,
                        internal_id=internal_id,
                        name=name,
                        is_group=is_group,
                        channels=channels,
                    ))
        
        cfg.load_state()
        return cfg


class SignalClient:
    """Async client for signal-cli-rest-api"""
    
    def __init__(self, config: Config):
        self.config = config
        self.api_url = config.signal_api_url.rstrip("/")
        self.phone_number = config.signal_phone_number
        self._session: Optional[aiohttp.ClientSession] = None
        self._running = False
        self._message_callback = None
        self.logger = logging.getLogger("signal")
        self._processed_messages = set()  # Track processed message IDs to avoid duplicates
    
    async def start(self):
        self._session = aiohttp.ClientSession()
        self._running = True
        self.logger.info(f"Signal client started, API: {self.api_url}")
    
    async def stop(self):
        self._running = False
        if self._session:
            await self._session.close()
            self._session = None
        self.logger.info("Signal client stopped")
    
    def on_message(self, callback):
        self._message_callback = callback
    
    async def send_message(self, target: Target, text: str) -> bool:
        if not self._session:
            self.logger.error("Session not initialized")
            return False
        
        url = f"{self.api_url}/v2/send"
        
        # For groups, the recipient ID needs "group." prefix if not already present
        recipient_id = target.id
        if target.is_group and not recipient_id.startswith("group."):
            recipient_id = f"group.{recipient_id}"
        
        payload = {
            "message": text,
            "number": self.phone_number,
            "recipients": [recipient_id],
        }
        
        self.logger.debug(f"Sending to {recipient_id}: {payload}")
        
        try:
            async with self._session.post(url, json=payload) as resp:
                if resp.status in (200, 201):
                    self.logger.debug(f"Message sent to {target.id}: {text[:50]}...")
                    return True
                else:
                    body = await resp.text()
                    self.logger.error(f"Failed to send message: {resp.status} - {body}")
                    return False
        except Exception as e:
            self.logger.error(f"Error sending message: {e}")
            return False
    
    async def poll_loop(self):
        url = f"{self.api_url}/v1/receive/{self.phone_number}"
        self.logger.info(f"Starting polling receive loop: {url}")
        
        while self._running:
            try:
                async with self._session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        if text.strip():
                            try:
                                messages = json.loads(text)
                                if isinstance(messages, list):
                                    for msg in messages:
                                        await self._process_message(msg)
                                elif isinstance(messages, dict):
                                    await self._process_message(messages)
                            except json.JSONDecodeError:
                                self.logger.debug(f"Non-JSON response: {text[:100]}")
                    else:
                        self.logger.warning(f"Poll returned {resp.status}")
                
                await asyncio.sleep(2)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Poll error: {e}")
                if self._running:
                    await asyncio.sleep(5)
    
    async def _process_message(self, msg: dict):
        self.logger.debug(f"Raw message received: {msg}")
        
        envelope = msg.get("envelope", msg)
        
        # Get unique message identifier for deduplication
        message_id = envelope.get("timestamp")
        if not message_id:
            # Fallback to combination of source and message content if timestamp not available
            source = envelope.get("source") or envelope.get("sourceNumber", "")
            data_message = envelope.get("dataMessage", {})
            text = data_message.get("message", "")
            message_id = f"{source}_{text}"
        
        # Skip if already processed
        if message_id in self._processed_messages:
            self.logger.debug(f"Duplicate message skipped: {message_id}")
            return
        self._processed_messages.add(message_id)
        
        # Keep only last 1000 processed messages to prevent memory issues
        if len(self._processed_messages) > 1000:
            # Remove oldest messages
            to_remove = len(self._processed_messages) - 1000
            for _ in range(to_remove):
                self._processed_messages.pop()
        
        source = envelope.get("source") or envelope.get("sourceNumber", "")
        source_uuid = envelope.get("sourceUuid", "")
        if source == self.phone_number:
            self.logger.debug(f"Skipping own message from {source}")
            return
        
        data_message = envelope.get("dataMessage", {})
        text = data_message.get("message", "")
        
        if not text:
            self.logger.debug(f"No text content in message: {list(envelope.keys())}")
            return
        
        # Get sender's display name from Signal
        source_name = envelope.get("sourceName") or source or source_uuid
        
        group_info = data_message.get("groupInfo", {})
        group_id = group_info.get("groupId", "")
        
        target = self.config.get_target_by_source(source, group_id)
        if not target and source_uuid:
            target = self.config.get_target_by_source(source_uuid, group_id)
        
        if not target:
            self.logger.debug(f"No matching target for source={source}, group_id={group_id}")
            return
        
        if not target.enabled:
            self.logger.debug(f"Target {target.id} is disabled")
            return
        
        target.message_count += 1
        target.last_message = datetime.now()
        
        self.logger.info(f"Signal message from {source_name}: {text[:50]}...")
        
        if self._message_callback:
            await self._message_callback(target, source_name, text)


class IRCBridge:
    """Async IRC client with SSL support"""
    
    def __init__(self, config: Config):
        self.config = config
        self.reactor = None
        self.connection = None
        self._message_callback = None
        self._admin_callback = None
        self._connected = asyncio.Event()
        self._running = False
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self.logger = logging.getLogger("irc")
        self.current_nick = config.irc_nick
        self._message_queue: asyncio.Queue = asyncio.Queue(maxsize=100)
        self._reconnecting = False
        self._reconnect_lock = asyncio.Lock()
        self._seen_messages: set[str] = set()  # For ZNC replay deduplication
        self._last_connect_time: float = 0

    async def start(self):
        self._running = True
        self._loop = asyncio.get_running_loop()
        self.reactor = irc.client_aio.AioReactor(loop=self._loop)
        
        connect_factory = None
        if self.config.irc_use_ssl:
            ssl_context = ssl.create_default_context()
            if not self.config.irc_verify_ssl:
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
            connect_factory = irc.connection.AioFactory(ssl=ssl_context)
        
        try:
            self.connection = await self.reactor.server().connect(
                self.config.irc_server,
                self.config.irc_port,
                self.config.irc_nick,
                password=self.config.irc_password or None,
                connect_factory=connect_factory,
            )
            
            self.connection.add_global_handler("welcome", self._on_connect)
            self.connection.add_global_handler("pubmsg", self._on_pubmsg)
            self.connection.add_global_handler("privmsg", self._on_privmsg)
            self.connection.add_global_handler("disconnect", self._on_disconnect)
            self.connection.add_global_handler("nicknameinuse", self._on_nick_in_use)
            self.connection.add_global_handler("kick", self._on_kick)
            self.connection.add_global_handler("error", self._on_error)
            
            self.logger.info(f"Connecting to {self.config.irc_server}:{self.config.irc_port}")
            
        except Exception as e:
            self.logger.error(f"Failed to connect: {e}")
            raise
    
    async def stop(self):
        self._running = False
        if self.connection and self.connection.is_connected():
            self.connection.quit("Bridge shutting down")
        self.logger.info("IRC client stopped")
    
    def on_message(self, callback):
        self._message_callback = callback
    
    def on_admin(self, callback):
        self._admin_callback = callback
    
    @staticmethod
    def _format_lines(sender_name: str, text: str, target_name: str = "", prefix: str = "") -> list[str]:
        """Build IRC-ready lines (split to fit message length limits).

        If target_name is set, display as: [TargetName] <sender> message
        Otherwise just: <sender> message. `prefix` is prepended to every line.
        """
        max_len = 400
        lines_to_send: list[str] = []
        for line in text.split("\n"):
            if target_name:
                line_formatted = f"{prefix}[{target_name}] <{sender_name}> {line}"
            else:
                line_formatted = f"{prefix}<{sender_name}> {line}"

            while len(line_formatted) > max_len:
                lines_to_send.append(line_formatted[:max_len])
                line_formatted = line_formatted[max_len:]

            if line_formatted:
                lines_to_send.append(line_formatted)
        return lines_to_send

    async def send_message(self, sender_name: str, text: str, target_name: str = "",
                           channels: Optional[list[str]] = None, prefix: Optional[str] = None):
        """Send a message to one or more IRC channels.

        Defaults to the configured default channel when none are given. `prefix`
        defaults to config.signal_prefix; pass "" for IRC<->IRC mirror echoes.
        """
        channels = channels or [self.config.irc_channel]
        if prefix is None:
            prefix = self.config.signal_prefix
        lines_to_send = self._format_lines(
            sender_name, text, target_name=target_name, prefix=prefix
        )

        # If connected, send immediately; otherwise queue per channel.
        connected = self.connection and self.connection.is_connected()
        for channel in channels:
            for line in lines_to_send:
                if connected:
                    self.connection.privmsg(channel, line)
                    await asyncio.sleep(self.config.rate_limit_ms / 1000)
                else:
                    try:
                        self._message_queue.put_nowait((channel, line))
                        self.logger.debug(f"Queued message for {channel} (queue size: {self._message_queue.qsize()})")
                    except asyncio.QueueFull:
                        self.logger.warning("Message queue full, dropping message")
    
    async def send_private(self, nick: str, text: str):
        if not self.connection or not self.connection.is_connected():
            return
        for line in text.split("\n"):
            self.connection.privmsg(nick, line)
            await asyncio.sleep(self.config.rate_limit_ms / 1000)
    
    async def run_loop(self):
        while self._running:
            try:
                await asyncio.sleep(1)
                if self.connection and not self.connection.is_connected():
                    self.logger.warning("Connection lost, will reconnect...")
                    if self._running:
                        await self._reconnect()
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"IRC loop error: {e}")
                await asyncio.sleep(1)
    
    def _on_connect(self, connection, event):
        import time
        self.logger.info("Connected to IRC server")
        
        # Clear seen messages on new connection to prevent issues with ZNC replay
        self._seen_messages.clear()
        self._last_connect_time = time.time()
        self.logger.debug("Cleared message deduplication cache for new connection")
        
        if self.config.irc_nickserv_password:
            connection.privmsg("NickServ", f"IDENTIFY {self.config.irc_nickserv_password}")
            self.logger.info("Sent NickServ identification")
        for channel in self.config.all_channels():
            connection.join(channel)
            self.logger.info(f"Joining {channel}")
        self._connected.set()
        
        # Process any queued messages
        if not self._message_queue.empty():
            self.logger.info(f"Processing {self._message_queue.qsize()} queued messages")
            self._loop.create_task(self._process_message_queue())
    
    async def _process_message_queue(self):
        """Send queued messages after reconnection"""
        while not self._message_queue.empty() and self.connection and self.connection.is_connected():
            try:
                channel, message = self._message_queue.get_nowait()
                self.connection.privmsg(channel, message)
                await asyncio.sleep(self.config.rate_limit_ms / 1000)
            except asyncio.QueueEmpty:
                break
            except Exception as e:
                self.logger.error(f"Error sending queued message: {e}")
                break
    
    def _on_pubmsg(self, connection, event):
        nick = event.source.nick
        channel = event.target  # the channel the message was sent to
        message = event.arguments[0]

        # Deduplication for ZNC replay - ZNC replays messages on reconnect.
        # Key on channel too so the same text in different channels isn't dropped.
        msg_key = f"{channel}:{nick}:{message}"

        # If this exact message was seen recently, skip it (likely ZNC replay)
        if msg_key in self._seen_messages:
            self.logger.debug(f"Skipping duplicate message from {nick} (ZNC replay)")
            return

        # Add to seen messages
        self._seen_messages.add(msg_key)

        # Keep set manageable - clear old entries periodically
        if len(self._seen_messages) > 500:
            # Keep only last 200
            self._seen_messages = set(list(self._seen_messages)[-200:])

        # Decide what text to relay: either everything (forward_all_messages) or
        # only messages explicitly addressed to the bot ("<nick>: ...").
        pattern = rf"^{re.escape(self.current_nick)}:\s*(.+)$"
        match = re.match(pattern, message, re.IGNORECASE)
        if match:
            relay_text = match.group(1).strip()
        elif self.config.forward_all_messages:
            relay_text = message.strip()
        else:
            return

        if not relay_text:
            return

        self.logger.info(f"IRC relay request from {nick} in {channel}: {relay_text[:50]}...")
        if self._message_callback:
            self._loop.create_task(
                self._message_callback(channel, nick, relay_text)
            )
    
    def _on_privmsg(self, connection, event):
        hostmask = str(event.source)
        nick = event.source.nick
        message = event.arguments[0].strip()
        
        self.logger.debug(f"Private message from {hostmask}: {message}")
        if self._admin_callback:
            self._loop.create_task(
                self._admin_callback(nick, hostmask, message)
            )
    
    def _on_disconnect(self, connection, event):
        self.logger.warning("Disconnected from IRC server")
        self._connected.clear()
        if self._running:
            self._loop.create_task(self._reconnect())
    
    def _on_nick_in_use(self, connection, event):
        new_nick = self.current_nick + "_"
        self.logger.warning(f"Nick in use, trying {new_nick}")
        self.current_nick = new_nick
        connection.nick(new_nick)
    
    def _on_kick(self, connection, event):
        if event.arguments[0] == self.current_nick:
            channel = event.target
            self.logger.warning(f"Kicked from {channel}, rejoining...")
            self._loop.call_later(5, lambda: connection.join(channel))
    
    def _on_error(self, connection, event):
        self.logger.error(f"IRC error: {event.arguments}")
    
    async def _reconnect(self):
        # Use lock to prevent multiple reconnection attempts
        if self._reconnecting:
            self.logger.debug("Reconnection already in progress, skipping")
            return
        
        async with self._reconnect_lock:
            self._reconnecting = True
            try:
                # Clean up old connection if it exists
                if self.connection:
                    try:
                        if self.connection.is_connected():
                            self.connection.quit("Reconnecting")
                    except Exception:
                        pass
                    self.connection = None
                
                # Clean up old reactor
                if self.reactor:
                    try:
                        # Close any pending connections
                        for connection in self.reactor.reactor.connections.values():
                            try:
                                connection.close()
                            except Exception:
                                pass
                    except Exception:
                        pass
                    self.reactor = None
                
                delay = 5  # Start with shorter delay
                max_delay = 120  # Cap at 2 minutes
                
                while self._running:
                    self.logger.info(f"Attempting to reconnect in {delay} seconds...")
                    await asyncio.sleep(delay)
                    
                    if not self._running:
                        break
                    
                    try:
                        # Clear connected event before attempting
                        self._connected.clear()
                        
                        # Re-initialize connection
                        self._loop = asyncio.get_running_loop()
                        self.reactor = irc.client_aio.AioReactor(loop=self._loop)
                        
                        connect_factory = None
                        if self.config.irc_use_ssl:
                            ssl_context = ssl.create_default_context()
                            if not self.config.irc_verify_ssl:
                                ssl_context.check_hostname = False
                                ssl_context.verify_mode = ssl.CERT_NONE
                            connect_factory = irc.connection.AioFactory(ssl=ssl_context)
                        
                        self.connection = await self.reactor.server().connect(
                            self.config.irc_server,
                            self.config.irc_port,
                            self.current_nick,  # Use current_nick in case it was changed
                            password=self.config.irc_password or None,
                            connect_factory=connect_factory,
                        )
                        
                        # Re-register event handlers
                        self.connection.add_global_handler("welcome", self._on_connect)
                        self.connection.add_global_handler("pubmsg", self._on_pubmsg)
                        self.connection.add_global_handler("privmsg", self._on_privmsg)
                        self.connection.add_global_handler("disconnect", self._on_disconnect)
                        self.connection.add_global_handler("nicknameinuse", self._on_nick_in_use)
                        self.connection.add_global_handler("kick", self._on_kick)
                        self.connection.add_global_handler("error", self._on_error)
                        
                        self.logger.info("Reconnection successful")
                        return
                        
                    except Exception as e:
                        self.logger.error(f"Reconnection failed: {e}")
                        # Clean up failed connection
                        self.connection = None
                        self.reactor = None
                        delay = min(delay * 2, max_delay)
            finally:
                self._reconnecting = False


class SignalIRCBridge:
    """Main bridge controller"""
    
    def __init__(self, config: Config):
        self.config = config
        self.signal = SignalClient(config)
        self.irc = IRCBridge(config)
        self.logger = logging.getLogger("bridge")
        self._tasks = []
        self._start_time = None
    
    async def start(self):
        self.logger.info("Starting Signal-IRC Bridge")
        self._start_time = datetime.now()
        
        self.signal.on_message(self._signal_to_irc)
        self.irc.on_message(self._irc_to_signal)
        self.irc.on_admin(self._handle_admin)
        
        await self.signal.start()
        await self.irc.start()
        
        self._tasks = [
            asyncio.create_task(self.signal.poll_loop()),
            asyncio.create_task(self.irc.run_loop()),
        ]
        
        self.logger.info("Bridge started successfully")
        self.logger.info(f"Active targets: {len(self.config.targets)}")
        for t in self.config.targets.values():
            desc = t.name if t.name else t.id
            self.logger.info(f"  - {desc} {'[group]' if t.is_group else ''}")
    
    async def stop(self):
        self.logger.info("Stopping bridge...")
        self.config.save_state()
        
        for task in self._tasks:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        
        await self.signal.stop()
        await self.irc.stop()
        self.logger.info("Bridge stopped")
    
    async def run(self):
        await self.start()
        
        stop_event = asyncio.Event()
        
        def signal_handler():
            self.logger.info("Received shutdown signal")
            stop_event.set()
        
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, signal_handler)
        
        await stop_event.wait()
        await self.stop()
    
    async def _signal_to_irc(self, target: Target, sender_name: str, text: str):
        """
        Relay a Signal message to the IRC channel(s) bound to its target.

        If the target has a name configured, show as: [TargetName] <sender> message
        Otherwise just: <sender> message. A target may map to several channels,
        in which case the message is mirrored to all of them.
        """
        channels = self.config.channels_for_target(target)
        self.logger.debug(f"Relaying Signal->IRC ({', '.join(channels)}): {sender_name}: {text[:50]}...")
        await self.irc.send_message(sender_name, text, target_name=target.name, channels=channels)

    async def _irc_to_signal(self, channel: str, sender: str, text: str):
        """Relay an IRC channel message to the Signal target(s) bound to it.

        Also mirrors the message to any other IRC channels in the same group
        when mirror_channels is enabled.
        """
        targets = self.config.targets_for_channel(channel)
        if not targets:
            self.logger.debug(f"IRC->Signal: no target bound to {channel}, ignoring")
            return

        formatted = f"<{sender}> {text}"
        sent = 0
        for target in targets:
            if await self.signal.send_message(target, formatted):
                sent += 1
            await asyncio.sleep(self.config.rate_limit_ms / 1000)
        self.logger.debug(f"Relayed IRC({channel})->Signal to {sent}/{len(targets)} target(s)")

        # IRC<->IRC mirroring: echo to the other channels in this channel's group.
        mirror_to = self.config.mirror_channels_for(channel)
        if mirror_to:
            self.logger.debug(f"Mirroring IRC msg from {channel} to {', '.join(mirror_to)}")
            await self.irc.send_message(sender, text, channels=mirror_to, prefix="")
    
    async def _handle_admin(self, nick: str, hostmask: str, message: str):
        if self.config.admin_masks:
            authorized = any(
                fnmatch.fnmatch(hostmask, pattern)
                for pattern in self.config.admin_masks
            )
            if not authorized:
                self.logger.warning(f"Unauthorized admin attempt from {hostmask}")
                await self.irc.send_private(nick, "You are not authorized to use admin commands.")
                return

        parts = message.split()
        cmd = parts[0].lower() if parts else ""
        args = parts[1:]

        handlers = {
            "help": self._cmd_help,
            "list": self._cmd_list,
            "add": self._cmd_add,
            "remove": self._cmd_remove,
            "enable": self._cmd_set_enabled,
            "disable": self._cmd_set_enabled,
            "channels": self._cmd_channels,
            "status": self._cmd_status,
            "save": self._cmd_save,
            "join": self._cmd_join,
            "part": self._cmd_part,
        }

        handler = handlers.get(cmd)
        if handler:
            await handler(nick, cmd, args)
        else:
            await self.irc.send_private(nick, f"Unknown command: {cmd}. Try 'help'.")

    async def _cmd_help(self, nick: str, _cmd: str, _args: list[str]):
        help_text = """Available commands:
  help                       - Show this help
  list                       - List active targets
  add <id> [name] [#chan...] - Add a target (phone or group ID)
  remove <id>                - Remove a target
  enable <id>                - Enable a target
  disable <id>               - Disable a target
  channels <id> [#chan...]   - Set/clear a target's IRC channels (none = default)
  status                     - Show bridge status
  save                       - Save current targets to state file
  join <channel> [key]       - Join an IRC channel (with optional key)
  part [channel]             - Part an IRC channel (default: current channel)"""
        await self.irc.send_private(nick, help_text)

    async def _cmd_list(self, nick: str, _cmd: str, _args: list[str]):
        if not self.config.targets:
            await self.irc.send_private(nick, "No targets configured.")
            return
        await self.irc.send_private(nick, f"Targets ({len(self.config.targets)}):")
        for t in self.config.targets.values():
            status = "enabled" if t.enabled else "disabled"
            type_str = "group" if t.is_group else "contact"
            name_str = f" ({t.name})" if t.name else ""
            chans = " ".join(self.config.channels_for_target(t))
            stats = f"msgs={t.message_count}"
            if t.last_message:
                stats += f", last={t.last_message.strftime('%H:%M:%S')}"
            await self.irc.send_private(nick, f"  {t.id}{name_str} [{type_str}] [{status}] -> {chans} {stats}")

    async def _cmd_add(self, nick: str, _cmd: str, args: list[str]):
        if not args:
            await self.irc.send_private(nick, "Usage: add <id> [name] [#chan...]")
            return
        target_id = args[0]
        # Tokens starting with '#' are channels; the first other token is the name.
        channels = [a for a in args[1:] if a.startswith("#")]
        names = [a for a in args[1:] if not a.startswith("#")]
        target_name = names[0] if names else ""
        if target_id in self.config.targets:
            await self.irc.send_private(nick, f"Target {target_id} already exists.")
            return
        target = Target(id=target_id, name=target_name, channels=channels)
        self.config.add_target(target)
        self.config.save_state()
        # Join any newly-referenced channels so the bridge is live immediately.
        for chan in channels:
            if self.irc.connection and self.irc.connection.is_connected():
                self.irc.connection.join(chan)
        display = f"{target_id} ({target_name})" if target_name else target_id
        chan_str = f" -> {' '.join(channels)}" if channels else ""
        await self.irc.send_private(nick, f"Added target: {display}{chan_str}")
        self.logger.info(f"Admin {nick} added target: {display}{chan_str}")

    async def _cmd_remove(self, nick: str, _cmd: str, args: list[str]):
        if not args:
            await self.irc.send_private(nick, "Usage: remove <id>")
            return
        target_id = args[0]
        if self.config.remove_target(target_id):
            self.config.save_state()
            await self.irc.send_private(nick, f"Removed target: {target_id}")
            self.logger.info(f"Admin {nick} removed target: {target_id}")
        else:
            await self.irc.send_private(nick, f"Target not found: {target_id}")

    async def _cmd_set_enabled(self, nick: str, cmd: str, args: list[str]):
        enable = cmd == "enable"
        if not args:
            await self.irc.send_private(nick, f"Usage: {cmd} <id>")
            return
        target_id = args[0]
        if target_id not in self.config.targets:
            await self.irc.send_private(nick, f"Target not found: {target_id}")
            return
        self.config.targets[target_id].enabled = enable
        self.config.save_state()
        label = "Enabled" if enable else "Disabled"
        await self.irc.send_private(nick, f"{label} target: {target_id}")

    async def _cmd_channels(self, nick: str, _cmd: str, args: list[str]):
        if not args:
            await self.irc.send_private(nick, "Usage: channels <id> [#chan...] (no channels = default)")
            return
        target_id = args[0]
        if target_id not in self.config.targets:
            await self.irc.send_private(nick, f"Target not found: {target_id}")
            return
        channels = [a for a in args[1:] if a.startswith("#")]
        target = self.config.targets[target_id]
        target.channels = channels
        self.config.save_state()
        # Join any newly-referenced channels right away.
        if self.irc.connection and self.irc.connection.is_connected():
            for chan in channels:
                self.irc.connection.join(chan)
        effective = " ".join(self.config.channels_for_target(target))
        await self.irc.send_private(nick, f"{target_id} now bridges: {effective}")
        self.logger.info(f"Admin {nick} set channels for {target_id}: {effective}")

    async def _cmd_status(self, nick: str, _cmd: str, _args: list[str]):
        uptime = datetime.now() - self._start_time if self._start_time else "N/A"
        total_msgs = sum(t.message_count for t in self.config.targets.values())
        enabled = sum(1 for t in self.config.targets.values() if t.enabled)
        status = f"""Bridge Status:
  Uptime: {uptime}
  Targets: {len(self.config.targets)} ({enabled} enabled)
  Total messages relayed: {total_msgs}"""
        await self.irc.send_private(nick, status)

    async def _cmd_save(self, nick: str, _cmd: str, _args: list[str]):
        self.config.save_state()
        await self.irc.send_private(nick, "State saved.")

    async def _cmd_join(self, nick: str, _cmd: str, args: list[str]):
        if not args:
            await self.irc.send_private(nick, "Usage: join <channel> [key]")
            return
        channel = args[0]
        key = args[1] if len(args) > 1 else ""
        self.irc.connection.join(channel, key)
        await self.irc.send_private(nick, f"Joining {channel}")
        self.logger.info(f"Admin {nick} joined channel: {channel}")

    async def _cmd_part(self, nick: str, _cmd: str, args: list[str]):
        channel = args[0] if args else self.config.irc_channel
        self.irc.connection.part(channel)
        await self.irc.send_private(nick, f"Parting {channel}")
        self.logger.info(f"Admin {nick} parted channel: {channel}")


def main():
    parser = argparse.ArgumentParser(
        description="Signal-IRC Bridge Bot",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Environment Variables:
  SIGNAL_API_URL          signal-cli-rest-api URL (default: http://localhost:8080)
  SIGNAL_PHONE_NUMBER     Your Signal phone number
  SIGNAL_TARGETS          Comma-separated target IDs to bridge. Append
                          "@#chan1+#chan2" to bind a target to channels.

  IRC_SERVER              IRC server hostname (default: irc.libera.chat)
  IRC_PORT                IRC server port (default: 6697)
  IRC_USE_SSL             Use SSL/TLS (default: true)
  IRC_VERIFY_SSL          Verify SSL certificate (default: true)
  IRC_NICK                Bot nickname (default: SignalBridge)
  IRC_CHANNEL             Default channel to join (default: #signal-bridge)

  SIGNAL_PREFIX           Prefix prepended to Signal -> IRC messages
  FORWARD_ALL_MESSAGES    Forward every IRC message to Signal (default: false)
  MIRROR_CHANNELS         Echo IRC messages between a target's channels (default: false)
  ADMIN_MASKS             Comma-separated IRC hostmasks for admin access

Example config.ini:
  [signal]
  api_url = http://localhost:8080
  phone_number = +1234567890

  [irc]
  server = irc.example.com
  port = 6697
  nick = SignalBridge
  channel = #signal-bridge      ; default channel for targets without one

  [bridge]
  forward_all_messages = false  ; true = relay all IRC msgs, not just "nick:"
  mirror_channels = false       ; true = mirror IRC msgs across a target's channels

  [admin]
  masks = *!~user@your.host.com

  [targets]
  ; Just the ID - relays to the default channel, sender's Signal name shown
  +15551234567 =

  ; A group with a friendly name, bridged to one specific channel
  group.abc123== = group, FamilyChat, channels:#family

  ; Mirror one Signal group across several IRC channels
  group.def456== = group, channels:#mirror-a #mirror-b
"""
    )
    
    parser.add_argument("-c", "--config", help="Path to config file")
    parser.add_argument("-l", "--loglevel", default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                        help="Set log level (default: INFO)")
    parser.add_argument("-s", "--silent", action="store_true",
                        help="Silent mode - suppress all console output")

    args = parser.parse_args()

    log_level = getattr(logging, args.loglevel)
    if args.silent:
        logging.basicConfig(
            level=logging.CRITICAL + 1,  # Disable all logging
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
    else:
        logging.basicConfig(
            level=log_level,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
    
    if args.config:
        config = Config.from_file(args.config)
    else:
        config = Config.from_env()
    
    if not config.signal_phone_number:
        print("Error: Signal phone number is required", file=sys.stderr)
        sys.exit(1)
    
    if not config.targets:
        print("Warning: No targets configured.", file=sys.stderr)
    
    bridge = SignalIRCBridge(config)
    
    try:
        asyncio.run(bridge.run())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
