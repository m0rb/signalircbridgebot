#!/usr/bin/env python3
"""

Signal-IRC Bridge Bot

Bridges messages between multiple Signal contacts/groups and an IRC channel

Admin commands (via IRC private message to the bot):
    help                    - Show available commands
    list                    - List active targets
    add <id> [name]         - Add a target (phone number or group ID)
    remove <id>             - Remove a target
    status                  - Show bridge status
    save                    - Save current targets to state file
    join <channel> [key]    - Join an IRC channel (with optional key)
    part [channel]          - Part an IRC channel (default: current channel)

Configuration:
    Can be provided via environment variables or an INI config file.
    For INI file format, see example_config.ini.

Requirements:
    - Python 3.8+
    - aiohttp
    - irc (irc.client_aio)
    - signal-cli-rest-api running and configured with your Signal account (phone number)

Usage:
    python signalbridgebot.py --config config.ini
    Or set environment variables and run without arguments.

This bot is designed to be run continuously, ideally in a screen/tmux session or as a 
systemd service. 

It will automatically reconnect to IRC if the connection is lost and will poll 
the signal-cli-rest-api for new messages.

This program is provided as-is, without warranty of any kind. Use at your own risk.
                                                                            --morb
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
    id: str
    internal_id: str = ""
    name: str = ""  
    is_group: bool = False
    enabled: bool = True
    message_count: int = 0
    last_message: Optional[datetime] = None
    
    def __post_init__(self):
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
        return d
    
    @classmethod
    def from_dict(cls, data: dict) -> "Target":
        return cls(
            id=data["id"],
            internal_id=data.get("internal_id", ""),
            name=data.get("name", ""),
            is_group=data.get("is_group", False),
            enabled=data.get("enabled", True),
        )


@dataclass
class Config:
    """Bridge configuration"""
    signal_api_url: str = "http://localhost:8080"
    signal_phone_number: str = ""
    
    targets: dict[str, Target] = field(default_factory=dict)
    
    irc_server: str = "irc.libera.chat"
    irc_port: int = 6697
    irc_use_ssl: bool = True
    irc_verify_ssl: bool = True
    irc_nick: str = "SignalBridge"
    irc_channel: str = "#signal-bridge"
    irc_password: str = ""
    irc_nickserv_password: str = ""
    
    admin_masks: list[str] = field(default_factory=list)
    
    rate_limit_ms: int = 500
    
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
            state_file=os.getenv("STATE_FILE", ""),
        )
        
        admin_masks = os.getenv("ADMIN_MASKS", "")
        if admin_masks:
            cfg.admin_masks = [m.strip() for m in admin_masks.split(",")]
        
        targets_str = os.getenv("SIGNAL_TARGETS", "")
        if targets_str:
            for t in targets_str.split(","):
                t = t.strip()
                if t:
                    cfg.add_target(Target(id=t))
        
        cfg.load_state()
        return cfg

    @classmethod
    def from_file(cls, path: str) -> "Config":
        """Load configuration from INI file"""
        parser = configparser.ConfigParser()
        parser.optionxform = str
        parser.read(path)
        
        cfg = cls()
        
        if "signal" in parser:
            s = parser["signal"]
            cfg.signal_api_url = s.get("api_url", cfg.signal_api_url)
            cfg.signal_phone_number = s.get("phone_number", "")
        
        if "irc" in parser:
            i = parser["irc"]
            cfg.irc_server = i.get("server", cfg.irc_server)
            cfg.irc_port = i.getint("port", cfg.irc_port)
            cfg.irc_use_ssl = i.getboolean("use_ssl", cfg.irc_use_ssl)
            cfg.irc_verify_ssl = i.getboolean("verify_ssl", cfg.irc_verify_ssl)
            cfg.irc_nick = i.get("nick", cfg.irc_nick)
            cfg.irc_channel = i.get("channel", cfg.irc_channel)
            cfg.irc_password = i.get("password", cfg.irc_password)
            cfg.irc_nickserv_password = i.get("nickserv_password", cfg.irc_nickserv_password)
        
        if "bridge" in parser:
            b = parser["bridge"]
            cfg.rate_limit_ms = b.getint("rate_limit_ms", cfg.rate_limit_ms)
            cfg.state_file = b.get("state_file", cfg.state_file)
        
        if "admin" in parser:
            a = parser["admin"]
            masks = a.get("masks", "")
            if masks:
                cfg.admin_masks = [m.strip() for m in masks.split(",")]
        
        if "targets" in parser:
            for line in parser["targets"]:
                raw_value = parser["targets"][line]
                target_id = line
                value = raw_value
                
                while value.startswith("="):
                    target_id += "="
                    value = value[1:].lstrip()
                
                is_group = False
                name = ""
                internal_id = ""
                
                if value:
                    parts = [p.strip() for p in value.split(",")]
                    for part in parts:
                        if part.lower() == "group":
                            is_group = True
                        elif part.startswith("internal:"):
                            internal_id = part[9:].strip()
                        elif part:
                            name = part
                
                if target_id:
                    cfg.add_target(Target(id=target_id, internal_id=internal_id, name=name, is_group=is_group))
        
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
    
    async def send_to_all(self, text: str) -> int:
        sent = 0
        for target in self.config.targets.values():
            if target.enabled:
                if await self.send_message(target, text):
                    sent += 1
                await asyncio.sleep(self.config.rate_limit_ms / 1000)
        return sent
    
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
    
    async def send_message(self, sender_name: str, text: str, target_name: str = ""):
        """
        Send a message to the channel.
        
        If target_name is set (from config), display as: [TargetName] <sender> message
        Otherwise just: <sender> message
        """
        if not self.connection or not self.connection.is_connected():
            self.logger.error("Not connected to IRC")
            return
        
        max_len = 400
        for line in text.split("\n"):
            if target_name:
                line_formatted = f"[{target_name}] <{sender_name}> {line}"
            else:
                line_formatted = f"<{sender_name}> {line}"
            
            while len(line_formatted) > max_len:
                self.connection.privmsg(self.config.irc_channel, line_formatted[:max_len])
                line_formatted = line_formatted[max_len:]
                await asyncio.sleep(self.config.rate_limit_ms / 1000)
            
            if line_formatted:
                self.connection.privmsg(self.config.irc_channel, line_formatted)
                await asyncio.sleep(self.config.rate_limit_ms / 1000)
    
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
        self.logger.info("Connected to IRC server")
        if self.config.irc_nickserv_password:
            connection.privmsg("NickServ", f"IDENTIFY {self.config.irc_nickserv_password}")
            self.logger.info("Sent NickServ identification")
        connection.join(self.config.irc_channel)
        self.logger.info(f"Joining {self.config.irc_channel}")
        self._connected.set()
    
    def _on_pubmsg(self, connection, event):
        nick = event.source.nick
        message = event.arguments[0]
        
        pattern = rf"^{re.escape(self.current_nick)}:\s*(.+)$"
        match = re.match(pattern, message, re.IGNORECASE)
        
        if match:
            relay_text = match.group(1).strip()
            self.logger.info(f"IRC relay request from {nick}: {relay_text[:50]}...")
            if self._message_callback:
                self._loop.create_task(
                    self._message_callback(nick, relay_text)
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
            self.logger.warning(f"Kicked from {event.target}, rejoining...")
            self._loop.call_later(5, lambda: connection.join(self.config.irc_channel))
    
    def _on_error(self, connection, event):
        self.logger.error(f"IRC error: {event.arguments}")
    
    async def _reconnect(self):
        delay = 10
        max_delay = 300
        while self._running:
            self.logger.info(f"Attempting to reconnect in {delay} seconds...")
            await asyncio.sleep(delay)
            if not self._running:
                break
            try:
                self._loop = asyncio.get_running_loop()
                self.reactor = irc.client_aio.AioReactor(loop=self._loop)
                await self.start()
                return
            except Exception as e:
                self.logger.error(f"Reconnection failed: {e}")
                delay = min(delay * 2, max_delay)


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
        Relay Signal message to IRC.
        
        If target has a name configured, show as: [TargetName] <sender> message
        Otherwise just: <sender> message
        """
        self.logger.debug(f"Relaying Signal->IRC: {sender_name}: {text[:50]}...")
        await self.irc.send_message(sender_name, text, target_name=target.name)
    
    async def _irc_to_signal(self, sender: str, text: str):
        self.logger.debug(f"Relaying IRC->Signal: {sender}: {text[:50]}...")
        formatted = f"<{sender}> {text}"
        sent = await self.signal.send_to_all(formatted)
        self.logger.debug(f"Sent to {sent} targets")
    
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

        parts = message.split(None, 2)
        cmd = parts[0].lower() if parts else ""
        args = parts[1:] if len(parts) > 1 else []

        handlers = {
            "help": self._cmd_help,
            "list": self._cmd_list,
            "add": self._cmd_add,
            "remove": self._cmd_remove,
            "enable": self._cmd_set_enabled,
            "disable": self._cmd_set_enabled,
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
  help              - Show this help
  list              - List active targets
  add <id> [name]   - Add a target (phone or group ID)
  remove <id>       - Remove a target
  enable <id>       - Enable a target
  disable <id>      - Disable a target
  status            - Show bridge status
  save              - Save current targets to state file
  join <channel> [key] - Join an IRC channel (with optional key)
  part [channel]    - Part an IRC channel (default: current channel)"""
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
            stats = f"msgs={t.message_count}"
            if t.last_message:
                stats += f", last={t.last_message.strftime('%H:%M:%S')}"
            await self.irc.send_private(nick, f"  {t.id}{name_str} [{type_str}] [{status}] {stats}")

    async def _cmd_add(self, nick: str, _cmd: str, args: list[str]):
        if not args:
            await self.irc.send_private(nick, "Usage: add <id> [name]")
            return
        target_id = args[0]
        target_name = args[1] if len(args) > 1 else ""
        if target_id in self.config.targets:
            await self.irc.send_private(nick, f"Target {target_id} already exists.")
            return
        target = Target(id=target_id, name=target_name)
        self.config.add_target(target)
        self.config.save_state()
        display = f"{target_id} ({target_name})" if target_name else target_id
        await self.irc.send_private(nick, f"Added target: {display}")
        self.logger.info(f"Admin {nick} added target: {display}")

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
  SIGNAL_TARGETS          Comma-separated target IDs to bridge
  
  IRC_SERVER              IRC server hostname (default: irc.libera.chat)
  IRC_PORT                IRC server port (default: 6697)
  IRC_USE_SSL             Use SSL/TLS (default: true)
  IRC_VERIFY_SSL          Verify SSL certificate (default: true)
  IRC_NICK                Bot nickname (default: SignalBridge)
  IRC_CHANNEL             Channel to join (default: #signal-bridge)
  
  ADMIN_MASKS             Comma-separated IRC hostmasks for admin access

Example config.ini:
  [signal]
  api_url = http://localhost:8080
  phone_number = +1234567890
  
  [irc]
  server = irc.example.com
  port = 6697
  nick = SignalBridge
  channel = #mychannel
  
  [admin]
  masks = *!~user@your.host.com
  
  [targets]
  ; Just the ID - sender's Signal name will be shown
  +18005551212 = ExamplePerson
  
  ; Group with a nickname - shown as [FamilyChat] <sender> message
  group.abc123== = internal:xyzPDQ= group, FamilyChat
"""
    )
    
    parser.add_argument("-c", "--config", help="Path to config file")
    parser.add_argument("-l", "--loglevel", default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                        help="Set log level (default: INFO)")

    args = parser.parse_args()

    log_level = getattr(logging, args.loglevel)
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
