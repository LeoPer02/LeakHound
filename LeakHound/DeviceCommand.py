from abc import ABC, abstractmethod


# ─────────────────────────────────────────────────────────────────────────────
# Existing Command classes
# ─────────────────────────────────────────────────────────────────────────────
class Command(ABC):
    @property
    @abstractmethod
    def name(self) -> str: ...
    @property
    @abstractmethod
    def help(self) -> str: ...
    @abstractmethod
    def execute(self, args: str, ctx: dict) -> None: ...

class StopAnalysis(Command):
    @property
    def name(self):   return "stop"
    @property
    def help(self):   return "stop <device-id>       ⎯ stop that device's controller"
    def execute(self, args, ctx):
        dev = args.strip()
        ev = ctx["stop_events"].get(dev)
        if ev:
            print(f"→ stopping {dev!r}")
            ev.set()
        else:
            print(f"❌ no such device: {dev!r}")

class StatusCommand(Command):
    @property
    def name(self):   return "status"
    @property
    def help(self):   return "status                 ⎯ show which devices are still running"
    def execute(self, args, ctx):
        for dev, ev in ctx["stop_events"].items():
            state = "stopped" if ev.is_set() else "running"
            print(f"  {dev}: {state}")

class HelpCommand(Command):
    @property
    def name(self):   return "help"
    @property
    def help(self):   return "help                   ⎯ show this help message"
    def execute(self, args, ctx):
        print("Available commands:")
        for cmd in ctx["commands"].values():
            print(f"  {cmd.name:<15} {cmd.help}")

class StartDroidBot(Command):
    @property
    def name(self):   return "droidbot_start"
    @property
    def help(self):   return "droidbot_start <timeout> <return_to_manual>  ⎯ start automated mode"
    def execute(self, args, ctx):
        # can parse args here, but for now we just exit the console
        ctx["should_exit"] = True

class StopDroidBot(Command):
    @property
    def name(self):   return "droidbot_stop"
    @property
    def help(self):   return "droidbot_stop         ⎯ stop DroidBot prematurely"
    def execute(self, args, ctx):
        ctx["should_exit"] = True

class StopTraceHive(Command):
    @property
    def name(self):   return "quit"
    @property
    def help(self):   return "quit         ⎯ Quit the LeakHound (this will kill all running threads, so use wisely)"
    def execute(self, args, ctx):
        ctx["should_exit"] = True