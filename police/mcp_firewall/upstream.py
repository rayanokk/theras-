"""Client MCP synchrone vers un serveur amont (propriétaire : D).

Implémente l'interface UpstreamClient de L (police/mcp_firewall/connector.py) :

    call_tool(name, arguments) -> Any      bloquant, lève en cas d'échec/timeout

    list_tools() -> list[dict]             pour la façade MCP

Pourquoi un thread : le pipeline du Gateway est synchrone, le SDK MCP est

asynchrone. On fait tourner UNE boucle asyncio dans un thread de fond, qui garde

UNE session MCP ouverte vers l'amont pendant toute la vie du client. Les appels

synchrones y sont soumis avec run_coroutine_threadsafe et attendent le résultat

avec un timeout.

Ce module ne décide RIEN : il exécute ce que le Gateway a déjà autorisé.

"""

from __future__ import annotations

import asyncio

import concurrent.futures

import threading

from typing import Any

from mcp import ClientSession, StdioServerParameters

from mcp.client.stdio import stdio_client

DEFAULT_TIMEOUT_S = 15.0

STARTUP_TIMEOUT_S = 20.0

class UpstreamError(RuntimeError):

    """Échec côté amont : outil en erreur, timeout, amont injoignable."""

class StdioUpstreamClient:

    """Session MCP persistante vers un serveur amont lancé en sous-processus (stdio).

    Utilisation :

        client = StdioUpstreamClient("fs", StdioServerParameters(command="python", args=[...]))

        client.start()

        client.list_tools()

        client.call_tool("read_file", {"path": "x"})

        client.close()

    ou comme gestionnaire de contexte : with StdioUpstreamClient(...) as client: ...

    """

    def __init__(self, name: str, params: StdioServerParameters, timeout_s: float = DEFAULT_TIMEOUT_S):

        self.name = name

        self._params = params

        self._timeout_s = timeout_s

        self._loop: asyncio.AbstractEventLoop | None = None

        self._thread: threading.Thread | None = None

        self._session: ClientSession | None = None

        self._ready = threading.Event()

        self._startup_error: BaseException | None = None

        self._stop: asyncio.Event | None = None

    # ------------------------------------------------------------------ cycle de vie

    def start(self) -> "StdioUpstreamClient":

        if self._thread is not None:

            return self

        self._thread = threading.Thread(target=self._thread_main, name=f"mcp-upstream-{self.name}", daemon=True)

        self._thread.start()

        if not self._ready.wait(STARTUP_TIMEOUT_S):

            raise UpstreamError(f"[{self.name}] amont MCP non démarré après {STARTUP_TIMEOUT_S:.0f} s")

        if self._startup_error is not None:

            raise UpstreamError(f"[{self.name}] démarrage de l'amont impossible : {self._startup_error}") from self._startup_error

        return self

    def close(self) -> None:

        if self._loop is not None and self._stop is not None:

            self._loop.call_soon_threadsafe(self._stop.set)

        if self._thread is not None:

            self._thread.join(timeout=5)

        self._thread = None

        self._session = None

    def __enter__(self) -> "StdioUpstreamClient":

        return self.start()

    def __exit__(self, *exc) -> None:

        self.close()

    def _thread_main(self) -> None:

        self._loop = asyncio.new_event_loop()

        asyncio.set_event_loop(self._loop)

        try:

            self._loop.run_until_complete(self._hold_session())

        except BaseException as exc:  # noqa: BLE001 - remonté via start()

            self._startup_error = exc

        finally:

            self._ready.set()

            self._loop.close()

    async def _hold_session(self) -> None:

        """Ouvre la session, la garde jusqu'à close(). Les contextes MCP doivent

        être ouverts et fermés dans la même tâche : d'où cette coroutine unique."""

        self._stop = asyncio.Event()

        async with stdio_client(self._params) as (read, write):

            async with ClientSession(read, write) as session:

                await session.initialize()

                self._session = session

                self._ready.set()

                await self._stop.wait()

    # ------------------------------------------------------------------ appels

    def _run(self, make_coro, timeout_s: float):

        """make_coro(session) -> coroutine, exécutée dans la boucle du thread de fond."""

        if self._session is None or self._loop is None:

            raise UpstreamError(f"[{self.name}] client amont non démarré")

        future = asyncio.run_coroutine_threadsafe(make_coro(self._session), self._loop)

        try:

            return future.result(timeout=timeout_s)

        except (TimeoutError, concurrent.futures.TimeoutError) as exc:  # distincts avant Python 3.11

            future.cancel()

            raise UpstreamError(f"[{self.name}] timeout après {timeout_s:.0f} s") from exc

        except UpstreamError:

            raise

        except Exception as exc:

            raise UpstreamError(f"[{self.name}] erreur amont : {exc}") from exc

    def list_tools(self) -> list[dict]:

        result = self._run(lambda s: s.list_tools(), self._timeout_s)

        return [

            {"name": t.name, "description": t.description or "", "input_schema": t.inputSchema}

            for t in result.tools

        ]

    def call_tool(self, name: str, arguments: dict) -> Any:

        result = self._run(lambda s: s.call_tool(name, arguments or {}), self._timeout_s)

        text = "\n".join(c.text for c in result.content if getattr(c, "type", None) == "text")

        if result.isError:

            raise UpstreamError(f"[{self.name}] l'outil {name} a échoué : {text or 'erreur sans message'}")

        if result.structuredContent:

            return result.structuredContent

        return text
