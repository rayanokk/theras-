"""Serveur MCP amont de test : aucun accès réel. Lancé en sous-processus par les tests."""

import time

from mcp.server.fastmcp import FastMCP

app = FastMCP("fake")

@app.tool()

def read_file(path: str) -> str:

    """Lit un fichier (faux)."""

    return f"contenu de {path}"

@app.tool()

def boom() -> str:

    """Échoue toujours."""

    raise ValueError("panne simulée")

@app.tool()

def slow(seconds: float) -> str:

    """Répond lentement (test du timeout)."""

    time.sleep(seconds)

    return "fini"

if __name__ == "__main__":

    app.run()
