"""Serveur MCP amont "demo_drive" : expose nos mocks Drive + Mail en stdio.

Ce serveur ne fait AUCUN contrôle de sécurité. Il n'inspecte ni l'appelant, ni la
classification, ni les ACL, ni la confiance. C'est le Gateway Theras qui décide,
en amont, ce qui a le droit de passer : ce module se contente d'exécuter l'action
déjà autorisée sur les mocks, exactement comme le ferait un vrai serveur MCP tiers.

Le nom du serveur et la liste des outils (ainsi que les noms d'arguments) sont
calqués sur police/mcp_firewall/manifests/demo_drive.yaml :

    server: demo_drive
    read_file(path)                              -> DriveMock
    list_files(path)                             -> DriveMock
    share_file(path, email)                      -> DriveMock (email -> recipient)
    delete_file(path)                            -> DriveMock
    send_email(attachment, to, subject, body)    -> MailMock

Une erreur du mock (fichier inconnu, action impossible...) remonte sous forme
d'exception : le SDK MCP la transforme alors en résultat isError pour le client.

Point d'entrée : python -m police.mcp_firewall.upstreams.theras_mocks
"""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from police.connectors.drive_mock import DriveMock
from police.connectors.mail_mock import MailMock, NO_ATTACHMENT

# Nom du serveur = champ `server` du manifeste demo_drive.yaml.
app = FastMCP("demo_drive")

# Un seul DriveMock, partagé avec le Mail (comme en production des mocks) : une
# reclassification ou une suppression côté Drive est vue côté Mail.
_drive = DriveMock()
_mail = MailMock(_drive)


@app.tool()
def read_file(path: str) -> Any:
    """Lit un fichier du Drive. Lève si le fichier est inconnu."""
    return _drive.execute("read_file", path, {})


@app.tool()
def list_files(path: str = "root") -> Any:
    """Liste les fichiers du Drive."""
    return _drive.execute("list_files", path, {})


@app.tool()
def share_file(path: str, email: str, role: str | None = None) -> Any:
    """Partage un fichier avec un destinataire (email)."""
    # Le manifeste expose l'argument `email` ; le connecteur attend `recipient`.
    return _drive.execute("share_file", path, {"recipient": email, "role": role})


@app.tool()
def delete_file(path: str) -> Any:
    """Supprime un fichier du Drive."""
    return _drive.execute("delete_file", path, {})


@app.tool()
def send_email(
    to: str,
    subject: str | None = None,
    body: str | None = None,
    attachment: str | None = None,
) -> Any:
    """Envoie un email (simulé), avec pièce jointe optionnelle."""
    resource_id = attachment if attachment else NO_ATTACHMENT
    return _mail.execute(
        "send_email",
        resource_id,
        {"to": to, "subject": subject, "body": body},
    )


if __name__ == "__main__":
    app.run()
