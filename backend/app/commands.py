# commands.py
from flask.cli import with_appcontext
import click
from .weekly_report import send_weekly_report

@click.command("send-weekly-report")
@with_appcontext
def send_weekly():
    """Envoie le rapport hebdomadaire CVE par email."""
    send_weekly_report()
