import click
import requests
from rich.console import Console


@click.command()
def main():
    Console().print(requests.__name__)
