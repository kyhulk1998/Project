from django.core.management.base import BaseCommand

from subprocess import Popen
from sys import stdout, stdin, stderr
import time, os, signal


class Command(BaseCommand):
    help = 'Run all commands'
    commands = [
        'python manage.py runscript activeSMS',
        'python manage.py runserver'

    ]

    def handle(self, *args, **options):
        proc_list = []

        for command in self.commands:
            print("$ " + command)
            proc = Popen(command, shell=True, stdin=stdin, stdout=stdout, stderr=stderr)
            proc_list.append(proc)

        try:
            while True:
                time.sleep(10)
        except KeyboardInterrupt:
            for proc in proc_list:
                os.kill(proc.pid, signal.SIGKILL)