import psutil
import datetime


def boot_time():
    """
    Timestamp of the last start-up

    Returns a human-readable (YYYY-MM-DD HH:MM:SS) timestamp of the last start-up

    Parameters:
    none

    Returns:
    (string): Timestamp of the last start-up.
    """
    return (datetime.datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S"))


def uptime():
    """
    Uptime since the last start-up

    Returns a timedelta of the last start-up and now (HH:MM:SS.MS).

    Parameters:
    none

    Returns:
    (timedelta): Timedelta since the last start-up.
    """
    bootTime = psutil.boot_time()
    bootTimeDateTime = datetime.datetime.fromtimestamp(bootTime)

    now = datetime.datetime.now()

    upTime = now - bootTimeDateTime

    return upTime