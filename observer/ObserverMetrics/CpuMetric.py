import psutil


def cpu_percentage(seconds):
    """
    Current system-wide CPU utilization in the form of a percentage

    Calculates the CPU utilization for a time interval and returns a percentage.

    Parameters:
    seconds (int): Time interval in seconds

    Returns:
    cpu_percent (float): Percentage of the CPU utilization for the given interval
    """
    cpu_percent = psutil.cpu_percent(seconds)
    # print("CPU usage", cpu_percent)
    return cpu_percent
