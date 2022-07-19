import psutil


def ram_percentage():
    """
    Current system-wide RAM utilization in the form of a percentage

    Calculates the RAM utilization returns a percentage.

    Parameters:
    none:

    Returns:
    ram_percent (float): Percentage of the RAM utilization
    """
    ram_percent = psutil.virtual_memory()[2]
    # print("RAM usage", ram_percent)
    return ram_percent
