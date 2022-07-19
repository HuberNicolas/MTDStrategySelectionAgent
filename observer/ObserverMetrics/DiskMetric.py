import psutil
import shutil
import time


def disk_percentage():
    """
    Current status of disk space

    Calculates the total, used and free memory in Megabytes.

    Parameters:
    none:

    Returns:
    disk_space_total (int): Number of total MB that are on the system
    disk_space_used (int): Number of MB that are currently used on the system
    disk_space_free (int): Number of MB that are currently available on the system
    """
    disk = shutil.disk_usage("/")
    disk_space_total = disk.total / (10 ** 6)
    disk_space_used = disk.used / (10 ** 6)
    disk_space_free = disk_space_total - disk_space_used
    # print("Total: %d MB" % disk_space_total)
    # print("Used: %d MB" % disk_space_used)
    # print("Free: %d MB" % disk_space_free)
    return (disk_space_total, disk_space_used, disk_space_free)


def disk_io_measures(seconds):
    """
    Disk IO measures

    Assesses the disk I/O operations for a time interval and returns a speed (MB / seconds).

    Parameters:
    seconds (int): Time interval in seconds

    Returns:
    read_mega_bytes_sec (int): Number of total MB that the disk have read in the time interval
    write_mega_bytes_sec (int): Number of total MB that the disk have written in the time interval
    """
    # start measure
    start_time = time.time()
    disk_io_counter = psutil.disk_io_counters()

    start_read_bytes = disk_io_counter[2]
    start_write_bytes = disk_io_counter[3]

    # wait before next measure
    time.sleep(seconds)

    # end measure
    disk_io_counter = psutil.disk_io_counters()

    end_read_bytes = disk_io_counter[2]
    end_write_bytes = disk_io_counter[3]

    end_time = time.time()

    # calculations
    time_diff = end_time - start_time

    read_speed = (end_read_bytes - start_read_bytes) / time_diff
    write_speed = (end_write_bytes - start_write_bytes) / time_diff

    # conversions
    read_mega_bytes_sec = round(read_speed / (1024 ** 2), 2)
    write_mega_bytes_sec = round(write_speed / (1024 ** 2), 2)

    return (read_mega_bytes_sec, write_mega_bytes_sec)
