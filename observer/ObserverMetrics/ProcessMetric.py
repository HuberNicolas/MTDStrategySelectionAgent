import psutil


def print_pids_information():
    """
    Process IDs (pids) information

    Prints a list of all process IDs of running processes that are currently running.

    Parameters:
    none

    Returns:
    none
    """
    for proc in psutil.process_iter(['pid', 'name', 'username']):
        print(proc.info)


# todo make more performant
# todo check if "ps all" in bash directly is more efficient
def pids_measures():
    """
    Process IDs (pids) information

    Returns a list of list elements, containing information for all processes: ID, name, username and status.

    Parameters:
    none

    Returns:
    (list): list of processes with the following information: ID, name, username and status.
    """
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'username', 'status']):
        processes.append([proc.info['pid'], proc.info['name'], proc.info['username'], proc.info['status']])

    return processes
