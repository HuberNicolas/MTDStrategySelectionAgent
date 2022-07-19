from ObserverMetrics import CpuMetric, RamMetric, DiskMetric, ProcessMetric, NetworkMetric
from datetime import datetime, timezone, timedelta
import csv
import time
import os

timezone_offset = +2.0  # Central European (Summer) Time CEST (UTC+02:00)
tzinfo = timezone(timedelta(hours=timezone_offset))

DELTA_NETWORK = 10
DELTA_DISK = 10
TIMEINTERVAL = 0


def observe(timeout):
    """
    Observer for MTD

    Observers the metrics and writes metrics + timestamp in a .csv-file.

    Parameters:

    Returns:
    none
    """
    # generate filenames
    now = datetime.now(tzinfo)
    format_code = '%Y-%m-%d %H:%M:%S'

    cwd = os.getcwd()
    os.chdir('./data/csv/')
    systemMetricName = 'systemMetric-' + now.strftime(format_code).replace(':','-') + '.csv'
    networkMetricName = 'networkMetric-' + now.strftime(format_code).replace(':','-') + '.csv'
    processMetricName = 'processMetric-' + now.strftime(format_code).replace(':','-') + '.csv'
    metricsNames = [systemMetricName, networkMetricName, processMetricName]

    # generate headers
    systemMetricHeader = ['id', 'cpu_percentage', 'ram_percentage', 'disk_percentage', 'timestamp']
    networkMetricHeader = ['id', 'fd', 'laddIP', 'laddPort', 'raddIP', 'raddPort', 'status', 'pid', 'timestamp']
    processMetricHeader = ['id', 'p_id', 'p_name', 'p_user', 'p_status', 'timestamp']
    metricsHeaders = [systemMetricHeader, networkMetricHeader, processMetricHeader]

    # writing headers
    for (metricHeader, metricName) in zip(metricsHeaders, metricsNames):
        with open(metricName, 'w') as csvfile:
            f = csv.writer(csvfile, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
            f.writerow(metricHeader)
            csvfile.close()

    # observe and write to csv
    with open(systemMetricName, 'w') as systemCSV, open(networkMetricName, 'w') as networkCSV, open(processMetricName,
                                                                                                    'w') as processCSV:
        while True:
            # metrics
            sysMetrics = [CpuMetric.cpu_percentage(1), RamMetric.ram_percentage(),
                          DiskMetric.disk_percentage()[1] / DiskMetric.disk_percentage()[0] * 100]
            networkMetrics = NetworkMetric.tcp_measures()
            psMetrics = ProcessMetric.pids_measures()
            dt = datetime.now(tzinfo)

            # write system metric
            system = csv.writer(systemCSV, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
            sysMetrics.append(dt)
            system.writerow(sysMetrics)

            # write network metric
            network = csv.writer(networkCSV, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
            for t in networkMetrics:
                t.append(dt)
                network.writerow(t)

            # write process metric
            processes = csv.writer(processCSV, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
            for p in psMetrics:
                p.append(dt)
                processes.writerow(p)
            
            time.sleep(timeout)


if __name__ == "__main__":
    """
    print(CpuMetric.cpu_percentage(1))
    print(RamMetric.ram_percentage())
    print(DiskMetric.disk_percentage())
    print(DiskMetric.disk_io_measures(1))
    print(ProcessMetric.pids_measures())
    ProcessMetric.print_pids_information()
    print(NetworkMetric.tcp_measures())
    print(NetworkMetric.net_io_measures(1))
    NetworkMetric.print_interfaces_ip_addresses()
    """

    print("start observing")
    observe(TIMEINTERVAL)
