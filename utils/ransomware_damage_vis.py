import matplotlib.pyplot as plt
import numpy as np

plt.style.use('classic')

plt.rc('font', size=10)  # controls default text size
plt.rc('axes', titlesize=10)  # fontsize of the title
plt.rc('axes', labelsize=10)  # fontsize of the x and y labels
plt.rc('xtick', labelsize=10)  # fontsize of the x tick labels
plt.rc('ytick', labelsize=10)  # fontsize of the y tick labels
plt.rc('legend', fontsize=8)  # fontsize of the legend

# individual
fig = plt.figure(figsize=(6.4, 4.8), dpi=600)

plt.subplot(1, 2, 1)
x = np.array(["Healthy", "Encrypted", "Total"])
y = np.array([123, 263, 386])
plt.title("Amount of data (MB)")
plt.barh(x, y)

plt.subplot(1, 2, 2)
x = np.array(["Healthy", "Encrypted", "Total"])
y = np.array([52, 40, 92])
plt.title("Number of files")
plt.bar(x, y)
plt.savefig('ransomware-individual.pdf', facecolor='white',
            transparent=False, bbox_inches="tight")
plt.show()


# mixed
fig = plt.figure(figsize=(6.4, 4.8), dpi=600)

plt.subplot(1, 2, 1)
x = np.array(["Healthy", "Encrypted", "Total"])
y = np.array([135, 250, 386])
plt.title("Amount of data (MB)")
plt.barh(x, y)

plt.subplot(1, 2, 2)
x = np.array(["Healthy", "Encrypted", "Total"])
y = np.array([53, 39, 92])
plt.title("Number of files")
plt.bar(x, y)
plt.savefig('ransomware-mixed.pdf', facecolor='white',
            transparent=False, bbox_inches="tight")
plt.show()
