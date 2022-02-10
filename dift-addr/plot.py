#!/usr/bin/python3

import pandas as pd
import sys
from matplotlib import pyplot as plt

df = pd.read_csv(sys.stdin)

print(df.head())
plt.plot(df.executed, df.addr_mem, label='contains memory address')
plt.plot(df.executed, df.addr_any, label='any seen address')
plt.xlabel('#ins executed')
plt.ylabel('#addresses')
plt.legend()
plt.show()
