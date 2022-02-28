#!/usr/bin/python3

# Copyright (C) 2022  Xiaoyue Chen

# This file is part of dift-addr.

# dift-addr is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# dift-addr is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with dift-addr.  If not, see <http://www.gnu.org/licenses/>.

import pandas as pd
import sys
from matplotlib import pyplot as plt

df = pd.read_csv(sys.stdin)

print(df.head())

if len(sys.argv) > 1:
    plt.title(sys.argv[1])

plt.plot(df.executed, df.addr_mem, label='contains memory address')
plt.plot(df.executed, df.addr_any, label='any seen address')
plt.xlabel('#ins executed')
plt.ylabel('#addresses')
plt.legend()
plt.show()
