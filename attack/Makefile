# Copyright (C) 2022  Xiaoyue Chen

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

CFLAGS = -g

victim: victim.c
	$(CC) $(CFLAGS) $< -o $@ -I extern/include -L extern/lib -lcrypto

run-victim: victim
	LD_LIBRARY_PATH=extern/lib ./victim

instrument-victim: victim
	 LD_LIBRARY_PATH=$$(LD_LIBRARY_PATH):extern/lib pin -t dift-addr.so -dumpperiod 1 -filter_rtn AES_encrypt -- ./victim

plot-victim:
	../dift-addr/plot.py < dift-addr.out

.PHONY: clean
clean:
	rm -f victim
