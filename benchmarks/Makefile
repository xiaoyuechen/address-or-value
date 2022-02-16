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

PATH = .
MAKE = /usr/bin/make
RM = /bin/rm
MKDIR = /bin/mkdir
SHELL = /bin/bash
PIN = /opt/pin

INSTRUMENT_CMD = $(PIN) -t dift-addr.so -o "results/$@.dump" -dumpperiod 10000 --
PIPE = > results/$@.ref.out 2> results/$@.ref.err
SELECTED = astar bwaves bzip2 calculix mcf omnetpp sjeng soplex sphinx # h264ref

.PHONY: instrument-selected
instrument-selected: $(SELECTED:%=%-instrument)

.PHONY: clean
clean:; $(RM) -rf results

.PHONY: %-instrument
%-instrument: results-dir
	$(INSTRUMENT_CMD) $* $(PIPE)

.PHONY: results-dir
results-dir:; [ -d results ] || $(MKDIR) results

.PHONY: GemsFDTD
GemsFDTD:; $@

.PHONY: astar
astar:; $@ BigLakes2048.cfg

.PHONY: bwaves
bwaves:; $@

.PHONY: bzip2
bzip2:; $@ chicken.jpg 30

.PHONY: cactusADM
cactusADM:; $@ benchADM.par

.PHONY: calculix
calculix:; $@ -i hyperviscoplastic

.PHONY: gamess
gamess:; gamess < cytosine.2.config

.PHONY: gobmk
gobmk:; gobmk --quiet --mode gtp < 13x13.tst

.PHONY: gromacs
gromacs:; gromacs -silent -deffnm gromacs -nice 0

.PHONY: h264ref
h264ref:; $@ foreman_ref_encoder_baseline.cfg

.PHONY: leslie3d
leslie3d:; $@ < $@.in

.PHONY: libquantum
libquantum:; $@ 1397 8

.PHONY: mcf
mcf:; $@ "inp.in"

.PHONY: milc
milc:; $@ < "su3imp.in"

.PHONY: named
named:; $@ $@.input --iterations 38

.PHONY: omnetpp
omnetpp:; $@ $@.ini

.PHONY: sjeng
sjeng:; $@ ref.txt

.PHONY: soplex
soplex:; $@ -s1 -e -m45000 pds-50.mps

.PHONY: sphinx
sphinx:; $@ ctlfile . args.an4

.PHONY: zeusmp
zeusmp:; $@
