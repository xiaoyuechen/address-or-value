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

INSTRUMENT_CMD = $(PIN) -t dift-addr.so -o "results/$@.dump" -dumpperiod 1000000 --
PIPE = > results/$@.ref.out 2> results/$@.ref.err
SELECTED = astar bwaves bzip2 calculix mcf omnetpp sjeng soplex sphinx # h264ref

.PHONY: selected
selected: $(SELECTED)

.PHONY: clean
clean:; $(RM) -rf results

.PHONY: results-dir
results-dir:; [ -d results ] || $(MKDIR) results

.PHONY: GemsFDTD
GemsFDTD:; $(INSTRUMENT_CMD) $@ $(PIPE)

.PHONY: astar
astar:; $(INSTRUMENT_CMD) $@ BigLakes2048.cfg $(PIPE)

.PHONY: bwaves
bwaves:; $(INSTRUMENT_CMD) $@ $(PIPE)

.PHONY: bzip2
bzip2:; $(INSTRUMENT_CMD) $@ chicken.jpg 30 $(PIPE)

.PHONY: cactusADM
cactusADM:; $(INSTRUMENT_CMD) $@ benchADM.par $(PIPE)

.PHONY: calculix
calculix:; $(INSTRUMENT_CMD) $@ -i hyperviscoplastic $(PIPE)

.PHONY: gamess
gamess:; $(INSTRUMENT_CMD) gamess < cytosine.2.config $(PIPE)

.PHONY: gobmk
gobmk:; $(INSTRUMENT_CMD) gobmk --quiet --mode gtp < 13x13.tst $(PIPE)

.PHONY: gromacs
gromacs:; $(INSTRUMENT_CMD) gromacs -silent -deffnm gromacs -nice 0 $(PIPE)

.PHONY: h264ref
h264ref:; $(INSTRUMENT_CMD) $@ foreman_ref_encoder_baseline.cfg $(PIPE)

.PHONY: leslie3d
leslie3d:; $(INSTRUMENT_CMD) $@ < $@.in $(PIPE)

.PHONY: libquantum
libquantum:; $(INSTRUMENT_CMD) $@ 1397 8 $(PIPE)

.PHONY: mcf
mcf:; $(INSTRUMENT_CMD) $@ "inp.in" $(PIPE)

.PHONY: milc
milc:; $(INSTRUMENT_CMD) $@ < "su3imp.in" $(PIPE)

.PHONY: named
named:; $(INSTRUMENT_CMD) $@ $@.input --iterations 38 $(PIPE)

.PHONY: omnetpp
omnetpp:; $(INSTRUMENT_CMD) $@ $@.ini $(PIPE)

.PHONY: sjeng
sjeng:; $(INSTRUMENT_CMD) $@ ref.txt $(PIPE)

.PHONY: soplex
soplex:; $(INSTRUMENT_CMD) $@ -s1 -e -m45000 pds-50.mps $(PIPE)

.PHONY: sphinx
sphinx:; $(INSTRUMENT_CMD) $@ ctlfile . args.an4 $(PIPE)

.PHONY: zeusmp
zeusmp:; $(INSTRUMENT_CMD) $@ $(PIPE)
