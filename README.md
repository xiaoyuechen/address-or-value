# Address or data?

This repository contains Xiaoyue Chen's Master's thesis which
currently only includes the LaTeX source code of the project proposal.

## The notion of address and data

- An address is used (directly or indirectly) as a memory location in
  some load/store instruction(s).
- Data is not used as memory locations in any load/store instructions.

## Research questions

- Is it possible to know if a piece of memory contains an address or
  data?

## Security implications

- Spectre attacks rely on using data as a memory address for storing.
  If we could distinguish data from address, protections could be
  added to prevent data from being misused as address.

## Who is involved

This thesis project is being conducted at Department of Information
Technology, Uppsala University. Currently, the following persons are
involved:

- Xiaoyue Chen (student)
- Stefanos Kaxiras (professor)
- Yuan Yao (professor)
