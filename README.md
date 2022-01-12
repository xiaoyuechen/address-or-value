# Address or value?

This repository contains Xiaoyue Chen's Master's thesis which
currently only includes the LaTeX source code of the project proposal.

## The notion of address and value

- An address is used (directly or indirectly) as a memory location in
  some load/store instruction(s).
- A value is not used as a memory location in any load/store instructions.

## Research questions

- Is it possible to know if a piece of memory contains an address or a
  value?

## Security implications

- Spectre attacks rely on using a value as a memory address for
  storing. If we could distinguish a value from an address,
  protections could be added to prevent a value from being misused as
  an address.

## Who is involved

This thesis project is being conducted at Department of Information
Technology, Uppsala University. Currently, the following persons are
involved:

- Xiaoyue Chen (student)
- Stefanos Kaxiras (professor)
- Yuan Yao (professor)
