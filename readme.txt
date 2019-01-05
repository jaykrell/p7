p7 is a project for running Windows programs.
The primary targets are:
 Microsoft C++ compiler and linker
 mono

While the idea is ancient and done many times in many ways,
the current impetus is to enable 32bit mono to run on MacOSX,
with 64bit support going away.

In time this could evolve.
But it is likely to be limited by implementation choices.
 - x86 interpreter -- slow
 - probably no multi-process capability (how to implement VirtualAllocEx / VirtualQueryEx?)
 - uncertain file system fidelity (would prefer to NOT leave files in virtual block device,
   but in a low fidelity host file system).
