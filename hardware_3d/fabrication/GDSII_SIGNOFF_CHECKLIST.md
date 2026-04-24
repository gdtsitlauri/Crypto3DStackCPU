# GDSII / 3D IC Signoff Checklist

This checklist is for future fabricated hardware only.

## Logical Signoff

- [ ] RTL lint clean
- [ ] CDC/RDC clean
- [ ] formal equivalence
- [ ] gate-level simulation
- [ ] memory BIST inserted
- [ ] scan/DFT inserted

## Physical Signoff

- [ ] floorplan complete
- [ ] layer placement complete
- [ ] TSV placement complete
- [ ] SRAM macros placed
- [ ] clock tree synthesis
- [ ] route complete
- [ ] timing closure
- [ ] hold closure
- [ ] DRC clean
- [ ] LVS clean
- [ ] antenna clean
- [ ] IR drop clean
- [ ] EM clean
- [ ] thermal signoff
- [ ] extraction complete
- [ ] GDSII/OASIS exported

## Security Signoff

- [ ] debug ports disabled or locked
- [ ] root key non-readable
- [ ] key zeroization path verified
- [ ] tamper sensors verified
- [ ] side-channel mitigation reviewed
- [ ] fault-injection response tested
