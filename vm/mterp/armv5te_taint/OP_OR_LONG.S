%verify "executed"
%include "armv5te_taint/binopWide.S" {"preinstr":"orr     r0, r0, r2", "instr":"orr     r1, r1, r3"}
