%verify "executed"
%include "armv5te_taint/unop.S" {"instr":"add     r0, r0, #0x80000000"}
