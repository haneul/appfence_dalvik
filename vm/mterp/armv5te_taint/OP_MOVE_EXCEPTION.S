%verify "executed"
    /* move-exception vAA */
    ldr     r0, [rGLUE, #offGlue_self]  @ r0<- glue->self
    mov     r2, rINST, lsr #8           @ r2<- AA
    ldr     r3, [r0, #offThread_exception]  @ r3<- dvmGetException bypass
    mov     r1, #0                      @ r1<- 0
    FETCH_ADVANCE_INST(1)               @ advance rPC, load rINST
    SET_VREG(r3, r2)                    @ fp[AA]<- exception obj
// begin WITH_TAINT_TRACKING
	SET_TAINT_FP(r3)
	SET_TAINT_CLEAR(r9)
	SET_VREG_TAINT(r9, r2, r3)
// end WITH_TAINT_TRACKING
    GET_INST_OPCODE(ip)                 @ extract opcode from rINST
    str     r1, [r0, #offThread_exception]  @ dvmClearException bypass
    GOTO_OPCODE(ip)                     @ jump to next instruction

