%verify "executed"
%include "armv5te_taint/zcmp.S" { "revcmp":"gt" }
