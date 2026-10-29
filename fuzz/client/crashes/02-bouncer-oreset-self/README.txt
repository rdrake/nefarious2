BOUNCER ORESET on the oper's own account -> caller's connection freed,
handler returns 0 (not CPTR_KILLED), parse_client derefs the freed Connection.
base64: X0JPVU5DRVIgT1JFU0VUIGZ1enphY2N0
printable: mode=0x5f (REG|CAPS|SASL as fuzzacct|OPER|CHAN); line 'BOUNCER ORESET fuzzacct'
