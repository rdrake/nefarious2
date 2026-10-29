CLEARMODE with a mode string covering more clearable modes than control_buf[20]
holds: do_clearmode appends one char per cleared flag (16 base + 10 ex pairs) with
no bound check, then control_buf[control_buf_i]='\0' writes past the end. Oper-gated
(mo_clearmode). base64: U0NMRUFSTU9ERSAjZnV6eiB2YW1wT3JpYnNvY2tldE5MaGxD
mode 0x53; line 'CLEARMODE #fuzz vampOribsocketNLhlC'
