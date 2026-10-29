draft/multiline BATCH with a batched PRIVMSG that has no text param:
multiline_add_message() does strcpy(msgcopy+1, text) with text==NULL (line 809
guards len for NULL text, line 847 does not). NULL deref, any client with
draft/multiline+batch negotiated. base64: T0JBVENIICttbDEgZHJhZnQvbXVsdGlsaW5lICNmdXp6CkBiYXRjaD1tbDEgUFJJVk1TRyAjZnV6eg==
mode 0x4f; lines 'BATCH +ml1 draft/multiline #fuzz' then '@batch=ml1 PRIVMSG #fuzz'
