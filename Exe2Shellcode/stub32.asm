.model flat,c
.code
public entry

run_exe proto

entry:
sub esp, 84h

call get_pc

add eax,17h
push eax
call run_exe
add esp,04h

add esp, 84h
ret

get_pc:
mov eax,[esp];
ret;

PE_data:
dq 00h
end