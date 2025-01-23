.code
public entry

run_exe proto

entry:

sub rsp, 88h
lea rcx,PE_data;
call run_exe
add rsp, 88h
ret

PE_data:
dq 00h
end
