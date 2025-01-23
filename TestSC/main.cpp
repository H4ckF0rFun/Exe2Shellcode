#include <stdio.h>
#include <Windows.h>

int main(){
	FILE * fp = fopen("sc_stub32", "rb");
	FILE * pe = fopen("TestExe.exe", "rb");
	int size = 0;

	if (fp && pe){
		int sc_len;
		int pe_len;

		fseek(fp, 0, SEEK_END);
		sc_len = ftell(fp);
		fseek(fp, 0, SEEK_SET);
		
		fseek(pe, 0, SEEK_END);
		pe_len = ftell(pe);
		fseek(pe, 0, SEEK_SET);

		DWORD dwOld;
		char * sc = (char*)VirtualAlloc(0, sc_len + pe_len, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		fread(sc, 1, sc_len, fp);
		fread(sc + sc_len, 1, pe_len, pe);

		((void(*)())sc)();
	}

	return 0;
}