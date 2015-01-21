// foo_http_sjis_patch4.cpp : DLL アプリケーション用にエクスポートされる関数を定義します。
//
#include "stdafx.h"

DECLARE_COMPONENT_VERSION(
	"http SJIS patch",
	"1.0.5",
	"http SJIS patch"
);

VALIDATE_COMPONENT_FILENAME("foo_http_sjis_patch4.dll");

static int (WSAAPI *ORIG_closesocket)(SOCKET) = NULL;
static int (WSAAPI *ORIG_recv)(SOCKET,char*,int,int) = NULL;
#if 0
bool is_disp_char(unsigned n){
	return (n=='\r' || n=='\n' || (0x20<=n && n<=0x7e));
}
void dump_string(const char* title, const char* s, int len){
	fprintf(stdout, ">>----- %s -----\n", title);
	if(len<0){
		for(; *s; s++)
			fprintf(stdout, is_disp_char((BYTE)*s) ? "%c" : "\\%x", (BYTE)*s);
	}
	else{
		for(int i=0; i < len; i++)
			fprintf(stdout, is_disp_char((BYTE)s[i]) ? "%c" : "\\%x", (BYTE)s[i]);
	}
	fprintf(stdout, "\n<<----- %s -----\n", title);
	fflush(stdout);
}
#else
void dump_string(const char* title, const char* s, int len){}
#endif


// sjisかutf-8か自動判別
bool is_sjis(const char* _s, const char* _e){
	const BYTE *s, *s2 = (const BYTE*)_s, *e = (const BYTE*)_e;
	int n_sjis = 0;
	int n_utf8 = 0;
	for(s=s2; s<e; s++){
		if(*s & 0x80){
			if((0x81 <= *s && *s <= 0x9F) || (0xE0 <= *s && *s <= 0xEA) || (0xF0 <= *s && *s <= 0xFC)){
				if(++s < e && (0x40 <= *s && *s <= 0xFC))
					n_sjis++;
				else
					n_sjis--;
			}
		}
	}
	for(s=s2; s<e; s++){
		if(*s & 0x80){
			if((*s & 0xF0)==0xE0){
				if(++s < e && (*s & 0xC0)==0x80){
					if(++s < e && (*s & 0xC0)==0x80)
						n_utf8++;
					else
						n_utf8--;
				}
				else
					n_utf8--;
			}
			else if((*s & 0xE0)==0xC0){
				if(++s < e && (*s & 0xC0)==0x80)
					n_utf8++;
				else
					n_utf8--;
			}
			else
				n_utf8--;
		}
	}
	return (n_sjis > 0 && n_sjis > n_utf8);
}


// winsock::recv()
// HTTPヘッダーをsjisからutf-8に変換してfoobar2000へ渡す
int WSAAPI HOOK_recv(SOCKET sock, char* buf, int max, int flags){
	int len = ORIG_recv(sock, buf, max, flags);
	if(len <= 0) return len;

	static SOCKET current_sock = 0;
	static bool   http_process = false;

	if(current_sock != sock){
		current_sock = sock;
		http_process = false;
		if(!strncmp(buf, "HTTP/1.0 200 OK\r\n", 17) || !strncmp(buf, "ICY 200 OK\r\n", 12)){
			http_process = true;//start
		}
	}
	if(http_process && current_sock == sock){
		char* tail = buf;
		char* end  = buf+len;
		for(; tail < end; tail++){
			if(tail+4 <= end && !strncmp(tail, "\r\n\r\n", 4)){
				tail += 4;
				http_process = false;//stop
				break;
			}
		}

		dump_string("http header", buf, tail-buf);

		if(is_sjis(buf,tail)){
			WCHAR ucs2 [1024];
			int ucs2len = MultiByteToWideChar(932,0, buf, tail-buf, ucs2, 1023);
			if(ucs2len>0){
				char utf8 [2048];
				int utf8len = WideCharToMultiByte(CP_UTF8,0, ucs2, ucs2len, utf8, 2047,0,0);
				if(utf8len>0){
					int remain = (end-tail);
					if(utf8len+remain <= max){
						dump_string("utf8", utf8, utf8len);

						memmove(buf+utf8len, tail, remain);
						memcpy(buf, utf8, utf8len);
						len = utf8len + remain;
					}
				}
			}
		}
	}
	return len;
}

// icy-metaint (meta interval)の定期更新は iso8859-1固定扱いになっている模様。
// active codepageに変更してやる
int WINAPI HOOK_mb2wc(UINT codepage, UINT flags, LPCSTR abuf, int alen, LPWSTR wbuf, int wlen){
	if(codepage==28591){//iso-8859-1
		//codepage=CP_ACP;
		codepage=932;
		dump_string("mb2wc", abuf, alen);
	}
	return MultiByteToWideChar(codepage, flags, abuf, alen, wbuf, wlen);
}

//
void _install(void** ptr, void* func){
	DWORD old;
	if(VirtualProtect(ptr, sizeof(void*), PAGE_READWRITE, &old)){
		*ptr = func;
		VirtualProtect(ptr, sizeof(void*), old, &old);
	}
}

// foobar2000.exeのインポートテーブルを書き換え、MultiByteToWideChar()と winsock::recv()をフックする
// 他のdllがインポートしていても、そちらは変更しない。exeだけで良い。
BOOL startup(){
	DWORD dos = (DWORD) GetModuleHandle(0);//exe
	IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(dos + ((IMAGE_DOS_HEADER*)dos)->e_lfanew);

	void** p_imp_mb2wc = 0;
	void** p_imp_recv = 0;

	//import table - kernel32.dll MultiByteToWideChar()
	IMAGE_IMPORT_DESCRIPTOR* imp = (IMAGE_IMPORT_DESCRIPTOR*)
		(dos + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	for(; imp->FirstThunk; imp++){
		const char* dll = (const char*)(dos+imp->Name);
		if(!_stricmp(dll, "kernel32.dll")){
			IMAGE_THUNK_DATA* pIAT = (IMAGE_THUNK_DATA*)(dos + imp->FirstThunk);
			IMAGE_THUNK_DATA* pINT = (IMAGE_THUNK_DATA*)(dos + imp->OriginalFirstThunk);
			for(; pINT->u1.Function; pINT++,pIAT++){
				if(! IMAGE_SNAP_BY_ORDINAL(pINT->u1.Ordinal)){
					const char* func = (const char*) ((IMAGE_IMPORT_BY_NAME*)(dos + pINT->u1.AddressOfData))->Name;
					if(!_stricmp(func, "MultiByteToWideChar")){
						p_imp_mb2wc = (void**) &pIAT->u1.Function;
					}
				}
			}
		}
	}

	//delay import talble - ws2_32.dll recv()
	struct ImgDelayDesc{
		DWORD grAttrs, szName, phmod, pIAT, pINT, pBoundIAT, pUnloadIAT, dwTimeStamp;
	} *delay = (ImgDelayDesc*)
		(dos + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress);
	for(; delay->pIAT; delay++){
		const char* dll = (const char*)(dos+delay->szName);
		if(!_stricmp(dll, "ws2_32.dll")){
			IMAGE_THUNK_DATA* pIAT = (IMAGE_THUNK_DATA*)(dos + delay->pIAT);
			IMAGE_THUNK_DATA* pINT = (IMAGE_THUNK_DATA*)(dos + delay->pINT);
			for(; pINT->u1.Function; pINT++,pIAT++){
				if(IMAGE_SNAP_BY_ORDINAL(pINT->u1.Ordinal)){
					if((pINT->u1.Ordinal & 0x7fffffff)==16){
						p_imp_recv = (void**) &pIAT->u1.Function;
						ORIG_recv = (int(WSAAPI*)(SOCKET,char*,int,int))pIAT->u1.Function;
						// 遅延ロードDLLなので先にアドレス解決を実施する
						ORIG_recv(INVALID_SOCKET,0,0,0);
						// 解決したアドレスを再取得
						ORIG_recv = (int(WSAAPI*)(SOCKET,char*,int,int))pIAT->u1.Function;
					}
				}
			}
		}
	}

	if(!p_imp_mb2wc || !p_imp_recv)
		return FALSE;

	_install(p_imp_mb2wc, HOOK_mb2wc);
	_install(p_imp_recv, HOOK_recv);
	return TRUE;
}

class initquit_handler : public initquit
{
	virtual void on_init() { startup(); }
	virtual void on_quit() {}
};

static initquit_factory_t< initquit_handler > foo_initquit;
//EOF