// Native Windows x64 TAPI service provider. One line per workstation.
#define WIN32 1
#define WIN32_LEAN_AND_MEAN
#define TAPI_CURRENT_VERSION 0x00020000
#define TAPI_NO_DATA_EXTENSIONS 1
#include <windows.h>
#include <tapi.h>
#include <tspi.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <ctime>
#pragma comment(lib,"bcrypt")
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#pragma comment(lib,"winhttp")
#pragma comment(lib,"advapi32")
using namespace std;
using Clock=chrono::steady_clock;
namespace {
struct Call {
    HTAPICALL tapi{};
    string wire, number;
    bool incoming=false, pending=false;
    DWORD state=LINECALLSTATE_UNKNOWN;
    DRV_REQUESTID request{};
    Clock::time_point since=Clock::now();
};
struct Observation {string id,phase,direction,number;};
mutex guard;
map<DWORD_PTR,Call> calls;
DWORD_PTR serial=1;
DWORD baseId, providerId,mediaModes;
HTAPILINE line{};
LINEEVENT notify{};
ASYNC_COMPLETION completed{};
HMODULE module{};
thread poller;
atomic<bool> stopping{false};
wstring token;
const wstring title=L"Frapuri CTI";
DWORD_PTR key(HDRVCALL c){return reinterpret_cast<DWORD_PTR>(c);}
HDRVLINE device(){return reinterpret_cast<HDRVLINE>(1);}
template<class T> bool setup(T* p) {
    if(!p || p->dwTotalSize<sizeof(T)) {if(p && p->dwTotalSize>=12)p->dwNeededSize=sizeof(T);return false;}
    DWORD sz=p->dwTotalSize; memset(p,0,sizeof(T));p->dwTotalSize=sz;p->dwNeededSize=p->dwUsedSize=sizeof(T);return true;
}
template<class T> void addText(T* p,const wstring& s,DWORD& pos,DWORD& len) {
    if(s.empty())return;
    DWORD offset=p->dwNeededSize, bytes=static_cast<DWORD>((s.size()+1)*sizeof(wchar_t));
    p->dwNeededSize+=bytes;
    if(p->dwTotalSize>=p->dwNeededSize){memcpy(reinterpret_cast<char*>(p)+offset,s.c_str(),bytes);pos=offset;len=bytes;p->dwUsedSize=p->dwNeededSize;}
}
struct Internet {HINTERNET h{}; ~Internet(){if(h)WinHttpCloseHandle(h);} };
string hexBytes(const unsigned char* data, size_t length) {
    static const char digits[]="0123456789abcdef";
    string result;
    for(size_t i=0;i<length;++i){result+=digits[data[i]>>4];result+=digits[data[i]&15];}
    return result;
}
string mac(const string& data) {
    BCRYPT_ALG_HANDLE alg{};
    if(BCryptOpenAlgorithmProvider(&alg,BCRYPT_SHA256_ALGORITHM,nullptr,BCRYPT_ALG_HANDLE_HMAC_FLAG)<0)return {};
    string secret(token.begin(),token.end());
    unsigned char digest[32]{};
    BCRYPT_HASH_HANDLE hash{};
    NTSTATUS status=BCryptCreateHash(alg,&hash,nullptr,0,(PUCHAR)secret.data(),(ULONG)secret.size(),0);
    if(status>=0)status=BCryptHashData(hash,(PUCHAR)data.data(),(ULONG)data.size(),0);
    if(status>=0)status=BCryptFinishHash(hash,digest,sizeof(digest),0);
    if(hash)BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg,0);
    return status<0?string():hexBytes(digest,sizeof(digest));
}
bool exchangeHttp(bool dial,const string& num,string& response) {
    Internet s{WinHttpOpen(L"FrapuriCTI/1",WINHTTP_ACCESS_TYPE_NO_PROXY,nullptr,nullptr,0)};
    if(!s.h)return false;
    WinHttpSetTimeouts(s.h,1000,1000,1500,dial?12000:4500);
    Internet c{WinHttpConnect(s.h,L"127.0.0.1",18763,0)};if(!c.h)return false;
    Internet q{WinHttpOpenRequest(c.h,dial?L"POST":L"GET",dial?L"/dial":L"/calls",nullptr,nullptr,nullptr,0)};if(!q.h)return false;
    DWORD policy=WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
    if(!WinHttpSetOption(q.h,WINHTTP_OPTION_REDIRECT_POLICY,&policy,sizeof(policy)))return false;
    unsigned char random[16];
    if(BCryptGenRandom(nullptr,random,sizeof(random),BCRYPT_USE_SYSTEM_PREFERRED_RNG)<0)return false;
    string nonce=to_string(time(nullptr))+"-"+hexBytes(random,sizeof(random));
    string signature=mac(string(dial?"POST|/dial|":"GET|/calls|")+nonce+"|"+num);
    if(signature.empty())return false;
    string headers="X-CTI-Nonce: "+nonce+"\r\nX-CTI-Mac: "+signature;
    wstring header(headers.begin(),headers.end());
    DWORD size=static_cast<DWORD>(num.size());
    if(!WinHttpSendRequest(q.h,header.c_str(),-1L,size?(void*)num.data():nullptr,size,size,0) || !WinHttpReceiveResponse(q.h,nullptr))return false;
    DWORD status=0,len=sizeof(status);
    if(!WinHttpQueryHeaders(q.h,WINHTTP_QUERY_STATUS_CODE|WINHTTP_QUERY_FLAG_NUMBER,nullptr,&status,&len,nullptr)||status!=(dial?204u:200u))return false;
    char chunk[1024]; DWORD n=0;
    for(;;){if(!WinHttpReadData(q.h,chunk,sizeof(chunk),&n))return false;if(!n)break;if(response.size()+n>16384)return false;response.append(chunk,n);}
    wchar_t proof[65]{};DWORD length=sizeof(proof);
    if(!WinHttpQueryHeaders(q.h,WINHTTP_QUERY_CUSTOM,L"X-CTI-Proof",proof,&length,nullptr))return false;
    string expected=mac("reply|"+nonce+"|"+response);
    return expected.size()==64 && wstring(expected.begin(),expected.end())==proof;
}
void transition(DWORD_PTR id,DWORD state) {
    LINEEVENT send; HTAPILINE l; HTAPICALL h;
    {lock_guard<mutex> lock(guard);auto it=calls.find(id);if(it==calls.end() || it->second.state==state || !line)return;
     it->second.state=state;h=it->second.tapi;l=line;send=notify;}
    if(h && send)send(l,h,LINE_CALLSTATE,state,0,LINEMEDIAMODE_INTERACTIVEVOICE);
}
void finish(DWORD_PTR id){transition(id,LINECALLSTATE_DISCONNECTED);transition(id,LINECALLSTATE_IDLE);}
void observe(const Observation& o) {
    DWORD_PTR id=0;LINEEVENT send=nullptr;HTAPILINE l{};
    {lock_guard<mutex> lock(guard);if(!line)return;
     for(auto& e:calls)if(e.second.wire==o.id && e.second.state!=LINECALLSTATE_IDLE){id=e.first;break;}
     if(!id && o.direction=="out")for(auto& e:calls){
        auto& c=e.second;
        if(!c.incoming && c.wire.empty() && !c.pending && c.state!=LINECALLSTATE_IDLE &&
          (o.number=="-" || o.number==c.number)){id=e.first;c.wire=o.id;break;}
     }
     if(!id){
        if(o.direction!="in" || !(mediaModes&LINEMEDIAMODE_INTERACTIVEVOICE))return;
        id=++serial;auto& c=calls[id];c.wire=o.id;c.incoming=true;c.number=o.number=="-"?"":o.number;l=line;send=notify;
     }}
    if(send){
        HTAPICALL h{};
        send(l,0,LINE_NEWCALL,id,reinterpret_cast<DWORD_PTR>(&h),0);
        lock_guard<mutex> lock(guard);auto it=calls.find(id);
        if(it==calls.end())return;if(!h || line!=l){calls.erase(it);return;}it->second.tapi=h;
    }
    if(send && o.phase=="up")transition(id,LINECALLSTATE_OFFERING);
    transition(id,o.phase=="up"?LINECALLSTATE_CONNECTED:(o.direction=="in"?LINECALLSTATE_OFFERING:LINECALLSTATE_PROCEEDING));
}
void process() {
    while(!stopping.load()){
        DWORD_PTR id=0;DRV_REQUESTID req{};string num;bool open;
        {lock_guard<mutex> lock(guard);open=line!=0;
         for(auto& e:calls)if(e.second.pending){id=e.first;e.second.pending=false;req=e.second.request;num=e.second.number;break;}}
        if(id){string unused;bool ok=exchangeHttp(true,num,unused);
            completed(req,ok?0:LINEERR_OPERATIONFAILED);
            if(ok)transition(id,LINECALLSTATE_DIALING);
            else {lock_guard<mutex> lock(guard);calls.erase(id);}
        }
        if(open){
            string data;bool online=exchangeHttp(false,"",data);vector<string> seen;
            if(online){
                istringstream input(data);Observation o;
                while(input>>o.id>>o.phase>>o.direction>>o.number){seen.push_back(o.id);observe(o);}
            }
            vector<DWORD_PTR> ended;
            {lock_guard<mutex> lock(guard);
             for(auto& e:calls){auto& c=e.second;
              if(!c.pending && c.state!=LINECALLSTATE_IDLE &&
                ((!c.wire.empty() && (!online || find(seen.begin(),seen.end(),c.wire)==seen.end())) ||
                (c.wire.empty() && Clock::now()-c.since>chrono::seconds(35))))ended.push_back(e.first);}}
            for(auto i:ended)finish(i);
        }
        this_thread::sleep_for(chrono::milliseconds(200));
    }
}
}
BOOL WINAPI DllMain(HMODULE m,DWORD reason,LPVOID){if(reason==DLL_PROCESS_ATTACH){module=m;DisableThreadLibraryCalls(m);}return TRUE;}
LONG TSPIAPI TSPI_providerUIIdentify(LPWSTR p){return GetModuleFileNameW(module,p,MAX_PATH)?0:LINEERR_OPERATIONFAILED;}
LONG TSPIAPI TUISPI_providerInstall(TUISPIDLLCALLBACK,HWND,DWORD){return 0;}
LONG TSPIAPI TUISPI_providerRemove(TUISPIDLLCALLBACK,HWND,DWORD){return 0;}
LONG TSPIAPI TSPI_providerEnumDevices(DWORD,LPDWORD lines,LPDWORD phones,HPROVIDER,LINEEVENT,PHONEEVENT){*lines=1;*phones=0;return 0;}
LONG TSPIAPI TSPI_lineNegotiateTSPIVersion(DWORD,DWORD low,DWORD high,LPDWORD out){if(low>0x20000||high<0x20000)return LINEERR_INCOMPATIBLEAPIVERSION;*out=0x20000;return 0;}
LONG TSPIAPI TSPI_providerInit(DWORD,DWORD perm,DWORD base,DWORD,DWORD_PTR,DWORD_PTR,ASYNC_COMPLETION complete,LPDWORD options){
 wchar_t value[64]{};DWORD len=sizeof(value);
 if(RegGetValueW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Frapuri\\CTIPilot",L"LocalToken",RRF_RT_REG_SZ,nullptr,value,&len)!=ERROR_SUCCESS || wcslen(value)!=48)return LINEERR_INIFILECORRUPT;
 providerId=perm;baseId=base;completed=complete;token=value;*options=0;stopping=false;
 try {poller=thread(process);}catch(...){return LINEERR_NOMEM;}return 0;
}
LONG TSPIAPI TSPI_providerShutdown(DWORD,DWORD){stopping=true;if(poller.joinable())poller.join();lock_guard<mutex> lock(guard);calls.clear();line=0;notify=nullptr;return 0;}
LONG TSPIAPI TSPI_lineGetDevCaps(DWORD id,DWORD,DWORD,LPLINEDEVCAPS p){
 if(id!=baseId)return LINEERR_BADDEVICEID;if(!setup(p))return LINEERR_STRUCTURETOOSMALL;
 p->dwPermanentLineID=providerId<<16;p->dwStringFormat=STRINGFORMAT_UNICODE;p->dwAddressModes=LINEADDRESSMODE_ADDRESSID;
 p->dwNumAddresses=1;p->dwMediaModes=LINEMEDIAMODE_INTERACTIVEVOICE;p->dwBearerModes=LINEBEARERMODE_VOICE;
 p->dwMaxNumActiveCalls=8;p->dwLineFeatures=LINEFEATURE_MAKECALL;
 addText(p,title,p->dwLineNameOffset,p->dwLineNameSize);return 0;
}
LONG TSPIAPI TSPI_lineGetAddressCaps(DWORD id,DWORD addr,DWORD,DWORD,LPLINEADDRESSCAPS p){
 if(id!=baseId||addr)return LINEERR_INVALADDRESSID;if(!setup(p))return LINEERR_STRUCTURETOOSMALL;
 p->dwLineDeviceID=id;p->dwAddressSharing=LINEADDRESSSHARING_PRIVATE;
 p->dwCallStates=LINECALLSTATE_IDLE|LINECALLSTATE_DIALING|LINECALLSTATE_PROCEEDING|LINECALLSTATE_OFFERING|LINECALLSTATE_CONNECTED|LINECALLSTATE_DISCONNECTED;
 p->dwCallerIDFlags=LINECALLPARTYID_ADDRESS|LINECALLPARTYID_UNKNOWN;p->dwCalledIDFlags=p->dwCallerIDFlags;
 p->dwMaxNumActiveCalls=8;p->dwAddressFeatures=LINEADDRFEATURE_MAKECALL;addText(p,title,p->dwAddressOffset,p->dwAddressSize);return 0;
}
LONG TSPIAPI TSPI_lineOpen(DWORD id,HTAPILINE l,LPHDRVLINE out,DWORD,LINEEVENT cb){
 lock_guard<mutex> lock(guard);if(id!=baseId)return LINEERR_BADDEVICEID;if(line)return LINEERR_ALLOCATED;
 line=l;notify=cb;mediaModes=0;*out=device();return 0;
}
LONG TSPIAPI TSPI_lineClose(HDRVLINE){lock_guard<mutex> lock(guard);line=0;notify=nullptr;calls.clear();return 0;}
LONG TSPIAPI TSPI_lineSetDefaultMediaDetection(HDRVLINE,DWORD modes){lock_guard<mutex> lock(guard);mediaModes=modes;return 0;}
LONG TSPIAPI TSPI_lineSetStatusMessages(HDRVLINE,DWORD,DWORD){return 0;}
LONG TSPIAPI TSPI_lineGetNumAddressIDs(HDRVLINE,LPDWORD out){*out=1;return 0;}
LONG TSPIAPI TSPI_lineGetAddressStatus(HDRVLINE,DWORD addr,LPLINEADDRESSSTATUS p){
 if(addr)return LINEERR_INVALADDRESSID;if(!setup(p))return LINEERR_STRUCTURETOOSMALL;
 lock_guard<mutex> lock(guard);for(auto& e:calls)if(e.second.state!=LINECALLSTATE_IDLE)++p->dwNumActiveCalls;
 p->dwAddressFeatures=LINEADDRFEATURE_MAKECALL;return 0;
}
LONG TSPIAPI TSPI_lineGetLineDevStatus(HDRVLINE,LPLINEDEVSTATUS p){if(!setup(p))return LINEERR_STRUCTURETOOSMALL;
 p->dwDevStatusFlags=LINEDEVSTATUSFLAGS_CONNECTED|LINEDEVSTATUSFLAGS_INSERVICE;p->dwLineFeatures=LINEFEATURE_MAKECALL;
 lock_guard<mutex> lock(guard);for(auto& e:calls)if(e.second.state!=LINECALLSTATE_IDLE)++p->dwNumActiveCalls;return 0;}
LONG TSPIAPI TSPI_lineMakeCall(DRV_REQUESTID request,HDRVLINE l,HTAPICALL h,LPHDRVCALL out,LPCWSTR dest,DWORD,LPLINECALLPARAMS const){
 if(!dest)return LINEERR_INVALADDRESS;string n;
 for(const wchar_t* t=dest;*t;++t){if((*t>=L'0'&&*t<=L'9')||(*t==L'+'&&n.empty()))n+=static_cast<char>(*t);
 else if(!wcschr(L" ()/-",*t))return LINEERR_INVALADDRESS;}
 if(n.empty()||n=="+"||n.size()>32)return LINEERR_INVALADDRESS;
 lock_guard<mutex> lock(guard);if(l!=device()||!line)return LINEERR_INVALLINEHANDLE;
 for(auto& e:calls)if(!e.second.incoming && e.second.state!=LINECALLSTATE_IDLE)return LINEERR_CALLUNAVAIL;
 auto id=++serial;auto& c=calls[id];c.tapi=h;c.number=n;c.pending=true;c.request=request;*out=reinterpret_cast<HDRVCALL>(id);return request;
}
LONG TSPIAPI TSPI_lineCloseCall(HDRVCALL h){lock_guard<mutex> lock(guard);calls.erase(key(h));return 0;}
LONG TSPIAPI TSPI_lineGetCallAddressID(HDRVCALL,LPDWORD out){*out=0;return 0;}
LONG TSPIAPI TSPI_lineGetCallStatus(HDRVCALL h,LPLINECALLSTATUS p){lock_guard<mutex> lock(guard);auto it=calls.find(key(h));if(it==calls.end())return LINEERR_INVALCALLHANDLE;
 if(!setup(p))return LINEERR_STRUCTURETOOSMALL;p->dwCallState=it->second.state;return 0;}
LONG TSPIAPI TSPI_lineGetCallInfo(HDRVCALL h,LPLINECALLINFO p){
 lock_guard<mutex> lock(guard);auto it=calls.find(key(h));if(it==calls.end())return LINEERR_INVALCALLHANDLE;if(!setup(p))return LINEERR_STRUCTURETOOSMALL;
 auto& c=it->second;p->dwLineDeviceID=baseId;p->dwBearerMode=LINEBEARERMODE_VOICE;p->dwMediaMode=LINEMEDIAMODE_INTERACTIVEVOICE;
 p->dwCallID=static_cast<DWORD>(key(h));p->dwOrigin=c.incoming?LINECALLORIGIN_UNKNOWN:LINECALLORIGIN_OUTBOUND;p->dwReason=LINECALLREASON_UNKNOWN;
 wstring n(c.number.begin(),c.number.end());DWORD flags=n.empty()?LINECALLPARTYID_UNKNOWN:LINECALLPARTYID_ADDRESS;
 if(c.incoming){p->dwCallerIDFlags=flags;addText(p,n,p->dwCallerIDOffset,p->dwCallerIDSize);}
 else{p->dwCalledIDFlags=flags;addText(p,n,p->dwCalledIDOffset,p->dwCalledIDSize);}return 0;
}
