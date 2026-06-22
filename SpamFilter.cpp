// SpamFilter.cpp
// -----------------------------------------------------------------------------
// MailEnable SMTP inbound plugin: marks junk mail so a MailEnable message filter
// can route it to the Junk folder. It does NOT reject — it tags only.
//
// Strategy (see SpamFilter\README.md and project memory "spam-plugin-architecture"):
//   * Fires only at DATAEND, the one stage where MailEnable gives us <messagepath>
//     (the full received message on disk).
//   * Hands the message to SpamAssassin for Windows (spamd) over the spamc/spamd
//     protocol. SpamAssassin does the hard crypto: SPF eval + DKIM verification,
//     plus a content/Bayesian score.
//   * Computes DMARC itself: From-domain alignment against the SPF/DKIM passing
//     domains + a _dmarc TXT policy lookup (Windows DnsQuery). This avoids depending
//     on SpamAssassin shipping a DMARC plugin.
//   * If the SA score is over threshold OR DMARC fails under p=quarantine/reject,
//     it injects X-Spam-Flag: YES (+ Authentication-Results / X-Spam-Status) into
//     the message file. Always returns 1 (accept).
//
// Build: see README.md. Exports "Execute" via SpamFilter.def. Build x86 and x64.
// -----------------------------------------------------------------------------

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <windns.h>
#include <string>
#include <cstdio>
#include <cstdlib>
#include <cctype>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "dnsapi.lib")

using std::string;

// ---- runtime configuration (overridable via SpamFilter.ini next to the DLL) ----
static string g_spamdHost        = "127.0.0.1";
static int    g_spamdPort        = 783;
static double g_spamThreshold    = 5.0;     // SA score at/above which we tag as spam
static bool   g_enforceDmarc     = true;    // also tag DMARC fails under p=quarantine/reject
static bool   g_skipAuthenticated= true;    // don't scan submissions from authenticated users
static string g_authServId       = "mail.local"; // authserv-id placed in Authentication-Results
static int    g_timeoutMs        = 10000;   // spamd socket timeout
static bool   g_debug            = false;
static string g_debugLog         = "";      // path to append debug lines to

static HMODULE          g_hModule = NULL;
static CRITICAL_SECTION g_cs;
static volatile bool    g_inited  = false;

// ----------------------------- small helpers --------------------------------
static string ToLower(string s){ for(size_t i=0;i<s.size();++i) s[i]=(char)tolower((unsigned char)s[i]); return s; }
static string ToUpper(string s){ for(size_t i=0;i<s.size();++i) s[i]=(char)toupper((unsigned char)s[i]); return s; }
static string Trim(const string &s){ size_t a=s.find_first_not_of(" \t\r\n"); if(a==string::npos) return ""; size_t b=s.find_last_not_of(" \t\r\n"); return s.substr(a,b-a+1); }
static string FmtScore(double v){ char b[32]; snprintf(b,sizeof(b),"%.1f",v); return b; }

// Read a <tag>value</tag> out of the MailEnable XML config blob.
static void GetConfigItem(const string &cfg, const string &item, string &out){
    out.clear();
    string st="<"+item+">", en="</"+item+">";
    size_t p=cfg.find(st);
    if(p==string::npos) return;
    size_t e=cfg.find(en,p);
    if(e==string::npos) return;
    out=cfg.substr(p+st.length(), e-(p+st.length()));
}

static void DebugLog(const string &line){
    if(!g_debug || g_debugLog.empty()) return;
    HANDLE h=CreateFileA(g_debugLog.c_str(),FILE_APPEND_DATA,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    if(h==INVALID_HANDLE_VALUE) return;
    SetFilePointer(h,0,NULL,FILE_END);
    string s=line+"\r\n"; DWORD wr=0; WriteFile(h,s.data(),(DWORD)s.size(),&wr,NULL);
    CloseHandle(h);
}

static bool ReadEntireFile(const string &path, string &out){
    HANDLE h=CreateFileA(path.c_str(),GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    if(h==INVALID_HANDLE_VALUE) return false;
    DWORD sz=GetFileSize(h,NULL);
    if(sz==INVALID_FILE_SIZE){ CloseHandle(h); return false; }
    out.resize(sz);
    DWORD rd=0; BOOL ok = sz==0 ? TRUE : ReadFile(h,&out[0],sz,&rd,NULL);
    CloseHandle(h);
    if(!ok) return false;
    out.resize(rd);
    return true;
}

static bool WriteEntireFile(const string &path, const string &data){
    HANDLE h=CreateFileA(path.c_str(),GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    if(h==INVALID_HANDLE_VALUE) return false;
    DWORD wr=0; BOOL ok=WriteFile(h,data.data(),(DWORD)data.size(),&wr,NULL);
    CloseHandle(h);
    return ok && wr==data.size();
}

// ----------------------------- header parsing -------------------------------
static string HeaderBlock(const string &msg){
    size_t p=msg.find("\r\n\r\n");
    if(p!=string::npos) return msg.substr(0,p+2);
    p=msg.find("\n\n");
    if(p!=string::npos) return msg.substr(0,p+1);
    return msg;
}

// First occurrence of a header, unfolded. Case-insensitive on the name.
static string GetHeaderValue(const string &msg, const string &name){
    string block=HeaderBlock(msg);
    string lblock=ToLower(block);
    string key=ToLower(name)+":";
    size_t pos=0;
    while(pos<lblock.size()){
        if(lblock.compare(pos,key.size(),key)==0){
            size_t vs=pos+key.size();
            size_t i=block.find("\r\n",vs);
            // unfold: a following line starting with SP/TAB continues this header
            while(i!=string::npos && i+2<block.size() && (block[i+2]==' '||block[i+2]=='\t'))
                i=block.find("\r\n",i+2);
            string val=block.substr(vs,(i==string::npos?block.size():i)-vs);
            string out;
            for(size_t k=0;k<val.size();++k) if(val[k]!='\r'&&val[k]!='\n') out+=val[k];
            return Trim(out);
        }
        size_t nl=lblock.find("\r\n",pos);
        if(nl==string::npos) break;
        pos=nl+2;
    }
    return "";
}

// Pull a domain out of an address-ish string: "Name <a@b.com>", "a@b.com",
// "[SMTP:a@b.com]" all yield "b.com".
static string DomainFromAddress(const string &addr){
    string s=addr;
    size_t lt=s.find('<');
    if(lt!=string::npos){ size_t gt=s.find('>',lt); if(gt!=string::npos) s=s.substr(lt+1,gt-lt-1); }
    size_t c=ToLower(s).find("smtp:");
    if(c!=string::npos) s=s.substr(c+5);
    string t;
    for(size_t i=0;i<s.size();++i){ char ch=s[i]; if(ch!='['&&ch!=']'&&ch!=' '&&ch!='<'&&ch!='>') t+=ch; }
    size_t at=t.rfind('@');
    if(at==string::npos) return "";
    return ToLower(t.substr(at+1));
}

// Read the d= signing domain from the first DKIM-Signature header.
static string DkimDomain(const string &msg){
    string sig=GetHeaderValue(msg,"DKIM-Signature");
    if(sig.empty()) return "";
    string low=ToLower(sig);
    size_t p=low.find("d=");
    while(p!=string::npos){
        if(p==0||low[p-1]==';'||low[p-1]==' '||low[p-1]=='\t') break;
        p=low.find("d=",p+2);
    }
    if(p==string::npos) return "";
    size_t s=p+2, e=sig.find_first_of("; \t",s);
    return ToLower(Trim(sig.substr(s,(e==string::npos?sig.size():e)-s)));
}

// Crude organizational-domain = last two labels. NOTE: not a real Public Suffix
// List, so multi-part TLDs (co.uk, com.au, ...) are imperfect. Good enough for a
// first cut; swap in a PSL table later if needed.
static string OrgDomain(const string &d){
    if(d.empty()) return d;
    size_t p1=d.rfind('.');
    if(p1==string::npos || p1==0) return d;
    size_t p2=d.rfind('.',p1-1);
    if(p2==string::npos) return d;
    return d.substr(p2+1);
}

static bool Aligned(const string &a, const string &b){
    return !a.empty() && !b.empty() && OrgDomain(a)==OrgDomain(b);
}

// comma-separated token membership ("SPF_PASS,DKIM_VALID,...")
static bool HasSym(const string &syms, const string &tok){
    string hay=","+syms+",";
    return hay.find(","+tok+",")!=string::npos;
}

// ------------------------------ DMARC lookup --------------------------------
static string TagVal(const string &rec, const string &tag){
    string lr=ToLower(rec), lt=ToLower(tag)+"=";
    size_t p=lr.find(lt);
    while(p!=string::npos){
        if(p==0||lr[p-1]==';'||lr[p-1]==' '||lr[p-1]=='\t') break;
        p=lr.find(lt,p+1);
    }
    if(p==string::npos) return "";
    size_t s=p+lt.size(), e=rec.find_first_of("; \t",s);
    return ToLower(Trim(rec.substr(s,(e==string::npos?rec.size():e)-s)));
}

static bool LookupDmarc(const string &domain, string &out){
    out.clear();
    string q="_dmarc."+domain;
    PDNS_RECORD p=NULL;
    DNS_STATUS st=DnsQuery_A(q.c_str(),DNS_TYPE_TEXT,DNS_QUERY_STANDARD,NULL,&p,NULL);
    if(st!=0||!p) return false;
    bool found=false;
    for(PDNS_RECORD r=p;r;r=r->pNext){
        if(r->wType==DNS_TYPE_TEXT){
            string s;
            for(DWORD i=0;i<r->Data.TXT.dwStringCount;i++) s+=r->Data.TXT.pStringArray[i];
            if(ToLower(s).find("v=dmarc1")!=string::npos){ out=s; found=true; break; }
        }
    }
    DnsRecordListFree(p,DnsFreeRecordList);
    return found;
}

static string DmarcPolicy(const string &rec, bool useSubdomainPolicy){
    if(useSubdomainPolicy){ string sp=TagVal(rec,"sp"); if(!sp.empty()) return sp; }
    string p=TagVal(rec,"p");
    return p.empty()?"none":p;
}

// --------------------------- SpamAssassin (spamd) ---------------------------
static bool SendAll(SOCKET s, const char *data, size_t len){
    size_t off=0;
    while(off<len){ int n=send(s,data+off,(int)(len-off),0); if(n<=0) return false; off+=(size_t)n; }
    return true;
}

static bool SpamdConnect(SOCKET &sock){
    sock=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    if(sock==INVALID_SOCKET) return false;
    DWORD to=(DWORD)g_timeoutMs;
    setsockopt(sock,SOL_SOCKET,SO_RCVTIMEO,(char*)&to,sizeof(to));
    setsockopt(sock,SOL_SOCKET,SO_SNDTIMEO,(char*)&to,sizeof(to));
    sockaddr_in a; memset(&a,0,sizeof(a));
    a.sin_family=AF_INET; a.sin_port=htons((u_short)g_spamdPort);
    unsigned long ip=inet_addr(g_spamdHost.c_str());
    if(ip!=INADDR_NONE){ a.sin_addr.s_addr=ip; }
    else {
        addrinfo hints; memset(&hints,0,sizeof(hints));
        hints.ai_family=AF_INET; hints.ai_socktype=SOCK_STREAM;
        addrinfo *res=NULL;
        if(getaddrinfo(g_spamdHost.c_str(),NULL,&hints,&res)!=0||!res){ closesocket(sock); return false; }
        a.sin_addr=((sockaddr_in*)res->ai_addr)->sin_addr;
        freeaddrinfo(res);
    }
    if(connect(sock,(sockaddr*)&a,sizeof(a))!=0){ closesocket(sock); return false; }
    return true;
}

// Ask spamd for the SYMBOLS report. Returns false if spamd is unreachable.
static bool SpamdSymbols(const string &msg, bool &isSpam, double &score, string &symbols){
    isSpam=false; score=0; symbols.clear();
    SOCKET s;
    if(!SpamdConnect(s)) return false;

    char hdr[160];
    snprintf(hdr,sizeof(hdr),"SYMBOLS SPAMC/1.2\r\nContent-length: %u\r\n\r\n",(unsigned)msg.size());
    bool ok = SendAll(s,hdr,strlen(hdr)) && SendAll(s,msg.data(),msg.size());
    if(ok) shutdown(s,SD_SEND);

    string resp;
    if(ok){
        char buf[4096]; int n;
        while((n=recv(s,buf,sizeof(buf),0))>0) resp.append(buf,n);
    }
    closesocket(s);
    if(!ok || resp.empty()) return false;

    // "Spam: True ; 15.3 / 5.0"
    size_t sp=resp.find("Spam:");
    if(sp!=string::npos){
        size_t le=resp.find("\r\n",sp);
        string line=resp.substr(sp,(le==string::npos?resp.size():le)-sp);
        isSpam = ToLower(line).find("true")!=string::npos;
        size_t semi=line.find(';');
        if(semi!=string::npos) score=atof(line.c_str()+semi+1);
    }
    size_t body=resp.find("\r\n\r\n");
    if(body!=string::npos) symbols=Trim(resp.substr(body+4));
    return true;
}

// --------------------------- header injection -------------------------------
static void InjectHeaders(string &msg, const string &hdrs){
    size_t p=msg.find("\r\n\r\n");
    if(p!=string::npos){ msg.insert(p+2,hdrs); return; }
    p=msg.find("\n\n");
    if(p!=string::npos){ msg.insert(p+1,hdrs); return; }
    msg = hdrs + msg;
}

// ------------------------------- init / DllMain -----------------------------
static void EnsureInit(){
    if(g_inited) return;
    EnterCriticalSection(&g_cs);
    if(!g_inited){
        char path[MAX_PATH]={0};
        GetModuleFileNameA(g_hModule,path,MAX_PATH);
        string p=path; size_t sl=p.find_last_of("\\/");
        string ini=(sl==string::npos?string("."):p.substr(0,sl))+"\\SpamFilter.ini";

        char buf[256];
        GetPrivateProfileStringA("SpamFilter","SpamdHost","127.0.0.1",buf,sizeof(buf),ini.c_str()); g_spamdHost=buf;
        g_spamdPort = GetPrivateProfileIntA("SpamFilter","SpamdPort",783,ini.c_str());
        GetPrivateProfileStringA("SpamFilter","SpamThreshold","5.0",buf,sizeof(buf),ini.c_str()); g_spamThreshold=atof(buf);
        g_enforceDmarc      = GetPrivateProfileIntA("SpamFilter","EnforceDmarc",1,ini.c_str())!=0;
        g_skipAuthenticated = GetPrivateProfileIntA("SpamFilter","SkipAuthenticated",1,ini.c_str())!=0;
        GetPrivateProfileStringA("SpamFilter","AuthServId","mail.local",buf,sizeof(buf),ini.c_str()); g_authServId=buf;
        g_timeoutMs = GetPrivateProfileIntA("SpamFilter","TimeoutMs",10000,ini.c_str());
        g_debug     = GetPrivateProfileIntA("SpamFilter","Debug",0,ini.c_str())!=0;
        GetPrivateProfileStringA("SpamFilter","DebugLog","",buf,sizeof(buf),ini.c_str()); g_debugLog=buf;

        WSADATA wsa; WSAStartup(MAKEWORD(2,2),&wsa);
        g_inited=true;
    }
    LeaveCriticalSection(&g_cs);
}

BOOL APIENTRY DllMain(HANDLE hinstDLL, DWORD fdwReason, LPVOID lpvReserved){
    switch(fdwReason){
        case DLL_PROCESS_ATTACH:
            g_hModule=(HMODULE)hinstDLL;
            InitializeCriticalSection(&g_cs);
            DisableThreadLibraryCalls((HMODULE)hinstDLL);
            break;
        case DLL_PROCESS_DETACH:
            DeleteCriticalSection(&g_cs);
            break;
    }
    UNREFERENCED_PARAMETER(lpvReserved);
    return TRUE;
}

// ------------------------------- entry point --------------------------------
// MailEnable calls this at MAIL/RCPT/DATA/DATAEND. We only act on DATAEND.
extern "C" long Execute(char *Configuration, char *Response){
    UNREFERENCED_PARAMETER(Response);
    EnsureInit();

    string cfg = Configuration ? Configuration : "";

    string cmd; GetConfigItem(cfg,"smtpcommand",cmd);
    if(cmd!="DATAEND") return 1;                 // only the full-message stage carries <messagepath>

    string senderAuth; GetConfigItem(cfg,"senderauth",senderAuth);
    if(g_skipAuthenticated && senderAuth=="1") return 1;   // trust authenticated submissions

    string path; GetConfigItem(cfg,"messagepath",path);
    if(path.empty()) return 1;

    string msg;
    if(!ReadEntireFile(path,msg)) return 1;      // fail open

    string sender; GetConfigItem(cfg,"sender",sender);

    // --- SpamAssassin: SPF + DKIM verification + content score ---
    bool isSpam=false; double score=0; string syms;
    bool saOk = SpamdSymbols(msg,isSpam,score,syms);

    bool spfPass  = HasSym(syms,"SPF_PASS");
    bool dkimPass = HasSym(syms,"DKIM_VALID") || HasSym(syms,"DKIM_VALID_AU");

    // --- DMARC computed here from the SA results ---
    string fromDom = DomainFromAddress(GetHeaderValue(msg,"From"));
    string envDom  = DomainFromAddress(sender);
    string dkimDom = DkimDomain(msg);

    bool spfAligned  = spfPass  && Aligned(envDom,  fromDom);
    bool dkimAligned = dkimPass && Aligned(dkimDom, fromDom);
    bool dmarcPass   = spfAligned || dkimAligned;

    string dmarcPolicy="none"; bool dmarcRecord=false;
    if(!fromDom.empty()){
        string rec;
        if(LookupDmarc(fromDom,rec)){ dmarcRecord=true; dmarcPolicy=DmarcPolicy(rec,false); }
        else {
            string org=OrgDomain(fromDom);
            if(org!=fromDom && LookupDmarc(org,rec)){ dmarcRecord=true; dmarcPolicy=DmarcPolicy(rec,true); }
        }
    }
    bool dmarcEnforced = dmarcRecord && !dmarcPass && (dmarcPolicy=="quarantine"||dmarcPolicy=="reject");

    bool tag = (saOk && isSpam && score>=g_spamThreshold) || (g_enforceDmarc && dmarcEnforced);

    // --- build the headers we inject ---
    string dmarcResult = dmarcPass ? "pass" : (dmarcRecord ? "fail" : "none");
    string ar =
        "Authentication-Results: "+g_authServId+";\r\n"
        "\tspf="+(spfPass?"pass":"fail")+" smtp.mailfrom="+(envDom.empty()?"unknown":envDom)+";\r\n"
        "\tdkim="+(dkimPass?"pass":"fail")+(dkimDom.empty()?"":" header.d="+dkimDom)+";\r\n"
        "\tdmarc="+dmarcResult+" (p="+dmarcPolicy+") header.from="+(fromDom.empty()?"unknown":fromDom)+"\r\n";

    string headers = ar;
    if(tag){
        headers += "X-Spam-Flag: YES\r\n";
        headers += "X-Spam-Score: "+FmtScore(score)+"\r\n";
        headers += "X-Spam-Status: Yes, score="+FmtScore(score)+" required="+FmtScore(g_spamThreshold);
        if(dmarcEnforced) headers += " DMARC_"+ToUpper(dmarcPolicy);
        headers += "\r\n";
    } else {
        headers += "X-Spam-Status: No, score="+FmtScore(score)+" required="+FmtScore(g_spamThreshold)+"\r\n";
    }

    InjectHeaders(msg,headers);
    WriteEntireFile(path,msg);

    if(g_debug){
        DebugLog("from="+fromDom+" env="+envDom+" dkimd="+dkimDom+
                 " spf="+(spfPass?"1":"0")+" dkim="+(dkimPass?"1":"0")+
                 " dmarc="+dmarcResult+"/"+dmarcPolicy+
                 " score="+FmtScore(score)+" tag="+(tag?"1":"0")+
                 (saOk?"":" [spamd-unreachable]")+" syms=["+syms+"]");
    }

    return 1;   // always accept — we mark, never reject
}
