// SpamFilter.cpp
// -----------------------------------------------------------------------------
// MailEnable SMTP inbound plugin: marks junk mail so a MailEnable message filter
// can route it to the Junk folder. It does NOT reject — it tags only.
//
// Detection layers (any one triggers a tag):
//   * Whitelist (domains + addresses) short-circuits everything -> deliver clean.
//   * TLD allow-list on the From: header domain.
//   * Subject keyword filter (whole-word OR re: regex), file-based, live-reloaded.
//   * SpamAssassin for Windows (spamd): SPF + DKIM verification + content score.
//   * DMARC computed in-process from the SPF/DKIM results + a _dmarc TXT lookup.
//
// Only fires at DATAEND (the one stage with <messagepath> = full message on disk).
// SpamAssassin is OPTIONAL: if spamd is disabled/unreachable the local checks
// (whitelist/TLD/keyword) still run and the message is delivered if nothing fires.
//
// Build: see README.md. Exports "Execute" via SpamFilter.def. Build x86 and x64.
// -----------------------------------------------------------------------------

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <windns.h>
#include <string>
#include <vector>
#include <regex>
#include <cstdio>
#include <cstdlib>
#include <cctype>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "dnsapi.lib")

using std::string;
using std::vector;

// ---- runtime configuration (overridable via SpamFilter.ini next to the DLL) ----
static string g_spamdHost        = "127.0.0.1";
static int    g_spamdPort        = 783;
static double g_spamThreshold    = 5.0;
static bool   g_useSA            = true;     // call SpamAssassin at all
static bool   g_enforceDmarc     = true;     // tag DMARC fails under p=quarantine/reject
static bool   g_skipAuthenticated= true;     // skip authenticated submissions (your users)
static bool   g_junkHeader       = true;     // inject X-ME-Content: Deliver-To=Junk when tagged
static string g_authServId       = "mail.local";
static int    g_timeoutMs        = 10000;
static bool   g_debug            = false;
static string g_debugLog         = "";

// TLD allow-list
static bool   g_tldFilter        = true;
static vector<string> g_allowedTlds;

// Subject keyword filter
static bool   g_kwFilter         = true;
static string g_kwFile           = "";
static int    g_kwReloadSec      = 5;

// Whitelist (bypass all marking)
static vector<string> g_wlDomains;
static vector<string> g_wlSenders;

// keyword list (guarded by g_kwCs)
struct KwEntry { bool isRegex; string literal; std::regex rx; string source; };
static vector<KwEntry>  g_keywords;
static FILETIME         g_kwMtime   = {0,0};
static ULONGLONG        g_kwLastChk = 0;

static HMODULE          g_hModule = NULL;
static CRITICAL_SECTION g_cs;        // init
static CRITICAL_SECTION g_kwCs;      // keyword list
static volatile bool    g_inited  = false;

// ----------------------------- small helpers --------------------------------
static string ToLower(string s){ for(size_t i=0;i<s.size();++i) s[i]=(char)tolower((unsigned char)s[i]); return s; }
static string ToUpper(string s){ for(size_t i=0;i<s.size();++i) s[i]=(char)toupper((unsigned char)s[i]); return s; }
static string Trim(const string &s){ size_t a=s.find_first_not_of(" \t\r\n"); if(a==string::npos) return ""; size_t b=s.find_last_not_of(" \t\r\n"); return s.substr(a,b-a+1); }
static string FmtScore(double v){ char b[32]; snprintf(b,sizeof(b),"%.1f",v); return b; }
static bool   IsWordChar(char c){ return isalnum((unsigned char)c)!=0 || c=='_'; }

static bool InList(const vector<string>&v, const string &item){
    for(size_t i=0;i<v.size();++i) if(v[i]==item) return true;
    return false;
}

// Split a space/comma/semicolon list into lowercased tokens. stripDot removes a
// leading '.' (so ".com" and "com" both work in AllowedTlds).
static void SplitList(const string &s, vector<string> &out, bool stripDot){
    out.clear();
    string cur;
    for(size_t i=0;i<=s.size();++i){
        char c = (i<s.size()? s[i] : ',');
        if(c==' '||c=='\t'||c==','||c==';'||c=='\r'||c=='\n'){
            if(!cur.empty()){
                string v=ToLower(Trim(cur));
                if(stripDot && !v.empty() && v[0]=='.') v=v.substr(1);
                if(!v.empty()) out.push_back(v);
                cur.clear();
            }
        } else cur+=c;
    }
}

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

static string GetHeaderValue(const string &msg, const string &name){
    string block=HeaderBlock(msg);
    string lblock=ToLower(block);
    string key=ToLower(name)+":";
    size_t pos=0;
    while(pos<lblock.size()){
        if(lblock.compare(pos,key.size(),key)==0){
            size_t vs=pos+key.size();
            size_t i=block.find("\r\n",vs);
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

// "Name <a@b.com>" / "a@b.com" / "[SMTP:a@b.com]" -> "a@b.com" (lowercased)
static string EmailFromAddress(const string &addr){
    string s=addr;
    size_t lt=s.find('<');
    if(lt!=string::npos){ size_t gt=s.find('>',lt); if(gt!=string::npos) s=s.substr(lt+1,gt-lt-1); }
    size_t c=ToLower(s).find("smtp:");
    if(c!=string::npos) s=s.substr(c+5);
    string t;
    for(size_t i=0;i<s.size();++i){ char ch=s[i]; if(ch!='['&&ch!=']'&&ch!=' '&&ch!='<'&&ch!='>'&&ch!='\t') t+=ch; }
    if(t.find('@')==string::npos) return "";
    return ToLower(t);
}

// ... -> "b.com" (lowercased)
static string DomainFromAddress(const string &addr){
    string e=EmailFromAddress(addr);
    if(e.empty()){
        // fall back: maybe a bare domain
        string t; for(size_t i=0;i<addr.size();++i){ char ch=addr[i]; if(ch!='['&&ch!=']'&&ch!=' '&&ch!='<'&&ch!='>') t+=ch; }
        size_t at=t.rfind('@');
        return at==string::npos ? "" : ToLower(t.substr(at+1));
    }
    size_t at=e.rfind('@');
    return at==string::npos ? "" : e.substr(at+1);
}

// final label of a domain = the TLD ("example.co.uk" -> "uk")
static string TldOf(const string &dom){
    size_t p=dom.rfind('.');
    return p==string::npos ? "" : dom.substr(p+1);
}

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

// Crude org-domain = last two labels (NOT a full Public Suffix List).
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
static bool HasSym(const string &syms, const string &tok){
    return ("," + syms + ",").find("," + tok + ",") != string::npos;
}

// --------------------------- whitelist --------------------------------------
static bool DomainWhitelisted(const string &dom){
    if(dom.empty()) return false;
    for(size_t i=0;i<g_wlDomains.size();++i){
        const string &w=g_wlDomains[i];
        if(dom==w) return true;                                   // exact
        if(dom.size()>w.size()+1 &&
           dom.compare(dom.size()-w.size()-1, w.size()+1, "."+w)==0) return true; // subdomain
    }
    return false;
}
static bool IsWhitelisted(const string &fromAddr, const string &fromDom,
                          const string &envAddr,  const string &envDom){
    if(!fromAddr.empty() && InList(g_wlSenders,fromAddr)) return true;
    if(!envAddr.empty()  && InList(g_wlSenders,envAddr))  return true;
    if(DomainWhitelisted(fromDom)) return true;
    if(DomainWhitelisted(envDom))  return true;
    return false;
}

// --------------------------- subject keywords -------------------------------
static bool WholeWordMatch(const string &hayLower, const string &needleLower){
    if(needleLower.empty()) return false;
    size_t pos=0;
    while((pos=hayLower.find(needleLower,pos))!=string::npos){
        bool leftOk  = (pos==0) || !IsWordChar(hayLower[pos-1]);
        size_t end=pos+needleLower.size();
        bool rightOk = (end>=hayLower.size()) || !IsWordChar(hayLower[end]);
        if(leftOk && rightOk) return true;
        pos+=1;
    }
    return false;
}

// (re)build the keyword list from g_kwFile. Caller holds g_kwCs.
static void LoadKeywordsLocked(){
    g_keywords.clear();
    string data;
    if(!ReadEntireFile(g_kwFile,data)) return;
    size_t start=0;
    while(start<=data.size()){
        size_t nl=data.find('\n',start);
        string line=data.substr(start,(nl==string::npos?data.size():nl)-start);
        start=(nl==string::npos)? data.size()+1 : nl+1;
        line=Trim(line);
        if(line.empty()||line[0]=='#') continue;
        KwEntry e; e.isRegex=false; e.source=line;
        if(line.size()>3 && ToLower(line.substr(0,3))=="re:"){
            string pat=Trim(line.substr(3));
            try { e.rx=std::regex(pat, std::regex::icase|std::regex::ECMAScript); e.isRegex=true; e.source=pat; }
            catch(...) { if(g_debug) DebugLog("bad regex skipped: "+pat); continue; }
        } else {
            e.literal=ToLower(line);
        }
        g_keywords.push_back(std::move(e));
    }
}

// Throttled mtime check + reload, then match. Returns the matched entry source.
static bool CheckKeywords(const string &subject, string &matched){
    if(!g_kwFilter || g_kwFile.empty()) return false;
    bool hit=false;
    EnterCriticalSection(&g_kwCs);
    ULONGLONG now=GetTickCount64();
    if(g_kwLastChk==0 || now-g_kwLastChk >= (ULONGLONG)g_kwReloadSec*1000){
        g_kwLastChk=now;
        WIN32_FILE_ATTRIBUTE_DATA fad;
        if(GetFileAttributesExA(g_kwFile.c_str(),GetFileExInfoStandard,&fad)){
            if(CompareFileTime(&fad.ftLastWriteTime,&g_kwMtime)!=0){
                g_kwMtime=fad.ftLastWriteTime;
                LoadKeywordsLocked();
            }
        }
    }
    string subjLower=ToLower(subject);
    for(size_t i=0;i<g_keywords.size() && !hit;i++){
        const KwEntry &e=g_keywords[i];
        if(e.isRegex){
            try { if(std::regex_search(subject,e.rx)){ hit=true; matched="re:"+e.source; } } catch(...){}
        } else {
            if(WholeWordMatch(subjLower,e.literal)){ hit=true; matched=e.source; }
        }
    }
    LeaveCriticalSection(&g_kwCs);
    return hit;
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
static bool SpamdSymbols(const string &msg, bool &isSpam, double &score, string &symbols){
    isSpam=false; score=0; symbols.clear();
    SOCKET s;
    if(!SpamdConnect(s)) return false;
    char hdr[160];
    snprintf(hdr,sizeof(hdr),"SYMBOLS SPAMC/1.2\r\nContent-length: %u\r\n\r\n",(unsigned)msg.size());
    bool ok = SendAll(s,hdr,strlen(hdr)) && SendAll(s,msg.data(),msg.size());
    if(ok) shutdown(s,SD_SEND);
    string resp;
    if(ok){ char buf[4096]; int n; while((n=recv(s,buf,sizeof(buf),0))>0) resp.append(buf,n); }
    closesocket(s);
    if(!ok || resp.empty()) return false;
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

// ------------------------------ init / DllMain ------------------------------
static void EnsureInit(){
    if(g_inited) return;
    EnterCriticalSection(&g_cs);
    if(!g_inited){
        char path[MAX_PATH]={0};
        GetModuleFileNameA(g_hModule,path,MAX_PATH);
        string p=path; size_t sl=p.find_last_of("\\/");
        string ini=(sl==string::npos?string("."):p.substr(0,sl))+"\\SpamFilter.ini";

        char buf[256], big[8192];
        GetPrivateProfileStringA("SpamFilter","SpamdHost","127.0.0.1",buf,sizeof(buf),ini.c_str()); g_spamdHost=buf;
        g_spamdPort = GetPrivateProfileIntA("SpamFilter","SpamdPort",783,ini.c_str());
        GetPrivateProfileStringA("SpamFilter","SpamThreshold","5.0",buf,sizeof(buf),ini.c_str()); g_spamThreshold=atof(buf);
        g_useSA             = GetPrivateProfileIntA("SpamFilter","UseSpamAssassin",1,ini.c_str())!=0;
        g_enforceDmarc      = GetPrivateProfileIntA("SpamFilter","EnforceDmarc",1,ini.c_str())!=0;
        g_skipAuthenticated = GetPrivateProfileIntA("SpamFilter","SkipAuthenticated",1,ini.c_str())!=0;
        GetPrivateProfileStringA("SpamFilter","AuthServId","mail.local",buf,sizeof(buf),ini.c_str()); g_authServId=buf;
        g_junkHeader = GetPrivateProfileIntA("SpamFilter","DeliverToJunkHeader",1,ini.c_str())!=0;
        g_timeoutMs = GetPrivateProfileIntA("SpamFilter","TimeoutMs",10000,ini.c_str());
        g_debug     = GetPrivateProfileIntA("SpamFilter","Debug",0,ini.c_str())!=0;
        GetPrivateProfileStringA("SpamFilter","DebugLog","",buf,sizeof(buf),ini.c_str()); g_debugLog=buf;

        g_tldFilter = GetPrivateProfileIntA("SpamFilter","TldFilter",1,ini.c_str())!=0;
        GetPrivateProfileStringA("SpamFilter","AllowedTlds","com uk net org us",big,sizeof(big),ini.c_str());
        SplitList(big,g_allowedTlds,true);

        g_kwFilter   = GetPrivateProfileIntA("SpamFilter","SubjectKeywordFilter",1,ini.c_str())!=0;
        GetPrivateProfileStringA("SpamFilter","KeywordFile","",buf,sizeof(buf),ini.c_str()); g_kwFile=buf;
        g_kwReloadSec= GetPrivateProfileIntA("SpamFilter","KeywordReloadSeconds",5,ini.c_str());
        if(g_kwReloadSec<1) g_kwReloadSec=1;

        GetPrivateProfileStringA("SpamFilter","WhitelistDomains","",big,sizeof(big),ini.c_str()); SplitList(big,g_wlDomains,false);
        GetPrivateProfileStringA("SpamFilter","WhitelistSenders","",big,sizeof(big),ini.c_str()); SplitList(big,g_wlSenders,false);

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
            InitializeCriticalSection(&g_kwCs);
            DisableThreadLibraryCalls((HMODULE)hinstDLL);
            break;
        case DLL_PROCESS_DETACH:
            DeleteCriticalSection(&g_cs);
            DeleteCriticalSection(&g_kwCs);
            break;
    }
    UNREFERENCED_PARAMETER(lpvReserved);
    return TRUE;
}

// ------------------------------- entry point --------------------------------
extern "C" long Execute(char *Configuration, char *Response){
    UNREFERENCED_PARAMETER(Response);
    EnsureInit();

    string cfg = Configuration ? Configuration : "";
    string cmd; GetConfigItem(cfg,"smtpcommand",cmd);
    if(cmd!="DATAEND") return 1;                          // only stage with <messagepath>

    string senderAuth; GetConfigItem(cfg,"senderauth",senderAuth);
    if(g_skipAuthenticated && senderAuth=="1") return 1;  // trust authenticated submissions

    string path; GetConfigItem(cfg,"messagepath",path);
    if(path.empty()) return 1;

    string msg;
    if(!ReadEntireFile(path,msg)) return 1;               // fail open

    string sender; GetConfigItem(cfg,"sender",sender);
    string fromHeader = GetHeaderValue(msg,"From");
    string subject    = GetHeaderValue(msg,"Subject");
    string fromAddr   = EmailFromAddress(fromHeader);
    string fromDom    = DomainFromAddress(fromHeader);
    string envAddr    = EmailFromAddress(sender);
    string envDom     = DomainFromAddress(sender);

    // 1) Whitelist -> deliver untouched
    if(IsWhitelisted(fromAddr,fromDom,envAddr,envDom)){
        if(g_debug) DebugLog("WHITELISTED from=["+fromAddr+"] dom=["+fromDom+"]");
        return 1;
    }

    vector<string> reasons;

    // 2) TLD allow-list (on the visible From: domain)
    if(g_tldFilter){
        string tld=TldOf(fromDom);
        if(tld.empty() || !InList(g_allowedTlds,tld))
            reasons.push_back("TLD_NOT_ALLOWED("+(tld.empty()?(fromDom.empty()?"no-from":fromDom):tld)+")");
    }

    // 3) Subject keyword filter
    if(g_kwFilter && !subject.empty()){
        string matched;
        if(CheckKeywords(subject,matched)) reasons.push_back("SUBJECT_KEYWORD("+matched+")");
    }

    // 4) SpamAssassin (optional) + DMARC — only enforce auth if spamd answered
    bool saOk=false, isSpam=false, spfPass=false, dkimPass=false, dmarcPass=false, dmarcRecord=false;
    double score=0; string syms, dkimDom, dmarcPolicy="none";
    if(g_useSA){
        saOk = SpamdSymbols(msg,isSpam,score,syms);
        if(saOk){
            spfPass  = HasSym(syms,"SPF_PASS");
            dkimPass = HasSym(syms,"DKIM_VALID")||HasSym(syms,"DKIM_VALID_AU");
            dkimDom  = DkimDomain(msg);
            bool spfAligned  = spfPass  && Aligned(envDom,  fromDom);
            bool dkimAligned = dkimPass && Aligned(dkimDom, fromDom);
            dmarcPass = spfAligned || dkimAligned;
            if(!fromDom.empty()){
                string rec;
                if(LookupDmarc(fromDom,rec)){ dmarcRecord=true; dmarcPolicy=DmarcPolicy(rec,false); }
                else { string org=OrgDomain(fromDom); if(org!=fromDom && LookupDmarc(org,rec)){ dmarcRecord=true; dmarcPolicy=DmarcPolicy(rec,true);} }
            }
            if(isSpam && score>=g_spamThreshold) reasons.push_back("SPAMASSASSIN(score="+FmtScore(score)+")");
            if(g_enforceDmarc && dmarcRecord && !dmarcPass &&
               (dmarcPolicy=="quarantine"||dmarcPolicy=="reject"))
                reasons.push_back("DMARC_"+ToUpper(dmarcPolicy));
        }
    }

    bool tag = !reasons.empty();

    // --- build headers ---
    string headers;
    if(saOk){
        string dmarcResult = dmarcPass?"pass":(dmarcRecord?"fail":"none");
        headers += "Authentication-Results: "+g_authServId+";\r\n"
            "\tspf="+(spfPass?"pass":"fail")+" smtp.mailfrom="+(envDom.empty()?"unknown":envDom)+";\r\n"
            "\tdkim="+(dkimPass?"pass":"fail")+(dkimDom.empty()?"":" header.d="+dkimDom)+";\r\n"
            "\tdmarc="+dmarcResult+" (p="+dmarcPolicy+") header.from="+(fromDom.empty()?"unknown":fromDom)+"\r\n";
    }
    if(tag){
        string reasonStr;
        for(size_t i=0;i<reasons.size();++i){ if(i) reasonStr+=", "; reasonStr+=reasons[i]; }
        headers += "X-Spam-Flag: YES\r\n";
        headers += "X-Spam-Reason: "+reasonStr+"\r\n";
        if(g_junkHeader) headers += "X-ME-Content: Deliver-To=Junk\r\n";   // MailEnable native -> Junk folder
    }
    if(saOk) headers += "X-Spam-Score: "+FmtScore(score)+"\r\n";
    {
        string status = string("X-Spam-Status: ") + (tag?"Yes":"No");
        if(saOk) status += ", score="+FmtScore(score)+" required="+FmtScore(g_spamThreshold);
        status += "\r\n";
        headers += status;
    }

    InjectHeaders(msg,headers);
    WriteEntireFile(path,msg);

    if(g_debug){
        string r; for(size_t i=0;i<reasons.size();++i){ if(i) r+=","; r+=reasons[i]; }
        DebugLog("from=["+fromAddr+"] dom=["+fromDom+"] tld=["+TldOf(fromDom)+"] "
                 "tag="+(tag?"1":"0")+" reasons=["+r+"] "
                 +(g_useSA?(saOk?("sa-ok score="+FmtScore(score)):"sa-unreachable"):"sa-off"));
    }

    return 1;   // always accept — we mark, never reject
}
